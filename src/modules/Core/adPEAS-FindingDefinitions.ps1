<#
.SYNOPSIS
    Central finding definitions and trigger-based severity/tooltip system for adPEAS.

.DESCRIPTION
    Single source of truth for security finding metadata, attribute severity classification,
    and tooltip content. Each finding includes: Title, Risk Level, Description, Impact,
    Attack Vectors, Remediation Steps, References, Tools, and MITRE ATT&CK mappings.

    The trigger system maps attribute name/value pairs to FindingIds and severity levels.
    Used by:
    - Get-TriggerMatch / Get-SeverityFromTrigger: Attribute severity classification
    - Get-FindingIdForAttribute: Tooltip FindingId lookup
    - Export-FindingDefinitionsJson: HTML report hover tooltips

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

# ============================================================================
# CENTRAL TOOL REPOSITORY
# ============================================================================
# Single source of truth for all security tools and their GitHub URLs.
# Referenced by FindingDefinitions using the tool name as key.

$Script:ToolUrls = @{
    # Password Cracking
    "Hashcat"           = "https://github.com/hashcat/hashcat"
    "John the Ripper"   = "https://github.com/openwall/john"

    # Kerberos Tools
    "Rubeus"            = "https://github.com/GhostPack/Rubeus"
    "Mimikatz"          = "https://github.com/gentilkiwi/mimikatz"
    "krbrelayx"         = "https://github.com/dirkjanm/krbrelayx"
    "Kerbrute"          = "https://github.com/ropnop/kerbrute"

    # Impacket Suite
    "Impacket"          = "https://github.com/fortra/impacket"

    # AD Enumeration & Exploitation
    "PowerView"         = "https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon"
    "BloodHound"        = "https://github.com/SpecterOps/BloodHound"
    "ADACLScanner"      = "https://github.com/canix1/ADACLScanner"
    "ADRecon"           = "https://github.com/adrecon/ADRecon"
    "PingCastle"        = "https://github.com/vletoux/pingcastle"
    "ldapdomaindump"    = "https://github.com/dirkjanm/ldapdomaindump"
    "windapsearch"      = "https://github.com/ropnop/windapsearch"
    "DSInternals"       = "https://github.com/MichaelGrafnetter/DSInternals"
    "ADExplorer"        = "https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer"

    # ADCS Tools
    "Certify"           = "https://github.com/GhostPack/Certify"
    "Certipy"           = "https://github.com/ly4k/Certipy"
    "ForgeCert"         = "https://github.com/GhostPack/ForgeCert"
    "PSPKI"             = "https://github.com/Crypt32/PSPKI"

    # Coercion & Relay
    "PetitPotam"        = "https://github.com/topotam/PetitPotam"
    "SpoolSample"       = "https://github.com/leechristensen/SpoolSample"
    "PrinterBug.py"     = "https://github.com/dirkjanm/krbrelayx"
    "Coercer"           = "https://github.com/p0dalirius/Coercer"
    "Responder"         = "https://github.com/lgandx/Responder"
    "Inveigh"           = "https://github.com/Kevin-Robertson/Inveigh"
    "ntlmrelayx"        = "https://github.com/fortra/impacket"

    # GPO Abuse
    "SharpGPOAbuse"     = "https://github.com/FSecureLABS/SharpGPOAbuse"
    "Get-GPPPassword"   = "https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1"
    "gpp-decrypt"       = "https://github.com/t0thkr1s/gpp-decrypt"

    # Shadow Credentials
    "Whisker"           = "https://github.com/eladshamir/Whisker"
    "PyWhisker"         = "https://github.com/ShutdownRepo/pywhisker"

    # Machine Account Attacks
    "PowerMad"          = "https://github.com/Kevin-Robertson/Powermad"
    "SharpMad"          = "https://github.com/Kevin-Robertson/SharpMad"

    # LAPS
    "LAPSToolkit"       = "https://github.com/leoloobeek/LAPSToolkit"

    # gMSA
    "GMSAPasswordReader" = "https://github.com/rvazarkar/GMSAPasswordReader"

    # SCCM/MECM
    "SharpSCCM"         = "https://github.com/Mayyhem/SharpSCCM"
    "sccmhunter"        = "https://github.com/garrettfoster13/sccmhunter"
    "MalSCCM"           = "https://github.com/nettitude/MalSCCM"
    "sccmwtf"           = "https://github.com/xpn/sccmwtf"

    # Azure AD
    "AADInternals"      = "https://github.com/Gerenios/AADInternals"
    "ROADtools"         = "https://github.com/dirkjanm/ROADtools"

    # DNS
    "dnsrecon"          = "https://github.com/darkoperator/dnsrecon"
    "dnstool.py"        = "https://github.com/dirkjanm/krbrelayx"
    "fierce"            = "https://github.com/mschwager/fierce"

    # Privilege Escalation
    "PowerSploit"       = "https://github.com/PowerShellMafia/PowerSploit"
    "SharpUp"           = "https://github.com/GhostPack/SharpUp"

    # Credential Hunting
    "Snaffler"          = "https://github.com/SnaffCon/Snaffler"
    "trufflehog"        = "https://github.com/trufflesecurity/trufflehog"

    # SCCM/PXE
    "PXEThief"          = "https://github.com/MWR-CyberSec/PXEThief"
    "PXEThiefy"         = "https://github.com/MWR-CyberSec/PXEThiefy"
    "ConfigManBearPig"  = "https://github.com/youhavbeenp4wned/ConfigManBearPig"

    # Graph Analysis
    "Neo4j"             = "https://github.com/neo4j/neo4j"

    # Exchange
    "PrivExchange"      = "https://github.com/dirkjanm/PrivExchange"
}

# Central Finding Definitions
# Structure: FindingID => @{ Title, Risk, BaseScore, Description, Impact, Attack, Remediation, References, Tools, MITRE }
#
# BaseScore values (0-100) represent intrinsic risk:
#   100     : Immediate domain compromise (DCSync, Golden Ticket)
#   80-99   : Direct privilege escalation (ESC1, Unconstrained Delegation)
#   60-79   : High-risk credential exposure or ACL abuse
#   40-59   : Credential exposure requiring cracking or significant ACL issues
#   30-39   : Configuration weaknesses enabling attacks
#   20-29   : Policy violations or informational findings
#   10-19   : Low-risk informational items
#   0       : Secure configurations (positive findings)
#
$Script:FindingDefinitions = @{

    # ============================================================================
    # KERBEROS FINDINGS
    # ============================================================================

    'KERBEROASTABLE_SPN' = @{
        Title = "Kerberoastable Service Account"
        Risk = "Finding"
        BaseScore = 35  # Requires offline password cracking
        Description = "This user account has a Service Principal Name (SPN) set, making it vulnerable to Kerberoasting. Any authenticated domain user can request a Kerberos service ticket (TGS) for this account and attempt to crack the password offline."
        Impact = @(
            "Attackers can obtain the account's password hash without triggering account lockout"
            "Offline password cracking can be performed indefinitely"
            "If the password is weak, the account can be compromised within hours or days"
            "Service accounts often have elevated privileges, enabling lateral movement or privilege escalation"
        )
        Attack = @(
            "1. Attacker authenticates to the domain with any valid user credentials"
            "2. Requests a TGS ticket for the service principal name"
            "3. Extracts the ticket from memory (encrypted with service account's password hash)"
            "4. Cracks the password offline using tools like Hashcat or John the Ripper"
            "5. Uses the cracked password to authenticate as the service account"
        )
        Remediation = @(
            "Use Group Managed Service Accounts (gMSA) instead of regular user accounts for services"
            "Set strong, randomly generated passwords (25+ characters) for service accounts"
            "Enable AES encryption for service accounts (reduces cracking speed significantly)"
            "Regularly rotate service account passwords"
            "Monitor for TGS requests to service accounts from unusual sources"
        )
        RemediationCommands = @(
            @{
                Description = "Enable AES encryption for the service account"
                Command = "Set-ADUser -Identity 'SERVICE_ACCOUNT' -KerberosEncryptionType AES128,AES256"
            }
            @{
                Description = "Set a strong random password (25+ chars)"
                Command = "`$NewPwd = [System.Web.Security.Membership]::GeneratePassword(25,5); Set-ADAccountPassword -Identity 'SERVICE_ACCOUNT' -NewPassword (ConvertTo-SecureString `$NewPwd -AsPlainText -Force)"
            }
            @{
                Description = "Remove the SPN if the service is no longer needed"
                Command = "Set-ADUser -Identity 'SERVICE_ACCOUNT' -ServicePrincipalNames @{Remove='SPN_VALUE'}"
            }
        )
        References = @(
            @{ Title = "Kerberoasting - MITRE ATT&CK"; Url = "https://attack.mitre.org/techniques/T1558/003/" }
            @{ Title = "Kerberoasting - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/kerberoast.html" }
            @{ Title = "Detecting Kerberoasting - Microsoft"; Url = "https://docs.microsoft.com/en-us/defender-for-identity/compromised-credentials-alerts" }
            @{ Title = "Kerberoasting Revisited - Harmj0y"; Url = "https://blog.harmj0y.net/redteaming/kerberoasting-revisited/" }
        )
        Tools = @("Rubeus", "Impacket", "PowerView", "Hashcat", "John the Ripper")
        MITRE = "T1558.003"
        Triggers = @(
            @{ Attribute = 'servicePrincipalName'; Custom = 'is_not_computer'; Severity = 'Finding' }
        )
    }

    'ASREP_ROASTABLE' = @{
        Title = "AS-REP Roastable Account (No Pre-Authentication)"
        Risk = "Finding"
        BaseScore = 30  # Requires offline password cracking, no auth needed
        Description = "This account has Kerberos pre-authentication disabled (DONT_REQUIRE_PREAUTH flag). This allows attackers to request an AS-REP ticket for this account without knowing the password, which can then be cracked offline."
        Impact = @(
            "Attackers can obtain the account's password hash without ANY authentication"
            "No failed login attempts are logged during the attack"
            "Offline password cracking can be performed indefinitely"
            "Compromised accounts can be used for initial access or privilege escalation"
        )
        Attack = @(
            "1. Attacker identifies accounts with DONT_REQUIRE_PREAUTH flag"
            "2. Sends AS-REQ to the KDC for the target account"
            "3. KDC responds with AS-REP encrypted with the account's password hash"
            "4. Attacker cracks the password offline using Hashcat or John the Ripper"
            "5. Uses the cracked password to authenticate as the target account"
        )
        Remediation = @(
            "Enable Kerberos pre-authentication for all accounts"
            "Review why pre-authentication was disabled and find alternatives"
            "Use strong passwords for accounts that must have pre-auth disabled"
            "Monitor for AS-REQ requests without pre-authentication"
        )
        RemediationCommands = @(
            @{
                Description = "Enable Kerberos pre-authentication for the account"
                Command = "Set-ADAccountControl -Identity 'USERNAME' -DoesNotRequirePreAuth `$false"
            }
            @{
                Description = "Find all accounts with pre-auth disabled"
                Command = "Get-ADUser -Filter {DoesNotRequirePreAuth -eq `$true} -Properties DoesNotRequirePreAuth"
            }
        )
        References = @(
            @{ Title = "AS-REP Roasting - MITRE ATT&CK"; Url = "https://attack.mitre.org/techniques/T1558/004/" }
            @{ Title = "AS-REP Roasting - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/asreproast.html" }
            @{ Title = "Kerberos Pre-Authentication - Microsoft"; Url = "https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/accounts" }
            @{ Title = "Roasting AS-REPs - Harmj0y"; Url = "https://blog.harmj0y.net/activedirectory/roasting-as-reps/" }
        )
        Tools = @("Rubeus", "Impacket", "Hashcat", "John the Ripper")
        MITRE = "T1558.004"
        Triggers = @(
            @{ Attribute = 'userAccountControl'; Pattern = 'DONT_REQ_PREAUTH'; Severity = 'Finding' }
        )
    }

    'KERBEROS_HASH_CRACKABLE' = @{
        Title = "Kerberos Hash - Offline Cracking"
        Risk = "Finding"
        BaseScore = 35
        Description = "This hash was extracted from a Kerberos ticket (TGS for Kerberoasting or AS-REP for AS-REP Roasting). The hash is encrypted with the target account's password and can be cracked offline without any interaction with the domain."
        Impact = @(
            "Offline cracking can run indefinitely without triggering account lockout"
            "Weak passwords can be cracked within minutes using modern GPUs"
            "Even complex passwords may fall to dictionary attacks with rules"
            "Once cracked, the attacker has valid credentials for the target account"
            "No logs are generated during offline cracking - the attack is undetectable"
        )
        Attack = @(
            "1. Save the hash to a file (e.g., hash.txt)"
            "2. Identify the hash type (Kerberoast: mode 13100/18200/19600/19700, AS-REP: mode 18200)"
            "3. Run Hashcat with a wordlist and rules for maximum effectiveness"
            "4. Wait for the password to be cracked"
            "5. Use the recovered password to authenticate as the service account"
        )
        Remediation = @(
            "Set strong, randomly generated passwords (25+ characters) for service accounts"
            "Use Group Managed Service Accounts (gMSA) which have 240-character auto-rotating passwords"
            "Enable AES encryption to slow down cracking (still crackable, but significantly slower)"
            "Implement a password policy that prevents dictionary words"
            "Regularly rotate service account passwords"
        )
        RemediationCommands = @(
            @{
                Description = "Crack Kerberoast hash (RC4/NTLM)"
                Command = "hashcat -m 13100 -a 0 hash.txt wordlist.txt -r rules/best64.rule"
            }
            @{
                Description = "Crack Kerberoast hash (AES256)"
                Command = "hashcat -m 19700 -a 0 hash.txt wordlist.txt -r rules/best64.rule"
            }
            @{
                Description = "Crack AS-REP hash"
                Command = "hashcat -m 18200 -a 0 hash.txt wordlist.txt -r rules/best64.rule"
            }
            @{
                Description = "Using John the Ripper"
                Command = "john --wordlist=wordlist.txt --rules=best64 hash.txt"
            }
        )
        References = @(
            @{ Title = "Hashcat Wiki - Kerberos TGS-REP"; Url = "https://hashcat.net/wiki/doku.php?id=example_hashes" }
            @{ Title = "Kerberoasting - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/kerberoast.html" }
            @{ Title = "AS-REP Roasting - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/asreproast.html" }
            @{ Title = "Managed Service Accounts - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview" }
        )
        Tools = @("Hashcat", "John the Ripper")
        MITRE = "T1110.002"
        Triggers = @(
            @{ Attribute = 'KerberoastingHash'; Severity = 'Finding' }
            @{ Attribute = 'ASREPRoastingHash'; Severity = 'Finding' }
        )
    }

    'KRBTGT_PASSWORD_OLD' = @{
        Title = "krbtgt Password Not Rotated"
        Risk = "Finding"
        BaseScore = 80
        Description = "The krbtgt account password has not been changed in an extended period. This account is used to encrypt all Kerberos tickets in the domain. If compromised, attackers can create Golden Tickets with unlimited validity."
        Impact = @(
            "Attackers with access to the krbtgt hash can forge any Kerberos ticket"
            "Golden Tickets provide complete domain compromise with persistence"
            "Tickets can be created for non-existent users with any group membership"
            "Standard password resets do not invalidate existing Golden Tickets"
            "Recovery requires rotating krbtgt password TWICE with proper timing"
        )
        Attack = @(
            "1. Attacker obtains the krbtgt password hash (via DCSync, NTDS.dit extraction)"
            "2. Creates a Golden Ticket with arbitrary user/group SIDs"
            "3. Uses the ticket to access any resource in the domain"
            "4. Ticket remains valid until krbtgt password is rotated twice"
        )
        Remediation = @(
            "Rotate krbtgt password every 180 days minimum"
            "After suspected compromise, rotate TWICE with 10+ hours between rotations"
            "Monitor for Kerberos ticket anomalies (long lifetime, unusual encryption)"
            "Implement tiered administration to protect krbtgt access"
        )
        RemediationCommands = @(
            @{
                Description = "Reset krbtgt password (use Microsoft script for production)"
                Command = "Set-ADAccountPassword -Identity 'krbtgt' -Reset -NewPassword (ConvertTo-SecureString -AsPlainText 'NewRandomPassword123!' -Force)"
            }
            @{
                Description = "Check krbtgt last password change"
                Command = "Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object Name, PasswordLastSet"
            }
        )
        References = @(
            @{ Title = "Golden Ticket - MITRE ATT&CK"; Url = "https://attack.mitre.org/techniques/T1558/001/" }
            @{ Title = "Golden Ticket - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/golden-ticket.html" }
            @{ Title = "krbtgt Account Password Reset - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password" }
            @{ Title = "Detecting Golden Tickets"; Url = "https://adsecurity.org/?p=1515" }
        )
        Tools = @("Mimikatz", "Impacket", "Rubeus")
        MITRE = "T1558.001"
        Triggers = @(
            @{ Attribute = 'krbtgtPasswordAge'; Custom = 'days_over_365'; Severity = 'Finding' }
            @{ Attribute = 'krbtgtPasswordAge'; Custom = 'days_181_to_365'; Severity = 'Hint' }
        )
    }

    'GUEST_ACCOUNT_ENABLED' = @{
        Title = "Guest Account Enabled"
        Risk = "Finding"
        BaseScore = 70
        Description = "The built-in Guest account (RID 501) is enabled and potentially accessible for anonymous or low-privilege access. This account should normally be disabled as it provides an unnecessary attack vector."
        Impact = @(
            "Allows unauthenticated or minimally authenticated access"
            "Can be used for initial foothold in the network"
            "Often has weak or no password protection"
            "May have been granted unintended permissions over time"
        )
        Attack = @(
            "1. Attacker identifies enabled Guest account"
            "2. Attempts authentication with blank or common passwords"
            "3. Enumerates accessible resources and permissions"
            "4. Uses Guest access for lateral movement or privilege escalation"
        )
        Remediation = @(
            "Disable the Guest account immediately"
            "Review group memberships and remove from all groups"
            "Audit any permissions explicitly granted to Guest"
            "Monitor for attempts to re-enable the account"
        )
        RemediationCommands = @(
            @{
                Description = "Disable Guest account via PowerShell"
                Command = "Disable-ADAccount -Identity 'Guest'"
            }
            @{
                Description = "Verify Guest account is disabled"
                Command = "Get-ADUser -Identity 'Guest' -Properties Enabled | Select-Object Name,Enabled,SID"
            }
            @{
                Description = "Disable Guest account via Group Policy (domain-wide enforcement)"
                Command = "# In Group Policy Management: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > 'Accounts: Guest account status' = Disabled"
            }
            @{
                Description = "Remove Guest account from all group memberships"
                Command = "Get-ADUser -Identity 'Guest' -Properties MemberOf | Select-Object -ExpandProperty MemberOf | ForEach-Object { Remove-ADGroupMember -Identity `$_ -Members 'Guest' -Confirm:`$false }"
            }
            @{
                Description = "Check for permissions explicitly granted to Guest account"
                Command = "(Get-Acl 'AD:\\DC=domain,DC=com').Access | Where-Object {`$_.IdentityReference -like '*Guest*'} | Format-Table IdentityReference,ActiveDirectoryRights,AccessControlType -AutoSize"
            }
        )
        References = @(
            @{ Title = "Microsoft Security Baseline - Guest Account"; Url = "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/accounts-guest-account-status" }
            @{ Title = "CIS Benchmark - Disable Guest Account"; Url = "https://www.cisecurity.org/benchmark/microsoft_windows_server" }
            @{ Title = "Accounts: Guest account status - Windows 10"; Url = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/accounts-guest-account-status" }
        )
        Tools = @()
        MITRE = "T1078.001"
        Triggers = @(
            @{ Attribute = 'accountStatus'; Pattern = 'ENABLED'; Severity = 'Hint' }
        )
    }

    'GUEST_ACCOUNT_DISABLED' = @{
        Title = "Guest Account Disabled"
        Risk = "Secure"
        BaseScore = 0
        Description = "The built-in Guest account (RID 501) is properly disabled. This is a secure configuration that prevents unauthenticated or low-privilege access through this legacy account."
        Impact = @(
            "Blocks anonymous or minimally authenticated access via Guest account"
            "Prevents attackers from using Guest account as initial foothold"
            "Reduces attack surface by disabling unnecessary account"
        )
        Attack = @()
        Remediation = @(
            "No action required - Guest account is already disabled"
            "Ensure the account remains disabled through Group Policy"
            "Regularly audit that the account has not been re-enabled"
        )
        RemediationCommands = @()
        References = @(
            @{ Title = "Microsoft Security Baseline - Guest Account"; Url = "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/accounts-guest-account-status" }
            @{ Title = "CIS Benchmark - Disable Guest Account"; Url = "https://www.cisecurity.org/benchmark/microsoft_windows_server" }
        )
        Tools = @()
        MITRE = ""
        Triggers = @(
            @{ Attribute = 'accountStatus'; Pattern = 'Disabled'; Severity = 'Secure' }
        )
    }

    # ============================================================================
    # DELEGATION FINDINGS
    # ============================================================================

    'UNCONSTRAINED_DELEGATION' = @{
        Title = "Unconstrained Delegation Enabled"
        Risk = "Finding"
        BaseScore = 85
        Description = "This computer or user has unconstrained delegation enabled (TRUSTED_FOR_DELEGATION). Any user who authenticates to this system will have their TGT stored in memory, allowing the system to impersonate them to ANY service in the domain."
        Impact = @(
            "TGTs of all authenticating users are cached on the system"
            "Attackers who compromise this system can steal TGTs of privileged users"
            "Enables impersonation attacks against any domain service"
            "Domain Controllers authenticate to computers via print spooler (PrinterBug)"
            "Can lead to complete domain compromise within minutes"
        )
        Attack = @(
            "1. Attacker compromises the unconstrained delegation system"
            "2. Coerces authentication from a Domain Controller (PrinterBug, PetitPotam)"
            "3. Captures the DC's TGT from memory"
            "4. Uses the TGT to perform DCSync and extract all domain credentials"
            "5. Creates Golden Tickets for persistent access"
        )
        Remediation = @(
            "Replace unconstrained delegation with constrained delegation or RBCD"
            "Add high-value accounts to 'Protected Users' group"
            "Enable 'Account is sensitive and cannot be delegated' for privileged accounts"
            "Disable the Print Spooler service on Domain Controllers"
            "Monitor for TGT requests from unconstrained delegation systems"
        )
        RemediationCommands = @(
            @{
                Description = "Remove unconstrained delegation from computer"
                Command = "Set-ADComputer -Identity 'COMPUTERNAME' -TrustedForDelegation `$false"
            }
            @{
                Description = "Add admin account to Protected Users group"
                Command = "Add-ADGroupMember -Identity 'Protected Users' -Members 'ADMIN_ACCOUNT'"
            }
            @{
                Description = "Make account sensitive (cannot be delegated)"
                Command = "Set-ADUser -Identity 'ADMIN_ACCOUNT' -AccountNotDelegated `$true"
            }
            @{
                Description = "Disable Print Spooler on Domain Controller"
                Command = "Invoke-Command -ComputerName 'DC_NAME' -ScriptBlock { Stop-Service Spooler; Set-Service Spooler -StartupType Disabled }"
            }
        )
        References = @(
            @{ Title = "Unconstrained Delegation - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/unconstrained-delegation.html" }
            @{ Title = "Kerberos Delegation - Microsoft"; Url = "https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/accounts" }
            @{ Title = "Kerberos Delegation Explained"; Url = "https://adsecurity.org/?p=1667" }
            @{ Title = "PrinterBug Attack"; Url = "https://github.com/leechristensen/SpoolSample" }
        )
        Tools = @("Rubeus", "Mimikatz", "SpoolSample", "PetitPotam", "Impacket")
        MITRE = "T1550.003"
        Triggers = @(
            @{ Attribute = 'userAccountControl'; Pattern = 'TRUSTED_FOR_DELEGATION'; Severity = 'Finding' }
        )
    }

    'CONSTRAINED_DELEGATION_PROTOCOL_TRANSITION' = @{
        Title = "Constrained Delegation with Protocol Transition"
        Risk = "Finding"
        BaseScore = 50
        Description = "This account has constrained delegation with protocol transition enabled (TRUSTED_TO_AUTH_FOR_DELEGATION). This allows the account to impersonate ANY user to the configured services without requiring the user's authentication."
        Impact = @(
            "Account can impersonate any user (including Domain Admins) to target services"
            "No authentication from the impersonated user is required"
            "If target services include LDAP/CIFS on DCs, enables privilege escalation"
            "Attackers who compromise this account gain significant lateral movement capability"
        )
        Attack = @(
            "1. Attacker compromises the account with protocol transition"
            "2. Uses S4U2Self to obtain a service ticket for any user"
            "3. Uses S4U2Proxy to access the configured target services as that user"
            "4. If LDAP is a target, performs privileged AD operations"
        )
        Remediation = @(
            "Review if protocol transition is actually required"
            "Switch to Resource-Based Constrained Delegation (RBCD) where possible"
            "Ensure target services don't include sensitive services like LDAP on DCs"
            "Add privileged accounts to 'Protected Users' group"
            "Monitor S4U2Self and S4U2Proxy requests"
        )
        RemediationCommands = @(
            @{
                Description = "Disable protocol transition (TrustedToAuthForDelegation flag)"
                Command = "Set-ADAccountControl -Identity 'ACCOUNT_NAME' -TrustedToAuthForDelegation `$false"
            }
            @{
                Description = "Find all accounts with protocol transition enabled"
                Command = "Get-ADObject -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=16777216)' -Properties userAccountControl,servicePrincipalName,msDS-AllowedToDelegateTo"
            }
            @{
                Description = "Enable auditing for Kerberos service ticket operations"
                Command = "auditpol /set /subcategory:'Kerberos Service Ticket Operations' /success:enable /failure:enable"
            }
        )
        References = @(
            @{ Title = "S4U2Self Abuse"; Url = "https://blog.harmj0y.net/activedirectory/s4u2pwnage/" }
            @{ Title = "Constrained Delegation - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/constrained-delegation.html" }
            @{ Title = "Constrained Delegation - Microsoft"; Url = "https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview" }
        )
        Tools = @("Rubeus", "Impacket", "PowerView")
        MITRE = "T1550.003"
        Triggers = @(
            @{ Attribute = 'userAccountControl'; Pattern = 'TRUSTED_TO_AUTH_FOR_DELEGATION'; Severity = 'Finding' }
            @{ Attribute = 'msDS-AllowedToDelegateTo'; Severity = 'Finding' }
        )
    }

    'RBCD_DANGEROUS_PRINCIPALS' = @{
        Title = "Resource-Based Constrained Delegation Misconfiguration"
        Risk = "Finding"
        BaseScore = 55
        Description = "The msDS-AllowedToActOnBehalfOfOtherIdentity attribute is set with principals that could allow privilege escalation. Attackers who control these principals can impersonate any user to this resource."
        Impact = @(
            "Principals in the RBCD list can impersonate any user to this computer"
            "If attackers control a listed principal, they can compromise this system"
            "Enables lateral movement through S4U2Proxy abuse"
        )
        Attack = @(
            "1. Attacker identifies computers with misconfigured RBCD"
            "2. Compromises or creates a principal in the allowed list"
            "3. Uses S4U2Self and S4U2Proxy to obtain a service ticket as any user"
            "4. Uses the ticket to access the target computer as Domain Admin"
        )
        Remediation = @(
            "Audit msDS-AllowedToActOnBehalfOfOtherIdentity on all computers"
            "Remove unnecessary principals from RBCD configurations"
            "Ensure only explicitly required accounts are in the delegation list"
            "Monitor changes to this attribute"
        )
        RemediationCommands = @(
            @{
                Description = "View current RBCD configuration for a computer"
                Command = "Get-ADComputer 'COMPUTERNAME' -Properties msDS-AllowedToActOnBehalfOfOtherIdentity,PrincipalsAllowedToDelegateToAccount | Select-Object Name,@{Name='AllowedPrincipals';Expression={`$_.PrincipalsAllowedToDelegateToAccount}}"
            }
            @{
                Description = "Remove ALL RBCD delegation from a computer (complete removal)"
                Command = "Set-ADComputer 'COMPUTERNAME' -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'"
            }
            @{
                Description = "Remove ALL RBCD delegation using friendly property name"
                Command = "Set-ADComputer 'COMPUTERNAME' -PrincipalsAllowedToDelegateToAccount `$null"
            }
            @{
                Description = "Find all computers with RBCD configured"
                Command = "Get-ADComputer -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity,PrincipalsAllowedToDelegateToAccount | Select-Object Name,DNSHostName,@{Name='AllowedPrincipals';Expression={`$_.PrincipalsAllowedToDelegateToAccount}}"
            }
        )
        References = @(
            @{ Title = "Resource-Based Constrained Delegation Abuse"; Url = "https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html" }
            @{ Title = "Set-ADComputer PrincipalsAllowedToDelegateToAccount"; Url = "https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adcomputer" }
            @{ Title = "RBCD - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/resource-based-constrained-delegation.html" }
            @{ Title = "Kerberos RBCD - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview" }
        )
        Tools = @("Rubeus", "PowerView", "Impacket")
        MITRE = "T1550.003"
        Triggers = @(
            @{ Attribute = 'msDS-AllowedToActOnBehalfOfOtherIdentity'; Severity = 'Finding' }
        )
    }

    # ============================================================================
    # ADCS (CERTIFICATE SERVICES) FINDINGS
    # ============================================================================

    'ESC1_TEMPLATE' = @{
        Title = "ESC1 - Vulnerable Certificate Template"
        Risk = "Finding"
        BaseScore = 90
        Description = "This certificate template allows the enrollee to specify a Subject Alternative Name (SAN) and enables Client Authentication. Any user who can enroll can request a certificate for any other user, including Domain Admins."
        Impact = @(
            "Any enrolling user can impersonate any other domain user"
            "Enables immediate privilege escalation to Domain Admin"
            "Certificates are valid for the template's lifetime (often 1-2 years)"
            "No password required - certificate-based authentication bypasses password policies"
        )
        Attack = @(
            "1. Attacker enrolls for a certificate using the vulnerable template"
            "2. Specifies Domain Admin's UPN in the Subject Alternative Name"
            "3. Uses the certificate for PKINIT authentication as Domain Admin"
            "4. Performs any privileged operations in the domain"
        )
        Remediation = @(
            "Remove 'ENROLLEE_SUPPLIES_SUBJECT' flag from the template"
            "Require CA Manager approval for certificate requests"
            "Restrict enrollment permissions to specific required groups"
            "Use 'Supply in the request' only when absolutely necessary with strong controls"
        )
        RemediationCommands = @(
            @{
                Description = "Remove ENROLLEE_SUPPLIES_SUBJECT flag from certificate template (requires Enterprise Admin)"
                Command = @'
# Get template DN (replace 'VulnerableTemplate' with actual template name)
$templateName = "VulnerableTemplate"
$configNC = (Get-ADRootDSE).configurationNamingContext
$templateDN = "CN=$templateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

# Get current flag value
$template = Get-ADObject -Identity $templateDN -Properties msPKI-Certificate-Name-Flag
$currentFlag = $template.'msPKI-Certificate-Name-Flag'

# Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (0x00000001)
$newFlag = $currentFlag -band (-bnot 0x00000001)

# Update template
Set-ADObject -Identity $templateDN -Replace @{'msPKI-Certificate-Name-Flag' = $newFlag}
'@
            }
            @{
                Description = "Require CA Manager approval (CT_FLAG_PEND_ALL_REQUESTS = 0x00000002)"
                Command = @'
$templateName = "VulnerableTemplate"
$configNC = (Get-ADRootDSE).configurationNamingContext
$templateDN = "CN=$templateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

# Get current enrollment flag
$template = Get-ADObject -Identity $templateDN -Properties msPKI-Enrollment-Flag
$currentFlag = $template.'msPKI-Enrollment-Flag'

# Add CT_FLAG_PEND_ALL_REQUESTS (0x00000002)
$newFlag = $currentFlag -bor 0x00000002

# Update template
Set-ADObject -Identity $templateDN -Replace @{'msPKI-Enrollment-Flag' = $newFlag}
'@
            }
            @{
                Description = "Remove template from CA (stop issuing certificates immediately)"
                Command = @'
# On the CA server, remove the vulnerable template
certutil -deltemplate "VulnerableTemplate"

# Or via PowerShell (run on CA server)
$caName = "$env:COMPUTERNAME\$(certutil -dump | Select-String 'Config:' | ForEach-Object { ($_ -split '\\')[-1].Trim() })"
Remove-CATemplate -Name "VulnerableTemplate" -Force
'@
            }
        )
        References = @(
            @{ Title = "Certified Pre-Owned - SpecterOps"; Url = "https://posts.specterops.io/certified-pre-owned-d95910965cd2" }
            @{ Title = "AD CS ESC1 - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.html#esc1" }
            @{ Title = "Certificate Template Security - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts" }
        )
        Tools = @("Certify", "Certipy", "ForgeCert", "Rubeus")
        MITRE = "T1649"
        Triggers = @(
            @{ Attribute = 'Vulnerabilities'; Pattern = 'ESC1'; Severity = 'Finding' }
            @{ Attribute = 'CertificateNameFlagDisplay'; Pattern = 'ENROLLEE_SUPPLIES_SUBJECT'; Severity = 'Finding' }
            @{ Attribute = 'EnrolleeSuppliesSubject'; Pattern = '^(True|Yes)$'; Severity = 'Finding' }
        )
    }

    'ESC2_TEMPLATE' = @{
        Title = "ESC2 - Any Purpose or SubCA Certificate Template"
        Risk = "Finding"
        BaseScore = 80
        Description = "This certificate template has 'Any Purpose' EKU or 'SubCA' capability, allowing the issued certificate to be used for any purpose including Client Authentication, Code Signing, or even issuing other certificates."
        Impact = @(
            "Certificates can be used for authentication as any user"
            "SubCA certificates can issue other certificates"
            "Enables code signing for malware"
            "Complete compromise of PKI trust chain possible"
        )
        Attack = @(
            "1. Attacker enrolls for a certificate with Any Purpose/SubCA"
            "2. For SubCA: Issues certificates for any user"
            "3. For Any Purpose: Uses certificate for Client Authentication as target user"
            "4. Bypasses all certificate-based access controls"
        )
        Remediation = @(
            "Remove 'Any Purpose' EKU - specify only required purposes"
            "Never allow SubCA certificates to be issued to non-CA systems"
            "Restrict enrollment permissions"
            "Require CA Manager approval"
        )
        RemediationCommands = @(
            @{
                Description = "Remove 'Any Purpose' EKU and set specific EKUs (requires Enterprise Admin)"
                Command = @'
$templateName = "VulnerableTemplate"
$configNC = (Get-ADRootDSE).configurationNamingContext
$templateDN = "CN=$templateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

# Define specific EKUs (replace with required OIDs)
# Common EKUs:
# 1.3.6.1.5.5.7.3.2 = Client Authentication
# 1.3.6.1.5.5.7.3.1 = Server Authentication
# 1.3.6.1.4.1.311.10.3.12 = Document Signing
$specificEKUs = @(
    "1.3.6.1.5.5.7.3.2"  # Client Authentication
)

# Update template EKUs (removes Any Purpose OID 2.5.29.37.0)
Set-ADObject -Identity $templateDN -Replace @{'msPKI-Certificate-Application-Policy' = $specificEKUs}
'@
            }
            @{
                Description = "Disable SubCA capability (CT_FLAG_IS_CA flag in msPKI-Enrollment-Flag)"
                Command = @'
$templateName = "VulnerableTemplate"
$configNC = (Get-ADRootDSE).configurationNamingContext
$templateDN = "CN=$templateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

# Get current enrollment flag
$template = Get-ADObject -Identity $templateDN -Properties msPKI-Enrollment-Flag
$currentFlag = $template.'msPKI-Enrollment-Flag'

# Remove CT_FLAG_IS_CA (0x00000080) if present
$newFlag = $currentFlag -band (-bnot 0x00000080)

# Update template
Set-ADObject -Identity $templateDN -Replace @{'msPKI-Enrollment-Flag' = $newFlag}
'@
            }
            @{
                Description = "Restrict enrollment permissions to specific groups only"
                Command = @'
$templateName = "VulnerableTemplate"
$configNC = (Get-ADRootDSE).configurationNamingContext
$templateDN = "CN=$templateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

# Remove Authenticated Users / Domain Users enrollment rights
$template = Get-ADObject -Identity $templateDN
$acl = Get-Acl -Path "AD:\$templateDN"

# Remove enrollment rights for Authenticated Users
$sid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")  # Authenticated Users
$acl.Access | Where-Object {$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $sid -and $_.ActiveDirectoryRights -match "ExtendedRight"} | ForEach-Object {
    $acl.RemoveAccessRule($_) | Out-Null
}

# Add specific group (replace with your group)
$groupSID = (Get-ADGroup "SpecificEnrollmentGroup").SID
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $groupSID,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AccessControlType]::Allow,
    [Guid]"0e10c968-78fb-11d2-90d4-00c04f79dc55"  # Certificate-Enrollment
)
$acl.AddAccessRule($ace)

Set-Acl -Path "AD:\$templateDN" -AclObject $acl
'@
            }
        )
        References = @(
            @{ Title = "Certified Pre-Owned - SpecterOps"; Url = "https://posts.specterops.io/certified-pre-owned-d95910965cd2" }
            @{ Title = "AD CS ESC2 - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.html#esc2" }
            @{ Title = "Certificate EKU Configuration - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts" }
        )
        Tools = @("Certify", "Certipy")
        MITRE = "T1649"
        Triggers = @(
            @{ Attribute = 'Vulnerabilities'; Pattern = 'ESC2'; Severity = 'Finding' }
            @{ Attribute = 'AnyPurpose'; Pattern = '^(True|Yes)$'; Severity = 'Finding' }
            # ExtendedKeyUsage: Any Purpose OID or Certificate Request Agent OID = Finding
            @{ Attribute = 'ExtendedKeyUsage'; Pattern = '2\.5\.29\.37\.0|Any Purpose'; Severity = 'Finding' }
            @{ Attribute = 'ExtendedKeyUsage'; Pattern = '1\.3\.6\.1\.4\.1\.311\.20\.2\.1|Certificate Request Agent'; Severity = 'Finding' }
        )
    }

    'ESC3_TEMPLATE' = @{
        Title = "ESC3 - Certificate Request Agent Template"
        Risk = "Finding"
        BaseScore = 75
        Description = "This template allows enrollment for a Certificate Request Agent (Enrollment Agent) certificate, which can then be used to enroll for certificates on behalf of other users, bypassing normal enrollment restrictions."
        Impact = @(
            "Enrollment Agent can request certificates for any user"
            "Bypasses per-user enrollment restrictions on other templates"
            "Enables escalation through certificate impersonation"
        )
        Attack = @(
            "1. Attacker enrolls for Certificate Request Agent certificate"
            "2. Uses the agent certificate to request certificates for other users"
            "3. Obtains certificate for Domain Admin or other privileged account"
            "4. Authenticates using the obtained certificate"
        )
        Remediation = @(
            "Restrict Enrollment Agent certificate issuance to specific users"
            "Enable 'Restrict enrollment agents' on the CA"
            "Configure enrollment agent restrictions to limit which templates agents can use"
            "Monitor enrollment agent certificate requests"
        )
        RemediationCommands = @(
            @{
                Description = "Restrict enrollment permissions on Certificate Request Agent template (requires Enterprise Admin)"
                Command = @'
$templateName = "EnrollmentAgent"  # Or your Certificate Request Agent template name
$configNC = (Get-ADRootDSE).configurationNamingContext
$templateDN = "CN=$templateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

# Get current ACL
$acl = Get-Acl -Path "AD:\$templateDN"

# Remove Authenticated Users / Domain Users enrollment rights
$authenticatedUsersSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")  # Authenticated Users
$domainUsersSID = (Get-ADGroup "Domain Users").SID

$acl.Access | Where-Object {
    ($_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $authenticatedUsersSID -or
     $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $domainUsersSID) -and
    $_.ActiveDirectoryRights -match "ExtendedRight"
} | ForEach-Object {
    $acl.RemoveAccessRule($_) | Out-Null
}

# Add specific trusted group only
$trustedGroupSID = (Get-ADGroup "EnrollmentAgentAdmins").SID
$enrollmentGuid = [Guid]"0e10c968-78fb-11d2-90d4-00c04f79dc55"  # Certificate-Enrollment
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $trustedGroupSID,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AccessControlType]::Allow,
    $enrollmentGuid
)
$acl.AddAccessRule($ace)

Set-Acl -Path "AD:\$templateDN" -AclObject $acl
'@
            }
            @{
                Description = "Configure CA enrollment agent restrictions (run on CA server)"
                Command = @'
# Enable enrollment agent restrictions on the CA
certutil -setreg policy\EnableEnrollmentAgentRestrictions 1

# Create restriction policy file (example: restrict to specific templates)
$restrictionXml = @"
<EnrollmentAgentRestrictions>
  <EnrollmentAgentRestriction>
    <EnrollmentAgentCertificate>
      <Template>EnrollmentAgent</Template>
    </EnrollmentAgentCertificate>
    <AllowedTemplates>
      <Template>SpecificTemplate1</Template>
      <Template>SpecificTemplate2</Template>
    </AllowedTemplates>
  </EnrollmentAgentRestriction>
</EnrollmentAgentRestrictions>
"@

# Save and apply restrictions
$restrictionXml | Out-File "C:\EnrollmentAgentRestrictions.xml"
certutil -setreg policy\EnrollmentAgentRestrictions "@C:\EnrollmentAgentRestrictions.xml"

# Restart CA service
net stop certsvc
net start certsvc
'@
            }
            @{
                Description = "Disable template or require manager approval"
                Command = @'
$templateName = "EnrollmentAgent"
$configNC = (Get-ADRootDSE).configurationNamingContext
$templateDN = "CN=$templateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

# Option 1: Require CA Manager approval
$template = Get-ADObject -Identity $templateDN -Properties msPKI-Enrollment-Flag
$currentFlag = $template.'msPKI-Enrollment-Flag'
$newFlag = $currentFlag -bor 0x00000002  # CT_FLAG_PEND_ALL_REQUESTS
Set-ADObject -Identity $templateDN -Replace @{'msPKI-Enrollment-Flag' = $newFlag}

# Option 2: Remove template from CA entirely
# certutil -deltemplate "EnrollmentAgent"
'@
            }
        )
        References = @(
            @{ Title = "Certified Pre-Owned - SpecterOps"; Url = "https://posts.specterops.io/certified-pre-owned-d95910965cd2" }
            @{ Title = "AD CS ESC3 - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.html#esc3" }
            @{ Title = "Enrollment Agent Restrictions - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts" }
        )
        Tools = @("Certify", "Certipy")
        MITRE = "T1649"
        Triggers = @(
            @{ Attribute = 'Vulnerabilities'; Pattern = 'ESC3'; Severity = 'Finding' }
            @{ Attribute = 'EnrollmentAgent'; Pattern = '^(True|Yes)$'; Severity = 'Finding' }
        )
    }

    'ESC4_TEMPLATE' = @{
        Title = "ESC4 - Certificate Template with Dangerous ACL"
        Risk = "Finding"
        BaseScore = 70
        Description = "This certificate template has ACL entries that allow unprivileged users to modify the template configuration. Attackers can modify the template to enable ESC1/ESC2 conditions and then exploit them."
        Impact = @(
            "Attackers can modify template to allow arbitrary SANs"
            "Can enable Any Purpose or Client Authentication EKUs"
            "Effectively converts to ESC1/ESC2 vulnerability"
            "Changes to templates take effect immediately"
        )
        Attack = @(
            "1. Attacker identifies template with writable ACL"
            "2. Modifies template to enable ENROLLEE_SUPPLIES_SUBJECT"
            "3. Adds Client Authentication EKU if not present"
            "4. Enrolls for certificate with Domain Admin SAN"
            "5. Authenticates as Domain Admin"
        )
        Remediation = @(
            "Audit template ACLs - remove unnecessary write permissions"
            "Only Domain Admins and Enterprise Admins should modify templates"
            "Monitor template modifications via Windows event logs"
        )
        RemediationCommands = @(
            @{
                Description = "Remove dangerous write permissions from certificate template (requires Enterprise Admin)"
                Command = @'
$templateName = "VulnerableTemplate"
$configNC = (Get-ADRootDSE).configurationNamingContext
$templateDN = "CN=$templateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

# Get current ACL
$acl = Get-Acl -Path "AD:\$templateDN"

# Define dangerous permissions to remove
$dangerousRights = @(
    [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
    [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
    [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
)

# Remove dangerous rights for non-admin users
$acl.Access | Where-Object {
    # Keep only Domain Admins, Enterprise Admins, and SYSTEM
    $sid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
    $isAdmin = ($sid.Value -match '-512$') -or  # Domain Admins
               ($sid.Value -match '-519$') -or  # Enterprise Admins
               ($sid.Value -eq 'S-1-5-18')      # SYSTEM

    -not $isAdmin -and ($_.ActiveDirectoryRights -band $dangerousRights)
} | ForEach-Object {
    $acl.RemoveAccessRule($_) | Out-Null
}

Set-Acl -Path "AD:\$templateDN" -AclObject $acl
'@
            }
            @{
                Description = "Audit all certificate template ACLs for dangerous permissions"
                Command = @'
$configNC = (Get-ADRootDSE).configurationNamingContext
$templateContainer = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

# Get all certificate templates
$templates = Get-ADObject -SearchBase $templateContainer -Filter {objectClass -eq "pKICertificateTemplate"} -Properties nTSecurityDescriptor

$dangerousTemplates = @()

foreach ($template in $templates) {
    $acl = $template.nTSecurityDescriptor

    # Check for dangerous permissions granted to non-admin users
    $acl.Access | Where-Object {
        $sid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
        $isAdmin = ($sid.Value -match '-512$|-519$') -or ($sid.Value -eq 'S-1-5-18')

        -not $isAdmin -and (
            $_.ActiveDirectoryRights -match "WriteProperty|WriteDacl|WriteOwner|GenericWrite|GenericAll"
        )
    } | ForEach-Object {
        $dangerousTemplates += [PSCustomObject]@{
            Template = $template.Name
            Principal = $_.IdentityReference
            Rights = $_.ActiveDirectoryRights
            AccessControlType = $_.AccessControlType
        }
    }
}

# Display results
$dangerousTemplates | Format-Table -AutoSize

# Export to CSV
$dangerousTemplates | Export-Csv "DangerousTemplateACLs.csv" -NoTypeInformation
'@
            }
        )
        References = @(
            @{ Title = "Certified Pre-Owned - SpecterOps"; Url = "https://posts.specterops.io/certified-pre-owned-d95910965cd2" }
            @{ Title = "AD CS ESC4 - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.html#esc4" }
            @{ Title = "Certificate Template Permissions - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts" }
        )
        Tools = @("Certify", "Certipy", "PowerView")
        MITRE = "T1649"
        Triggers = @(
            @{ Attribute = 'Vulnerabilities'; Pattern = 'ESC4'; Severity = 'Finding' }
        )
    }

    'ESC5_PKI_CONTAINER_ACL' = @{
        Title = "ESC5 - Vulnerable PKI Container Permissions"
        Risk = "Finding"
        BaseScore = 80
        Description = "PKI container objects in Active Directory have ACL entries that allow unprivileged users to modify the PKI infrastructure. Attackers can create new vulnerable certificate templates, modify existing templates, manipulate the NTAuth store, or alter issuance policies."
        Impact = @(
            "Attackers can create new ESC1-vulnerable templates from scratch"
            "Attackers can modify existing secure templates to make them vulnerable"
            "Attackers can grant themselves enrollment permissions on any template"
            "Attackers can manipulate the NTAuth store to trust rogue CAs"
            "Complete PKI infrastructure takeover possible"
        )
        Attack = @(
            "1. Identify dangerous permissions on PKI containers (GenericAll, WriteDacl, WriteOwner)"
            "2. Create a new certificate template with ESC1 conditions"
            "3. Grant enrollment permissions to attacker-controlled account"
            "4. Request certificate with arbitrary SAN (e.g., Domain Admin UPN)"
            "5. Use certificate for authentication and privilege escalation"
        )
        Remediation = @(
            "Review ACLs on all PKI container objects"
            "Remove GenericAll, WriteDacl, WriteOwner rights from unprivileged principals"
            "Only Domain Admins, Enterprise Admins, and specific PKI admins should have write access"
            "Key containers to check:"
            "  - CN=Public Key Services,CN=Services,CN=Configuration,DC=..."
            "  - CN=Certificate Templates,CN=Public Key Services,..."
            "  - CN=Enrollment Services,CN=Public Key Services,..."
            "  - CN=NTAuthCertificates,CN=Public Key Services,..."
            "  - CN=OID,CN=Public Key Services,..."
            "Audit existing templates for unauthorized modifications"
        )
        RemediationCommands = @(
            @{
                Description = "Audit all PKI container ACLs for dangerous permissions (requires Enterprise Admin)"
                Command = @'
$configNC = (Get-ADRootDSE).configurationNamingContext
$pkiContainers = @(
    "CN=Public Key Services,CN=Services,$configNC",
    "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC",
    "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC",
    "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,$configNC",
    "CN=OID,CN=Public Key Services,CN=Services,$configNC"
)

$dangerousContainers = @()

foreach ($containerDN in $pkiContainers) {
    $acl = Get-Acl -Path "AD:\$containerDN"

    # Check for dangerous permissions granted to non-admin users
    $acl.Access | Where-Object {
        $sid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
        $isAdmin = ($sid.Value -match '-512$|-519$') -or ($sid.Value -eq 'S-1-5-18')  # Domain/Enterprise Admins or SYSTEM

        -not $isAdmin -and (
            $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner|WriteProperty"
        )
    } | ForEach-Object {
        $dangerousContainers += [PSCustomObject]@{
            Container = $containerDN
            Principal = $_.IdentityReference
            Rights = $_.ActiveDirectoryRights
            AccessControlType = $_.AccessControlType
        }
    }
}

# Display results
$dangerousContainers | Format-Table -AutoSize

# Export to CSV
$dangerousContainers | Export-Csv "DangerousPKIContainerACLs.csv" -NoTypeInformation
'@
            }
            @{
                Description = "Remove dangerous write permissions from PKI containers (requires Enterprise Admin)"
                Command = @'
$containerDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"  # Replace with vulnerable container DN
$configNC = (Get-ADRootDSE).configurationNamingContext

# Get current ACL
$acl = Get-Acl -Path "AD:\$containerDN"

# Define dangerous permissions to remove
$dangerousRights = @(
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
    [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner,
    [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
)

# Remove dangerous rights for non-admin users
$acl.Access | Where-Object {
    $sid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
    # Keep only Domain Admins (512), Enterprise Admins (519), and SYSTEM
    $isAdmin = ($sid.Value -match '-512$|-519$') -or ($sid.Value -eq 'S-1-5-18')

    -not $isAdmin -and ($_.ActiveDirectoryRights -band $dangerousRights)
} | ForEach-Object {
    $acl.RemoveAccessRule($_) | Out-Null
}

Set-Acl -Path "AD:\$containerDN" -AclObject $acl
'@
            }
            @{
                Description = "Monitor PKI container modifications (enable auditing)"
                Command = @'
# Enable auditing on PKI containers (requires Domain Admin or Enterprise Admin)
$configNC = (Get-ADRootDSE).configurationNamingContext
$containerDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

# Get current ACL
$acl = Get-Acl -Path "AD:\$containerDN" -Audit

# Add audit rule for Everyone - Write operations
$everyoneSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")  # Everyone
$auditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
    $everyoneSID,
    [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl -bor [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner,
    [System.Security.AccessControl.AuditFlags]::Success -bor [System.Security.AccessControl.AuditFlags]::Failure,
    [Guid]::Empty
)
$acl.AddAuditRule($auditRule)

Set-Acl -Path "AD:\$containerDN" -AclObject $acl
'@
            }
        )
        References = @(
            @{ Title = "Certified Pre-Owned - SpecterOps"; Url = "https://posts.specterops.io/certified-pre-owned-d95910965cd2" }
            @{ Title = "AD CS ESC5 - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.html#esc5" }
            @{ Title = "Certipy - ESC5 Detection"; Url = "https://github.com/ly4k/Certipy" }
        )
        Tools = @("Certipy", "Certify", "PowerView")
        MITRE = "T1649"
        Triggers = @(
            @{ Attribute = 'Container'; Pattern = 'Public Key Services|Certificate Templates|Enrollment Services|NTAuthCertificates|OID'; Severity = 'Finding' }
            @{ Attribute = 'Rights'; Pattern = 'GenericAll|WriteDacl|WriteOwner'; Severity = 'Finding' }
        )
    }

    'ESC6_CA' = @{
        Title = "ESC6 - CA with EDITF_ATTRIBUTESUBJECTALTNAME2"
        Risk = "Finding"
        BaseScore = 65
        Description = "The Certificate Authority has the EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled, allowing ANY certificate request to include an arbitrary Subject Alternative Name, regardless of template settings."
        Impact = @(
            "All certificate templates become effectively ESC1-vulnerable"
            "Any user who can enroll for ANY certificate can impersonate any user"
            "Template-level SAN restrictions are completely bypassed"
            "Enables domain-wide privilege escalation"
        )
        Attack = @(
            "1. Attacker finds any template they can enroll for"
            "2. Requests certificate and adds Domain Admin UPN as SAN in the request"
            "3. CA accepts the SAN due to the flag"
            "4. Uses certificate to authenticate as Domain Admin"
        )
        Remediation = @(
            "Disable EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA"
            "Run: certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2"
            "Restart the CA service after making changes"
            "Audit all existing certificates for suspicious SANs"
        )
        RemediationCommands = @(
            @{
                Description = "Check if EDITF_ATTRIBUTESUBJECTALTNAME2 flag is enabled (run on CA server)"
                Command = @'
# Query current EditFlags setting
certutil -getreg policy\EditFlags

# Look for EDITF_ATTRIBUTESUBJECTALTNAME2 (0x40000) in output
# If present, flag is enabled and vulnerable
'@
            }
            @{
                Description = "Disable EDITF_ATTRIBUTESUBJECTALTNAME2 flag (run on CA server, requires CA Admin)"
                Command = @'
# Disable the vulnerable flag
certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2

# Restart CA service to apply changes
net stop certsvc
net start certsvc

# Verify flag is disabled
certutil -getreg policy\EditFlags
'@
            }
            @{
                Description = "Audit issued certificates for suspicious Subject Alternative Names"
                Command = @'
# Export all issued certificates from CA database
certutil -view -restrict "Disposition=20" -out "SubjectAlternativeName,Request.RequesterName,NotAfter" csv > IssuedCerts.csv

# Review IssuedCerts.csv for:
# - SANs containing privileged usernames (administrator, domain admins, etc.)
# - SANs not matching the requester name
# - SANs with UPNs from different security groups

# Optional: Import CSV for analysis
$certs = Import-Csv IssuedCerts.csv
$certs | Where-Object { $_.'Request.RequesterName' -notmatch $_.SubjectAlternativeName } | Format-Table -AutoSize
'@
            }
        )
        References = @(
            @{ Title = "Certified Pre-Owned - SpecterOps"; Url = "https://posts.specterops.io/certified-pre-owned-d95910965cd2" }
            @{ Title = "AD CS ESC6 - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.html#esc6" }
            @{ Title = "EDITF_ATTRIBUTESUBJECTALTNAME2 - Microsoft"; Url = "https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786426(v=ws.11)" }
        )
        Tools = @("Certify", "Certipy", "certutil")
        MITRE = "T1649"
        Triggers = @(
            @{ Attribute = 'Vulnerabilities'; Pattern = 'ESC6'; Severity = 'Finding' }
        )
    }

    'ESC8_WEB_ENROLLMENT' = @{
        Title = "ESC8 - NTLM Relay to Web Enrollment"
        Risk = "Finding"
        BaseScore = 70
        Description = "The CA has Web Enrollment enabled without Extended Protection for Authentication (EPA). Attackers can relay NTLM authentication to the CA's web interface to obtain certificates as the relayed user."
        Impact = @(
            "NTLM authentication can be relayed to obtain certificates"
            "Domain Controller machine accounts can be relayed to get DC certificates"
            "DC certificates enable DCSync and complete domain compromise"
            "No credentials required - only network position for relay"
        )
        Attack = @(
            "1. Attacker coerces DC authentication (PetitPotam, PrinterBug)"
            "2. Relays DC's NTLM authentication to CA web enrollment"
            "3. Requests a certificate for the DC's machine account"
            "4. Uses the certificate to perform DCSync"
            "5. Extracts all domain credentials"
        )
        Remediation = @(
            "Enable Extended Protection for Authentication (EPA) on IIS"
            "Disable NTLM authentication on CA web enrollment"
            "Require Kerberos authentication for certificate enrollment"
            "Disable web enrollment if not required"
            "Enable LDAP signing and channel binding on DCs"
        )
        RemediationCommands = @(
            @{
                Description = "Enable Extended Protection for Authentication (EPA) on IIS"
                Command = @'
# Run on CA server hosting web enrollment
# Enable EPA for Default Web Site
Import-Module WebAdministration
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/authentication/windowsAuthentication' -Name 'extendedProtection.tokenChecking' -Value 'Require' -Location 'Default Web Site'

# Or via appcmd.exe
C:\Windows\System32\inetsrv\appcmd.exe set config "Default Web Site" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:Require /commit:apphost
'@
            }
            @{
                Description = "Disable NTLM and require Kerberos for web enrollment"
                Command = @'
# Disable NTLM provider and keep only Negotiate (Kerberos)
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/authentication/windowsAuthentication' -Name 'providers' -Value @{value='Negotiate'}

# Verify settings
Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/authentication/windowsAuthentication' -Name 'providers'
'@
            }
            @{
                Description = "Disable web enrollment if not required"
                Command = @'
# Remove CertSrv web application
Remove-WebApplication -Name 'CertSrv' -Site 'Default Web Site'

# Or uninstall the Web Enrollment role
Uninstall-WindowsFeature -Name ADCS-Web-Enrollment
'@
            }
        )
        References = @(
            @{ Title = "ADCS ESC8 - PetitPotam"; Url = "https://github.com/topotam/PetitPotam" }
            @{ Title = "Certified Pre-Owned - SpecterOps"; Url = "https://posts.specterops.io/certified-pre-owned-d95910965cd2" }
            @{ Title = "AD CS ESC8 - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.html#esc8" }
            @{ Title = "KB5005413: Mitigate NTLM Relay on ADCS - Microsoft"; Url = "https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429" }
        )
        Tools = @("Certipy", "PetitPotam", "ntlmrelayx", "Impacket")
        MITRE = "T1187"
        Triggers = @(
            @{ Attribute = 'Vulnerabilities'; Pattern = 'ESC8'; Severity = 'Finding' }
            @{ Attribute = 'WebEnrollmentEndpoints'; ExcludePattern = '\[EPA:\s*Enabled\]'; Severity = 'Finding' }
        )
    }

    # ADCS CA - HTTP Available without HTTPS (Red/Finding)
    'ADCS_HTTP_AVAILABLE' = @{
        Title = "CA HTTP Enrollment Available"
        Risk = "Finding"
        BaseScore = 50
        Description = "The Certificate Authority has HTTP (unencrypted) enrollment endpoints available. This allows attackers to perform NTLM relay attacks against the CA web enrollment interface, as credentials are transmitted without TLS protection."
        Impact = @(
            "NTLM relay attacks against CA enrollment endpoints"
            "Credential interception through man-in-the-middle attacks"
            "Combined with coercion (PetitPotam, PrinterBug) enables domain compromise"
            "Certificates obtained via relay can impersonate the victim"
        )
        Remediation = @(
            "Enforce HTTPS-only access for all CA enrollment endpoints"
            "Disable HTTP bindings on the CA's IIS server"
            "Enable Extended Protection for Authentication (EPA)"
            "If web enrollment is not required, disable it entirely"
        )
        RemediationCommands = @(
            @{
                Description = "Enable Require SSL in IIS for Certificate Authority Web Enrollment"
                Command = "Import-Module WebAdministration; Set-WebConfigurationProperty -Filter '/system.webServer/security/access' -Name 'sslFlags' -Value 'Ssl' -PSPath 'IIS:\' -Location 'Default Web Site/CertSrv'"
            }
            @{
                Description = "Enable Extended Protection for Authentication (EPA) for CA Web Enrollment"
                Command = "Import-Module WebAdministration; Set-WebConfigurationProperty -Filter '/system.webServer/security/authentication/windowsAuthentication' -Name 'extendedProtection.tokenChecking' -Value 'Required' -PSPath 'IIS:\' -Location 'Default Web Site/CertSrv'"
            }
            @{
                Description = "Restart IIS to apply changes"
                Command = "iisreset /restart"
            }
        )
        References = @(
            @{ Title = "Certified Pre-Owned - SpecterOps"; Url = "https://posts.specterops.io/certified-pre-owned-d95910965cd2" }
            @{ Title = "ESC8 - NTLM Relay"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.html#esc8" }
            @{ Title = "KB5005413: Mitigate NTLM Relay on ADCS - Microsoft"; Url = "https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429" }
        )
        Tools = @("Certipy", "ntlmrelayx", "PetitPotam")
        MITRE = "T1187"
        Triggers = @(
            @{ Attribute = 'HttpAvailable'; Pattern = 'True'; Severity = 'Finding' }
        )
    }

    # ADCS Template - Non-Privileged Enrollment Principals (Yellow/Hint)
    'ADCS_NONPRIV_ENROLLMENT' = @{
        Title = "Non-Privileged Enrollment Principal"
        Risk = "Hint"
        BaseScore = 20
        Description = "This certificate template allows enrollment by non-privileged users or groups. While not inherently vulnerable, this increases the attack surface if the template has other misconfigurations (ESC1, ESC2, ESC3, etc.)."
        Impact = @(
            "Non-privileged users can request certificates from this template"
            "If combined with ENROLLEE_SUPPLIES_SUBJECT flag, enables ESC1"
            "If combined with Any Purpose EKU, enables ESC2"
            "Wider enrollment permissions increase exploitation potential"
        )
        Remediation = @(
            "Review if non-privileged enrollment is required"
            "Restrict enrollment to specific groups if possible"
            "Ensure template does not have dangerous flags enabled"
            "Monitor certificate enrollment activity"
        )
        RemediationCommands = @(
            @{
                Description = "Remove enrollment permission for broad groups (via Certificate Templates Console)"
                Command = "# Use certtmpl.msc - Security tab - Remove 'Enroll' permission for Everyone/Domain Users/Authenticated Users"
            }
            @{
                Description = "Add specific group with enrollment permission"
                Command = "# Use certtmpl.msc - Security tab - Add specific security group and grant 'Enroll' permission"
            }
            @{
                Description = "View template enrollment permissions"
                Command = "(Get-Acl 'AD:\CN=<TemplateName>,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com').Access | Where-Object { `$_.ActiveDirectoryRights -match 'Enroll' } | Format-Table IdentityReference, ActiveDirectoryRights"
            }
        )
        References = @(
            @{ Title = "Certified Pre-Owned - SpecterOps"; Url = "https://posts.specterops.io/certified-pre-owned-d95910965cd2" }
            @{ Title = "Certificate Enrollment Permissions - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts" }
        )
        MITRE = "T1649"
        Triggers = @(
            # SID-based classification: Broad groups (Everyone, Domain Users) enrolling = Finding
            @{ Attribute = 'EnrollmentPrincipals'; Custom = 'is_broad_group_sid'; Severity = 'Finding' }
            # Non-privileged enrollment = Hint (operator or unknown)
            @{ Attribute = 'EnrollmentPrincipals'; Severity = 'Hint'; SeverityOnly = $true }
        )
    }

    # ADCS Template - Client Authentication EKU (Yellow/Hint)
    'ADCS_CLIENT_AUTH_EKU' = @{
        Title = "Client Authentication EKU Enabled"
        Risk = "Hint"
        BaseScore = 15
        Description = "This certificate template includes the Client Authentication Extended Key Usage (EKU), which allows the certificate to be used for Kerberos PKINIT authentication. This is a prerequisite for many ADCS attacks."
        Impact = @(
            "Certificates can be used to authenticate as the enrolled user"
            "If combined with ENROLLEE_SUPPLIES_SUBJECT, enables impersonation (ESC1)"
            "Certificates valid for long periods (often 1-2 years)"
            "Authentication possible even after password change"
        )
        Remediation = @(
            "Only enable Client Authentication EKU where required"
            "Combine with Manager Approval for sensitive templates"
            "Ensure enrollment restrictions are in place"
            "Monitor certificate-based authentication events"
        )
        RemediationCommands = @(
            @{
                Description = "Remove Client Authentication EKU from template (if not required)"
                Command = "# Use certtmpl.msc - Extensions tab - Application Policies - Remove 'Client Authentication'"
            }
            @{
                Description = "Enable Manager Approval for templates with Client Authentication EKU"
                Command = "# Use certtmpl.msc - Issuance Requirements tab - check 'CA certificate manager approval'"
            }
        )
        References = @(
            @{ Title = "Certified Pre-Owned - SpecterOps"; Url = "https://posts.specterops.io/certified-pre-owned-d95910965cd2" }
            @{ Title = "PKINIT Authentication"; Url = "https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-architecture" }
        )
        MITRE = "T1649"
        Triggers = @(
            # ExtendedKeyUsage: Client Authentication OID = Hint
            @{ Attribute = 'ExtendedKeyUsage'; Pattern = '1\.3\.6\.1\.5\.5\.7\.3\.2|Client Authentication'; Severity = 'Hint' }
        )
    }

    # ADCS Template - Smartcard Logon EKU (Yellow/Hint)
    'ADCS_SMARTCARD_LOGON_EKU' = @{
        Title = "Smartcard Logon EKU Enabled"
        Risk = "Hint"
        BaseScore = 15
        Description = "This certificate template includes the Smartcard Logon Extended Key Usage (EKU), which allows the certificate to be used for interactive Windows logon via PKINIT. This is equivalent to Client Authentication for attack purposes."
        Impact = @(
            "Certificates can be used for Windows interactive logon"
            "Enables PKINIT-based authentication (Kerberos)"
            "If combined with ENROLLEE_SUPPLIES_SUBJECT, enables impersonation (ESC1)"
            "Smartcard certificates often have longer validity periods"
        )
        Remediation = @(
            "Only enable Smartcard Logon EKU where required"
            "Implement strong enrollment approval processes"
            "Monitor smartcard certificate requests"
            "Consider hardware-bound certificates for smartcards"
        )
        RemediationCommands = @(
            @{
                Description = "Remove Smartcard Logon EKU from template (if not required)"
                Command = "# Use certtmpl.msc - Extensions tab - Application Policies - Remove 'Smart Card Logon'"
            }
            @{
                Description = "Enable Manager Approval for templates with Smartcard Logon EKU"
                Command = "# Use certtmpl.msc - Issuance Requirements tab - check 'CA certificate manager approval'"
            }
        )
        References = @(
            @{ Title = "Certified Pre-Owned - SpecterOps"; Url = "https://posts.specterops.io/certified-pre-owned-d95910965cd2" }
            @{ Title = "Smart Card Architecture - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-architecture" }
        )
        MITRE = "T1649"
        Triggers = @(
            # ExtendedKeyUsage: Smartcard Logon OID = Hint
            @{ Attribute = 'ExtendedKeyUsage'; Pattern = '1\.3\.6\.1\.4\.1\.311\.20\.2\.2|Smartcard'; Severity = 'Hint' }
        )
    }

    # ============================================================================
    # ACL / PERMISSION FINDINGS
    # ============================================================================

    'DANGEROUS_ACL_GENERICALL' = @{
        Title = "GenericAll Permission on Sensitive Object"
        Risk = "Finding"
        BaseScore = 60
        Description = "A user or group has GenericAll (Full Control) permission on a sensitive Active Directory object. This grants complete control including the ability to modify any attribute, reset passwords, or change group membership."
        Impact = @(
            "Can reset passwords of target accounts without knowing current password"
            "Can add members to groups (including Domain Admins)"
            "Can modify any attribute including servicePrincipalName for Kerberoasting"
            "Can enable Resource-Based Constrained Delegation"
            "Complete control over the target object"
        )
        Attack = @(
            "On User: Reset password and take over account"
            "On Group: Add attacker to the group"
            "On Computer: Configure RBCD for lateral movement"
            "On GPO: Modify to deploy malware or credentials"
        )
        Remediation = @(
            "Review and remove unnecessary GenericAll permissions"
            "Follow principle of least privilege"
            "Use role-based access control (RBAC)"
            "Monitor ACL changes on sensitive objects"
        )
        RemediationCommands = @(
            @{
                Description = "Remove GenericAll ACE from object (replace values)"
                Command = "`$Acl = Get-Acl 'AD:\\CN=TARGET,DC=domain,DC=com'; `$Acl.RemoveAccessRule((`$Acl.Access | Where-Object { `$_.IdentityReference -eq 'DOMAIN\\USER' -and `$_.ActiveDirectoryRights -eq 'GenericAll' })); Set-Acl -AclObject `$Acl 'AD:\\CN=TARGET,DC=domain,DC=com'"
            }
            @{
                Description = "View current ACL of the object"
                Command = "(Get-Acl 'AD:\\CN=TARGET,DC=domain,DC=com').Access | Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType"
            }
        )
        References = @(
            @{ Title = "BloodHound Attack Paths"; Url = "https://bloodhound.specterops.io/resources/edges/overview" }
            @{ Title = "Active Directory ACL Attacks"; Url = "https://wald0.com/?p=112" }
            @{ Title = "AD DS Security Best Practices - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory" }
        )
        Tools = @("BloodHound", "PowerView", "ADACLScanner")
        MITRE = "T1222.001"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'GenericAll|FullControl'; Severity = 'Finding' }
            @{ Attribute = 'DangerousPermissions'; Pattern = 'GenericAll|FullControl'; Severity = 'Finding' }
        )
    }

    'DANGEROUS_ACL_GENERICWRITE' = @{
        Title = "GenericWrite Permission on Sensitive Object"
        Risk = "Finding"
        BaseScore = 55
        Description = "A user or group has GenericWrite permission on a sensitive Active Directory object. This allows writing to all non-protected attributes, which can be abused for various attack paths depending on the object type."
        Impact = @(
            "On User objects: Set servicePrincipalName for targeted Kerberoasting, modify scriptPath for logon script execution"
            "On Computer objects: Configure msDS-AllowedToActOnBehalfOfOtherIdentity for Resource-Based Constrained Delegation (RBCD)"
            "On Group objects: Modify member attribute to add accounts to the group"
            "On GPO objects: Modify Group Policy settings to execute code on all linked systems"
            "Can write msDS-KeyCredentialLink for Shadow Credentials attack"
        )
        Attack = @(
            "On User: Set SPN and Kerberoast the account, or set logon script for code execution"
            "On Computer: Configure RBCD to impersonate any user to the target"
            "On Group: Add attacker account to gain group privileges"
            "On GPO: Add scheduled tasks, startup scripts, or registry modifications affecting all linked OUs"
        )
        Remediation = @(
            "Review and remove unnecessary GenericWrite permissions"
            "Follow principle of least privilege - use specific write permissions instead"
            "Use role-based access control (RBAC)"
            "Monitor attribute changes on sensitive objects (Event ID 5136)"
        )
        RemediationCommands = @(
            @{
                Description = "View current ACL of the object"
                Command = "(Get-Acl 'AD:\\CN=TARGET,DC=domain,DC=com').Access | Format-Table IdentityReference,ActiveDirectoryRights,AccessControlType -AutoSize"
            }
            @{
                Description = "Remove GenericWrite ACE from Active Directory object"
                Command = "`$acl = Get-Acl 'AD:\\CN=TARGET,DC=domain,DC=com'; `$ace = `$acl.Access | Where-Object {`$_.IdentityReference -eq 'DOMAIN\\USER' -and `$_.ActiveDirectoryRights -match 'GenericWrite'}; `$ace | ForEach-Object {`$acl.RemoveAccessRule(`$_)}; Set-Acl -Path 'AD:\\CN=TARGET,DC=domain,DC=com' -AclObject `$acl"
            }
            @{
                Description = "Enable auditing for attribute changes on sensitive objects (Event ID 5136)"
                Command = "# In Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > DS Access > Audit Directory Service Changes = Success, Failure"
            }
        )
        References = @(
            @{ Title = "BloodHound GenericWrite"; Url = "https://bloodhound.specterops.io/resources/edges/generic-write" }
            @{ Title = "AD Delegation Best Practices - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/delegating-administration-by-using-ou-objects" }
            @{ Title = "Set-Acl cmdlet"; Url = "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl" }
        )
        Tools = @("BloodHound", "PowerView", "SharpGPOAbuse", "ADACLScanner")
        MITRE = "T1222.001"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'GenericWrite'; Severity = 'Finding' }
            @{ Attribute = 'DangerousPermissions'; Pattern = 'GenericWrite'; Severity = 'Finding' }
        )
    }

    'DANGEROUS_ACL_WRITEDACL' = @{
        Title = "WriteDACL Permission on Sensitive Object"
        Risk = "Finding"
        BaseScore = 55
        Description = "A user or group has WriteDACL permission on a sensitive object. This allows modification of the object's security descriptor, effectively granting the ability to give themselves any other permission."
        Impact = @(
            "Can grant themselves GenericAll or any other permission"
            "Effectively equals full control over the object"
            "Can be used to hide permission changes by modifying SACL"
        )
        Attack = @(
            "1. Attacker uses WriteDACL to grant themselves GenericAll"
            "2. Exploits GenericAll as described in that finding"
        )
        Remediation = @(
            "Remove WriteDACL from non-administrative principals"
            "Only domain/enterprise admins should have WriteDACL on sensitive objects"
            "Monitor DACL modifications"
        )
        RemediationCommands = @(
            @{
                Description = "View who has WriteDACL on the object"
                Command = "(Get-Acl 'AD:\\CN=TARGET,DC=domain,DC=com').Access | Where-Object { `$_.ActiveDirectoryRights -match 'WriteDacl' } | Format-Table IdentityReference,ActiveDirectoryRights,AccessControlType -AutoSize"
            }
            @{
                Description = "Remove WriteDACL ACE from Active Directory object"
                Command = "`$acl = Get-Acl 'AD:\\CN=TARGET,DC=domain,DC=com'; `$ace = `$acl.Access | Where-Object {`$_.IdentityReference -eq 'DOMAIN\\USER' -and `$_.ActiveDirectoryRights -match 'WriteDacl'}; `$ace | ForEach-Object {`$acl.RemoveAccessRule(`$_)}; Set-Acl -Path 'AD:\\CN=TARGET,DC=domain,DC=com' -AclObject `$acl"
            }
            @{
                Description = "Enable auditing for DACL modifications (Event ID 4670)"
                Command = "# In Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Object Access > Audit Authorization Policy Change = Success, Failure"
            }
        )
        References = @(
            @{ Title = "ACL Abuse Attacks"; Url = "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces" }
            @{ Title = "AD Access Control - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers" }
        )
        Tools = @("BloodHound", "PowerView", "ADACLScanner")
        MITRE = "T1222.001"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'WriteDacl'; Severity = 'Finding' }
            @{ Attribute = 'DangerousPermissions'; Pattern = 'WriteDacl'; Severity = 'Finding' }
        )
    }

    'DANGEROUS_ACL_WRITEOWNER' = @{
        Title = "WriteOwner Permission on Sensitive Object"
        Risk = "Finding"
        BaseScore = 55
        Description = "A user or group has WriteOwner permission on a sensitive object. This allows changing the object's owner, and as owner, granting themselves full control via WriteDACL implicit permission."
        Impact = @(
            "Can become owner of the object"
            "Owners have implicit WriteDACL permission"
            "Leads to full control through permission chaining"
        )
        Attack = @(
            "1. Attacker changes object owner to themselves"
            "2. As owner, modifies DACL to grant GenericAll"
            "3. Exploits GenericAll for full control"
        )
        Remediation = @(
            "Remove WriteOwner from non-administrative principals"
            "Ensure proper ownership is set on sensitive objects"
            "Monitor ownership changes"
        )
        RemediationCommands = @(
            @{
                Description = "View who has WriteOwner on the object"
                Command = "(Get-Acl 'AD:\\CN=TARGET,DC=domain,DC=com').Access | Where-Object { `$_.ActiveDirectoryRights -match 'WriteOwner' } | Format-Table IdentityReference,ActiveDirectoryRights,AccessControlType -AutoSize"
            }
            @{
                Description = "Remove WriteOwner ACE from Active Directory object"
                Command = "`$acl = Get-Acl 'AD:\\CN=TARGET,DC=domain,DC=com'; `$ace = `$acl.Access | Where-Object {`$_.IdentityReference -eq 'DOMAIN\\USER' -and `$_.ActiveDirectoryRights -match 'WriteOwner'}; `$ace | ForEach-Object {`$acl.RemoveAccessRule(`$_)}; Set-Acl -Path 'AD:\\CN=TARGET,DC=domain,DC=com' -AclObject `$acl"
            }
            @{
                Description = "Check current owner of the object"
                Command = "(Get-Acl 'AD:\\CN=TARGET,DC=domain,DC=com').Owner"
            }
            @{
                Description = "Enable auditing for ownership changes (Event ID 4780)"
                Command = "# In Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > DS Access > Audit Directory Service Changes = Success, Failure"
            }
        )
        References = @(
            @{ Title = "WriteOwner Attack Path"; Url = "https://bloodhound.specterops.io/resources/edges/write-owner" }
            @{ Title = "AD Object Ownership - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory" }
        )
        Tools = @("BloodHound", "PowerView")
        MITRE = "T1222.001"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'WriteOwner'; Severity = 'Finding' }
            @{ Attribute = 'DangerousPermissions'; Pattern = 'WriteOwner'; Severity = 'Finding' }
        )
    }

    'DANGEROUS_ACL_DCSYNC' = @{
        Title = "DCSync Rights (Replication Permissions)"
        Risk = "Finding"
        BaseScore = 100
        Description = "A non-standard principal has 'Replicating Directory Changes' and/or 'Replicating Directory Changes All' permissions on the domain. These permissions allow performing DCSync attacks to extract all domain credentials."
        Impact = @(
            "Can extract password hashes for ALL domain accounts"
            "Includes the krbtgt hash for Golden Ticket attacks"
            "Complete domain compromise without touching Domain Controllers"
            "Enables persistent access through credential theft"
        )
        Attack = @(
            "1. Attacker compromises account with replication rights"
            "2. Uses DCSync to request password hashes from DC"
            "3. Extracts NTLM hashes and Kerberos keys"
            "4. Uses krbtgt hash to create Golden Tickets"
        )
        Remediation = @(
            "Remove replication rights from non-DC accounts"
            "Only Domain Controllers should have these permissions"
            "Monitor for DCSync activity (Event ID 4662 with specific GUIDs)"
            "Use Advanced Threat Protection to detect DCSync"
        )
        RemediationCommands = @(
            @{
                Description = "View accounts with replication rights on domain"
                Command = "(Get-Acl 'AD:\\DC=domain,DC=com').Access | Where-Object { `$_.ObjectType -in @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') } | Format-Table IdentityReference, ObjectType"
            }
            @{
                Description = "Remove replication rights from user (replace values)"
                Command = "`$guid1 = [GUID]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'; `$guid2 = [GUID]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'; # Use ADSI to remove specific extended rights"
            }
        )
        References = @(
            @{ Title = "DCSync - MITRE ATT&CK"; Url = "https://attack.mitre.org/techniques/T1003/006/" }
            @{ Title = "DCSync - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/dcsync.html" }
            @{ Title = "Detecting DCSync"; Url = "https://adsecurity.org/?p=1729" }
            @{ Title = "Monitoring AD Replication - Microsoft"; Url = "https://learn.microsoft.com/en-us/defender-for-identity/alerts-overview" }
        )
        Tools = @("Mimikatz", "Impacket", "DSInternals")
        MITRE = "T1003.006"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'DS-Replication-Get-Changes|Replicating Directory Changes|DCSync'; Severity = 'Finding' }
            @{ Attribute = 'DangerousPermissions'; Pattern = 'DS-Replication-Get-Changes|Replicating Directory Changes|DCSync'; Severity = 'Finding' }
        )
    }

    # ============================================================================
    # OU PERMISSION FINDINGS (Dangerous Rights on OUs)
    # ============================================================================

    'OU_PERM_WRITEPROPERTY_ALL' = @{
        Title = "WriteProperty (All Properties) on OU"
        Risk = "Finding"
        BaseScore = 60
        Description = "A principal has WriteProperty permission on ALL attributes of objects in this OU. This grants the ability to modify any attribute on affected objects, including security-sensitive properties like userAccountControl, servicePrincipalName, and delegation settings."
        Impact = @(
            "Can modify userAccountControl to disable accounts or enable delegation"
            "Can add SPNs to user accounts for Kerberoasting attacks"
            "Can configure Resource-Based Constrained Delegation (RBCD)"
            "Can modify scriptPath for code execution on logon"
            "Complete attribute-level control over affected objects"
        )
        Attack = @(
            "1. Attacker identifies principal with WriteProperty (All Properties)"
            "2. Modifies userAccountControl to enable delegation or disable protections"
            "3. Adds SPN to enable Kerberoasting of privileged accounts"
            "4. Configures RBCD for lateral movement"
        )
        Remediation = @(
            "Replace broad WriteProperty with specific attribute-level permissions"
            "Use delegation wizards that grant minimal required permissions"
            "Review and remove unnecessary write permissions on OUs"
            "Monitor for attribute modifications on sensitive accounts"
        )
        RemediationCommands = @(
            @{
                Description = "View current ACL on an OU"
                Command = "(Get-Acl 'AD:\OU=Users,DC=domain,DC=com').Access | Where-Object {`$_.ActiveDirectoryRights -match 'WriteProperty'} | Format-Table IdentityReference,ActiveDirectoryRights,ObjectType,InheritedObjectType -AutoSize"
            }
            @{
                Description = "Remove specific WriteProperty ACE from OU"
                Command = "`$ou = 'AD:\OU=Users,DC=domain,DC=com'; `$acl = Get-Acl `$ou; `$ace = `$acl.Access | Where-Object {`$_.IdentityReference -eq 'DOMAIN\User' -and `$_.ActiveDirectoryRights -match 'WriteProperty'}; `$acl.RemoveAccessRule(`$ace); Set-Acl -AclObject `$acl -Path `$ou"
            }
            @{
                Description = "Grant specific attribute write permission instead of all properties (example: telephoneNumber)"
                Command = "dsacls 'OU=Users,DC=domain,DC=com' /G 'DOMAIN\User:WP;telephoneNumber'"
            }
            @{
                Description = "Find all OUs where a specific principal has WriteProperty permissions"
                Command = "Get-ADOrganizationalUnit -Filter * | ForEach-Object { `$acl = Get-Acl `$_.DistinguishedName; `$writePerms = `$acl.Access | Where-Object {`$_.IdentityReference -like '*USERNAME*' -and `$_.ActiveDirectoryRights -match 'WriteProperty'}; if (`$writePerms) { [PSCustomObject]@{OU=`$_.Name; DN=`$_.DistinguishedName; Rights=`$writePerms.ActiveDirectoryRights} } }"
            }
        )
        References = @(
            @{ Title = "AD Delegation Best Practices"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/delegating-administration-by-using-ou-objects-of-default-containers-and-ous" }
            @{ Title = "BloodHound WriteAllProperties Edge"; Url = "https://bloodhound.specterops.io/resources/edges/overview" }
        )
        Tools = @("BloodHound", "PowerView", "ADACLScanner")
        MITRE = "T1222.001"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'WriteProperty \(All Properties\)'; Severity = 'Finding' }
        )
    }

    'OU_PERM_PASSWORD_RESET' = @{
        Title = "Password Reset Rights on OU"
        Risk = "Finding"
        BaseScore = 55
        Description = "A principal has the 'Reset Password' (User-Force-Change-Password) extended right on this OU. This allows resetting passwords of user accounts without knowing the current password - a powerful privilege that can lead to account takeover."
        Impact = @(
            "Can reset passwords of all user accounts in the OU"
            "Enables immediate account takeover without cracking passwords"
            "If privileged users are in the OU, leads to privilege escalation"
            "No knowledge of current password required"
        )
        Attack = @(
            "1. Attacker identifies principal with password reset rights"
            "2. Resets password of target user (e.g., Domain Admin)"
            "3. Logs in as the target user with the new password"
            "4. Achieves privilege escalation"
        )
        Remediation = @(
            "Remove password reset rights from non-helpdesk principals"
            "Segregate privileged accounts into protected OUs"
            "Use tiered administration model"
            "Add privileged accounts to Protected Users group"
            "Monitor for password reset events (Event ID 4724)"
        )
        RemediationCommands = @(
            @{
                Description = "View who has password reset rights on OU"
                Command = "(Get-Acl 'AD:\\OU=Users,DC=domain,DC=com').Access | Where-Object { `$_.ObjectType -eq '00299570-246d-11d0-a768-00aa006e0529' } | Format-Table IdentityReference"
            }
        )
        References = @(
            @{ Title = "ForceChangePassword - BloodHound"; Url = "https://bloodhound.specterops.io/resources/edges/force-change-password" }
            @{ Title = "AD Tier Model"; Url = "https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material" }
        )
        Tools = @("BloodHound", "PowerView", "ADACLScanner")
        MITRE = "T1098"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'Reset Password|ForceChangePassword|User-Force-Change-Password'; Severity = 'Finding' }
        )
    }

    'OU_PERM_USERACCOUNTCONTROL' = @{
        Title = "WriteProperty (userAccountControl) on OU"
        Risk = "Finding"
        BaseScore = 55
        Description = "A principal can modify the userAccountControl attribute on objects in this OU. This attribute contains critical security flags including account enabled/disabled, delegation settings, pre-authentication requirements, and more."
        Impact = @(
            "Can disable accounts or enable previously disabled accounts"
            "Can enable TRUSTED_FOR_DELEGATION for unconstrained delegation attacks"
            "Can set DONT_REQUIRE_PREAUTH for AS-REP Roasting"
            "Can set TRUSTED_TO_AUTH_FOR_DELEGATION for constrained delegation"
            "Can clear PASSWORD_EXPIRED flag"
        )
        Attack = @(
            "1. Attacker modifies userAccountControl on target account"
            "2. Sets DONT_REQUIRE_PREAUTH flag"
            "3. Performs AS-REP Roasting to obtain crackable hash"
            "Or: Enables TRUSTED_FOR_DELEGATION for Kerberos attacks"
        )
        Remediation = @(
            "Remove WriteProperty on userAccountControl from non-admin principals"
            "Use specific delegation instead of broad attribute permissions"
            "Monitor for userAccountControl changes (Event ID 4738)"
            "Protect sensitive accounts in dedicated OUs with restricted ACLs"
        )
        RemediationCommands = @(
            @{
                Description = "View current ACL on OU to identify principals with WriteProperty on userAccountControl"
                Command = "(Get-Acl 'AD:\\OU=TARGET_OU,DC=domain,DC=com').Access | Where-Object {`$_.ActiveDirectoryRights -match 'WriteProperty' -and `$_.ObjectType -eq 'bf967a68-0de6-11d0-a285-00aa003049e2'} | Format-Table IdentityReference,ActiveDirectoryRights,ObjectType,AccessControlType -AutoSize"
            }
            @{
                Description = "Remove WriteProperty permission on userAccountControl attribute from specific principal"
                Command = "`$acl = Get-Acl 'AD:\\OU=TARGET_OU,DC=domain,DC=com'; `$ace = `$acl.Access | Where-Object {`$_.IdentityReference -eq 'DOMAIN\\USER' -and `$_.ActiveDirectoryRights -match 'WriteProperty' -and `$_.ObjectType -eq 'bf967a68-0de6-11d0-a285-00aa003049e2'}; `$ace | ForEach-Object {`$acl.RemoveAccessRule(`$_)}; Set-Acl -Path 'AD:\\OU=TARGET_OU,DC=domain,DC=com' -AclObject `$acl"
            }
            @{
                Description = "Enable auditing for userAccountControl modifications (Event ID 4738)"
                Command = "# Configure via Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy > Account Management > Audit User Account Management = Success, Failure"
            }
            @{
                Description = "Find all users in OU with DONT_REQUIRE_PREAUTH flag set (AS-REP Roastable)"
                Command = "Get-ADUser -Filter * -SearchBase 'OU=TARGET_OU,DC=domain,DC=com' -Properties userAccountControl | Where-Object {`$_.userAccountControl -band 0x400000} | Select-Object Name,SamAccountName,UserAccountControl"
            }
        )
        References = @(
            @{ Title = "userAccountControl Attribute"; Url = "https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties" }
            @{ Title = "BloodHound WriteAccountRestrictions"; Url = "https://bloodhound.specterops.io/resources/edges/overview" }
            @{ Title = "Set-Acl - Microsoft Learn"; Url = "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl" }
        )
        Tools = @("BloodHound", "PowerView", "Rubeus")
        MITRE = "T1098"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'WriteProperty \(userAccountControl\)'; Severity = 'Finding' }
        )
    }

    'OU_PERM_USER_ACCOUNT_RESTRICTIONS' = @{
        Title = "WriteProperty (User-Account-Restrictions) on OU"
        Risk = "Finding"
        BaseScore = 55
        Description = "A principal can write to the User-Account-Restrictions property set on objects in this OU. This property set includes userAccountControl, pwdLastSet, accountExpires, and other security-critical attributes, granting significant control over account security settings."
        Impact = @(
            "Includes all userAccountControl impacts (delegation, pre-auth, etc.)"
            "Can modify pwdLastSet to reset password age"
            "Can change accountExpires to lock out accounts"
            "Can modify logon hours restrictions"
            "Property set grants access to multiple security attributes at once"
        )
        Attack = @(
            "1. Attacker uses User-Account-Restrictions write access"
            "2. Modifies userAccountControl for delegation or AS-REP Roasting"
            "3. Or modifies accountExpires to deny legitimate access"
            "4. Changes are harder to detect than direct attribute writes"
        )
        Remediation = @(
            "Remove User-Account-Restrictions property set permissions from non-admin principals"
            "Grant specific attribute permissions instead of property sets"
            "Property sets were designed for convenience, not security"
            "Review all principals with property set permissions"
        )
        RemediationCommands = @(
            @{
                Description = "View current ACL on OU to identify principals with WriteProperty on User-Account-Restrictions property set"
                Command = "(Get-Acl 'AD:\\OU=TARGET_OU,DC=domain,DC=com').Access | Where-Object {`$_.ActiveDirectoryRights -match 'WriteProperty' -and `$_.ObjectType -eq '4c164200-20c0-11d0-a768-00aa006e0529'} | Format-Table IdentityReference,ActiveDirectoryRights,ObjectType,AccessControlType -AutoSize"
            }
            @{
                Description = "Remove WriteProperty permission on User-Account-Restrictions property set from specific principal"
                Command = "`$acl = Get-Acl 'AD:\\OU=TARGET_OU,DC=domain,DC=com'; `$ace = `$acl.Access | Where-Object {`$_.IdentityReference -eq 'DOMAIN\\USER' -and `$_.ActiveDirectoryRights -match 'WriteProperty' -and `$_.ObjectType -eq '4c164200-20c0-11d0-a768-00aa006e0529'}; `$ace | ForEach-Object {`$acl.RemoveAccessRule(`$_)}; Set-Acl -Path 'AD:\\OU=TARGET_OU,DC=domain,DC=com' -AclObject `$acl"
            }
            @{
                Description = "List all attributes included in User-Account-Restrictions property set"
                Command = "# User-Account-Restrictions property set (GUID 4c164200-20c0-11d0-a768-00aa006e0529) includes: userAccountControl, pwdLastSet, accountExpires, logonHours, userParameters, homeDirectory, homeDrive, scriptPath, profilePath, userWorkstations"
            }
            @{
                Description = "Enable auditing for User-Account-Restrictions modifications"
                Command = "# Configure via Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy > DS Access > Audit Directory Service Changes = Success, Failure"
            }
        )
        References = @(
            @{ Title = "AD Property Sets"; Url = "https://docs.microsoft.com/en-us/windows/win32/adschema/property-sets" }
            @{ Title = "Property Set GUID 4c164200-20c0-11d0-a768-00aa006e0529"; Url = "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb" }
            @{ Title = "Set-Acl - Microsoft Learn"; Url = "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl" }
        )
        Tools = @("BloodHound", "PowerView", "ADACLScanner")
        MITRE = "T1098"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'WriteProperty \(User-Account-Restrictions\)'; Severity = 'Finding' }
        )
    }

    'OU_PERM_GROUP_MEMBERSHIP' = @{
        Title = "WriteProperty (member) on OU"
        Risk = "Finding"
        BaseScore = 55
        Description = "A principal can modify the 'member' attribute on groups in this OU. This allows adding or removing group members, which can lead to privilege escalation if privileged groups are affected."
        Impact = @(
            "Can add attacker-controlled accounts to groups in the OU"
            "If Domain Admins or other privileged groups are in the OU, instant privilege escalation"
            "Can remove legitimate members to cause denial of service"
            "Group membership changes are often overlooked in monitoring"
        )
        Attack = @(
            "1. Attacker identifies privileged groups in target OU"
            "2. Adds their controlled account to the privileged group"
            "3. Gains all privileges associated with the group"
            "4. Optionally removes themselves later to cover tracks"
        )
        Remediation = @(
            "Segregate privileged groups into protected OUs"
            "Remove member write permissions from non-admin principals"
            "Use AdminSDHolder to protect privileged groups"
            "Monitor group membership changes (Event ID 4728, 4732, 4756)"
        )
        RemediationCommands = @(
            @{
                Description = "View current ACL on OU to identify principals with WriteProperty on member attribute"
                Command = "(Get-Acl 'AD:\\OU=TARGET_OU,DC=domain,DC=com').Access | Where-Object {`$_.ActiveDirectoryRights -match 'WriteProperty' -and `$_.ObjectType -eq 'bf9679c0-0de6-11d0-a285-00aa003049e2'} | Format-Table IdentityReference,ActiveDirectoryRights,ObjectType,AccessControlType -AutoSize"
            }
            @{
                Description = "Remove WriteProperty permission on member attribute from specific principal"
                Command = "`$acl = Get-Acl 'AD:\\OU=TARGET_OU,DC=domain,DC=com'; `$ace = `$acl.Access | Where-Object {`$_.IdentityReference -eq 'DOMAIN\\USER' -and `$_.ActiveDirectoryRights -match 'WriteProperty' -and `$_.ObjectType -eq 'bf9679c0-0de6-11d0-a285-00aa003049e2'}; `$ace | ForEach-Object {`$acl.RemoveAccessRule(`$_)}; Set-Acl -Path 'AD:\\OU=TARGET_OU,DC=domain,DC=com' -AclObject `$acl"
            }
            @{
                Description = "Identify privileged groups in the OU that are vulnerable"
                Command = "Get-ADGroup -Filter * -SearchBase 'OU=TARGET_OU,DC=domain,DC=com' -Properties AdminCount,Member | Where-Object {`$_.AdminCount -eq 1 -or `$_.Name -match 'Admin|Operator'} | Select-Object Name,DistinguishedName,@{Name='MemberCount';Expression={(`$_.Member | Measure-Object).Count}}"
            }
            @{
                Description = "Enable auditing for group membership changes (Event IDs 4728, 4732, 4756)"
                Command = "# Configure via Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy > Account Management > Audit Security Group Management = Success, Failure"
            }
        )
        References = @(
            @{ Title = "AddMember - BloodHound"; Url = "https://bloodhound.specterops.io/resources/edges/add-member" }
            @{ Title = "AdminSDHolder Protection"; Url = "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory" }
            @{ Title = "Set-Acl - Microsoft Learn"; Url = "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl" }
        )
        Tools = @("BloodHound", "PowerView")
        MITRE = "T1098.002"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'WriteProperty \(member\)'; Severity = 'Finding' }
        )
    }

    'OU_PERM_SPN_WRITE' = @{
        Title = "WriteProperty (servicePrincipalName) on OU"
        Risk = "Finding"
        BaseScore = 50
        Description = "A principal can modify the servicePrincipalName attribute on user accounts in this OU. This enables targeted Kerberoasting attacks by adding SPNs to accounts that don't normally have them, making their password hashes extractable."
        Impact = @(
            "Can add SPNs to ANY user account in the OU"
            "Enables Kerberoasting of accounts without existing SPNs"
            "If privileged accounts are in the OU, their hashes become crackable"
            "SPN changes are rarely monitored"
        )
        Attack = @(
            "1. Attacker adds SPN to target privileged user account"
            "2. Requests TGS ticket for the new SPN (Kerberoasting)"
            "3. Extracts ticket encrypted with user's password hash"
            "4. Cracks password offline"
            "5. Optionally removes SPN to cover tracks"
        )
        Remediation = @(
            "Remove SPN write permissions from non-admin principals"
            "Use gMSA for service accounts instead of user accounts"
            "Monitor for SPN changes on user accounts (Event ID 4742)"
            "Protect privileged accounts in separate OUs"
        )
        RemediationCommands = @(
            @{
                Description = "View current ACL on OU to identify principals with WriteProperty on servicePrincipalName"
                Command = "(Get-Acl 'AD:\\OU=TARGET_OU,DC=domain,DC=com').Access | Where-Object {`$_.ActiveDirectoryRights -match 'WriteProperty' -and `$_.ObjectType -eq 'f3a64788-5306-11d1-a9c5-0000f80367c1'} | Format-Table IdentityReference,ActiveDirectoryRights,ObjectType,AccessControlType -AutoSize"
            }
            @{
                Description = "Remove WriteProperty permission on servicePrincipalName from specific principal"
                Command = "`$acl = Get-Acl 'AD:\\OU=TARGET_OU,DC=domain,DC=com'; `$ace = `$acl.Access | Where-Object {`$_.IdentityReference -eq 'DOMAIN\\USER' -and `$_.ActiveDirectoryRights -match 'WriteProperty' -and `$_.ObjectType -eq 'f3a64788-5306-11d1-a9c5-0000f80367c1'}; `$ace | ForEach-Object {`$acl.RemoveAccessRule(`$_)}; Set-Acl -Path 'AD:\\OU=TARGET_OU,DC=domain,DC=com' -AclObject `$acl"
            }
            @{
                Description = "Find all user accounts with SPNs in the OU (potential Kerberoasting targets)"
                Command = "Get-ADUser -Filter {ServicePrincipalName -like '*'} -SearchBase 'OU=TARGET_OU,DC=domain,DC=com' -Properties ServicePrincipalName,AdminCount | Select-Object Name,SamAccountName,@{Name='SPNs';Expression={`$_.ServicePrincipalName -join '; '}},AdminCount"
            }
            @{
                Description = "Enable auditing for SPN changes on user accounts (Event ID 4742)"
                Command = "# Configure via Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy > Account Management > Audit User Account Management = Success, Failure"
            }
        )
        References = @(
            @{ Title = "Targeted Kerberoasting"; Url = "https://blog.harmj0y.net/activedirectory/targeted-kerberoasting/" }
            @{ Title = "WriteSPN - BloodHound"; Url = "https://bloodhound.specterops.io/resources/edges/write-spn" }
            @{ Title = "SPN Attribute - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows/win32/adschema/a-serviceprincipalname" }
            @{ Title = "Set-Acl - Microsoft Learn"; Url = "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl" }
        )
        Tools = @("Rubeus", "Impacket", "PowerView", "Hashcat")
        MITRE = "T1558.003"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'WriteProperty \(servicePrincipalName\)'; Severity = 'Finding' }
        )
    }

    'OU_PERM_VALIDATED_SPN' = @{
        Title = "Validated-SPN Rights on OU"
        Risk = "Hint"
        BaseScore = 35
        Description = "A principal has Validated-SPN rights (Self or WriteProperty) on objects in this OU. This validated write allows modifying servicePrincipalName with certain restrictions. While more limited than direct WriteProperty, it can still enable targeted Kerberoasting in some scenarios."
        Impact = @(
            "Can add SPNs with validation constraints"
            "Validated writes are commonly delegated for legitimate purposes"
            "Computer accounts often have Self rights for SPN management"
            "Less dangerous than direct WriteProperty but still noteworthy"
        )
        Attack = @(
            "1. If target is a user account, same Kerberoasting attack applies"
            "2. Validation may prevent some attack scenarios"
            "3. Still allows adding SPNs within validation rules"
        )
        Remediation = @(
            "Review if Validated-SPN delegation is necessary"
            "For computer objects, this is often legitimate (computer self-management)"
            "For user objects in privileged OUs, consider removing"
            "Monitor SPN changes regardless of method used"
        )
        RemediationCommands = @(
            @{
                Description = "Find who has Validated-SPN rights on OU"
                Command = "(Get-Acl 'AD:\\OU=Users,DC=domain,DC=com').Access | Where-Object { `$_.ObjectType -eq 'f3a64788-5306-11d1-a9c5-0000f80367c1' }"
            }
            @{
                Description = "Remove Validated-SPN ACE from OU (replace PRINCIPAL_SID with actual SID)"
                Command = @'
`$ou = 'OU=Users,DC=domain,DC=com'
`$acl = Get-Acl "AD:\\`$ou"
`$ace = `$acl.Access | Where-Object { `$_.IdentityReference -match 'PRINCIPAL_SID' -and `$_.ObjectType -eq 'f3a64788-5306-11d1-a9c5-0000f80367c1' }
`$acl.RemoveAccessRule(`$ace)
Set-Acl -Path "AD:\\`$ou" -AclObject `$acl
'@
            }
            @{
                Description = "Enable auditing for SPN changes"
                Command = "auditpol /set /subcategory:'Directory Service Changes' /success:enable"
            }
        )
        References = @(
            @{ Title = "Validated Writes in AD"; Url = "https://docs.microsoft.com/en-us/windows/win32/adschema/validated-writes" }
            @{ Title = "Validated-SPN GUID f3a64788-5306-11d1-a9c5-0000f80367c1"; Url = "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb" }
        )
        Tools = @("BloodHound", "PowerView")
        MITRE = "T1558.003"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'Validated-SPN|Self \(Validated-SPN\)|WriteProperty \(Validated-SPN\)'; Severity = 'Hint' }
        )
    }

    'OU_PERM_DNSHOSTNAME_WRITE' = @{
        Title = "WriteProperty (dNSHostName) on OU"
        Risk = "Finding"
        BaseScore = 50
        Description = "A principal can modify the dNSHostName attribute on computer accounts in this OU. This can enable Kerberos relay attacks where an attacker impersonates the computer's identity to other services."
        Impact = @(
            "Can change computer's DNS hostname identity"
            "Enables Kerberos relay attacks against other services"
            "Can impersonate the computer to obtain service tickets"
            "Affects authentication flows that rely on dNSHostName"
        )
        Attack = @(
            "1. Attacker modifies dNSHostName of a computer account"
            "2. Sets it to match a target server (e.g., DC)"
            "3. Performs Kerberos relay to authenticate as the computer"
            "4. Obtains tickets for services trusting the DNS name"
        )
        Remediation = @(
            "Remove dNSHostName write permissions from non-admin principals"
            "Only machine accounts should modify their own dNSHostName"
            "Monitor for dNSHostName changes on computer accounts"
            "Use validated writes (Validated-DNS-Host-Name) instead of direct WriteProperty"
        )
        RemediationCommands = @(
            @{
                Description = "View current ACL for dNSHostName attribute on OU"
                Command = "(Get-Acl 'AD:\\OU=Computers,DC=domain,DC=com').Access | Where-Object {`$_.ObjectType -eq 'bf967953-0de6-11d0-a285-00aa003049e2'} | Format-Table IdentityReference,ActiveDirectoryRights,AccessControlType -AutoSize"
            }
            @{
                Description = "Remove WriteProperty permission for dNSHostName from specific principal"
                Command = "`$acl = Get-Acl 'AD:\\OU=Computers,DC=domain,DC=com'; `$ace = `$acl.Access | Where-Object {`$_.IdentityReference -eq 'DOMAIN\\User' -and `$_.ActiveDirectoryRights -match 'WriteProperty' -and `$_.ObjectType -eq 'bf967953-0de6-11d0-a285-00aa003049e2'}; `$ace | ForEach-Object {`$acl.RemoveAccessRule(`$_)}; Set-Acl -Path 'AD:\\OU=Computers,DC=domain,DC=com' -AclObject `$acl"
            }
            @{
                Description = "Monitor dNSHostName changes via Event ID 5136 (Directory Service Changes)"
                Command = "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5136; StartTime=(Get-Date).AddDays(-7)} | Where-Object {`$_.Message -match 'dNSHostName'} | Select-Object TimeCreated,@{Name='Computer';Expression={`$_.Properties[10].Value}},@{Name='Attribute';Expression={`$_.Properties[8].Value}},@{Name='NewValue';Expression={`$_.Properties[11].Value}} | Format-Table -AutoSize"
            }
            @{
                Description = "Grant SELF permission to allow computers to update their own dNSHostName"
                Command = "`$ouPath = 'AD:\\OU=Computers,DC=domain,DC=com'; `$acl = Get-Acl `$ouPath; `$sid = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-10'; `$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(`$sid, 'WriteProperty', 'Allow', 'bf967953-0de6-11d0-a285-00aa003049e2', 'Descendents', '00000000-0000-0000-0000-000000000000'); `$acl.AddAccessRule(`$ace); Set-Acl -Path `$ouPath -AclObject `$acl"
            }
        )
        References = @(
            @{ Title = "Machine Account Quota Attacks"; Url = "https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd" }
            @{ Title = "CVE-2022-26923 - Microsoft"; Url = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923" }
            @{ Title = "Understanding Get-ACL and AD Drive Output"; Url = "https://devblogs.microsoft.com/powershell-community/understanding-get-acl-and-ad-drive-output/" }
            @{ Title = "Using PowerShell to assign permissions on AD objects"; Url = "https://social.technet.microsoft.com/Forums/Lync/en-US/df3bfd33-c070-4a9c-be98-c4da6e591a0a/forum-faq-using-powershell-to-assign-permissions-on-active-directory-objects" }
        )
        Tools = @("Impacket", "krbrelayx", "Rubeus")
        MITRE = "T1557.001"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'WriteProperty \(dNSHostName\)'; Severity = 'Finding' }
        )
    }

    'OU_PERM_DNS_HOST_NAME_ATTRIBUTES' = @{
        Title = "WriteProperty (DNS-Host-Name-Attributes) on OU"
        Risk = "Finding"
        BaseScore = 50
        Description = "A principal can write to the DNS-Host-Name-Attributes property set on computer accounts in this OU. This property set includes dNSHostName and msDS-AdditionalDnsHostName, enabling DNS-based identity attacks."
        Impact = @(
            "Includes all dNSHostName write impacts"
            "Also allows modifying additional DNS host names"
            "Property set grants access to multiple DNS-related attributes"
            "Can enable computer impersonation attacks"
        )
        Attack = @(
            "1. Attacker uses DNS-Host-Name-Attributes write access"
            "2. Modifies dNSHostName or adds additional DNS names"
            "3. Performs Kerberos relay attacks using modified identity"
            "4. May evade detection that only monitors dNSHostName directly"
        )
        Remediation = @(
            "Remove DNS-Host-Name-Attributes property set permissions"
            "Grant Validated-DNS-Host-Name instead for legitimate delegation"
            "Only computer accounts should manage their own DNS names"
            "Monitor for DNS attribute changes on computer accounts"
        )
        RemediationCommands = @(
            @{
                Description = "View current ACL for DNS-Host-Name-Attributes property set on OU"
                Command = "(Get-Acl 'AD:\\OU=Computers,DC=domain,DC=com').Access | Where-Object {`$_.ObjectType -eq '72e39547-7b18-11d1-adef-00c04fd8d5cd'} | Format-Table IdentityReference,ActiveDirectoryRights,AccessControlType -AutoSize"
            }
            @{
                Description = "Remove WriteProperty permission for DNS-Host-Name-Attributes property set from specific principal"
                Command = "`$acl = Get-Acl 'AD:\\OU=Computers,DC=domain,DC=com'; `$ace = `$acl.Access | Where-Object {`$_.IdentityReference -eq 'DOMAIN\\User' -and `$_.ActiveDirectoryRights -match 'WriteProperty' -and `$_.ObjectType -eq '72e39547-7b18-11d1-adef-00c04fd8d5cd'}; `$ace | ForEach-Object {`$acl.RemoveAccessRule(`$_)}; Set-Acl -Path 'AD:\\OU=Computers,DC=domain,DC=com' -AclObject `$acl"
            }
            @{
                Description = "Grant Validated-DNS-Host-Name extended right instead (GUID: f0f8ffab-1191-11d0-a060-00aa006c33ed)"
                Command = "`$ouPath = 'AD:\\OU=Computers,DC=domain,DC=com'; `$acl = Get-Acl `$ouPath; `$sid = (Get-ADGroup 'DOMAIN\\GroupName').SID; `$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(`$sid, 'ExtendedRight', 'Allow', 'f0f8ffab-1191-11d0-a060-00aa006c33ed', 'Descendents', 'bf967a86-0de6-11d0-a285-00aa003049e2'); `$acl.AddAccessRule(`$ace); Set-Acl -Path `$ouPath -AclObject `$acl"
            }
            @{
                Description = "Find all computers with non-default dNSHostName values (potential indicators of modification)"
                Command = "Get-ADComputer -Filter * -Properties dNSHostName | Where-Object { `$_.dNSHostName -ne (`$_.Name + '.' + (Get-ADDomain).DNSRoot) } | Select-Object Name,dNSHostName,DistinguishedName"
            }
        )
        References = @(
            @{ Title = "AD Property Sets"; Url = "https://docs.microsoft.com/en-us/windows/win32/adschema/property-sets" }
            @{ Title = "CVE-2022-26923 - Microsoft"; Url = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923" }
        )
        Tools = @("Impacket", "krbrelayx", "PowerView")
        MITRE = "T1557.001"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'WriteProperty \(DNS-Host-Name-Attributes\)'; Severity = 'Finding' }
        )
    }

    'OU_PERM_VALIDATED_DNS' = @{
        Title = "Validated-DNS-Host-Name Rights on OU"
        Risk = "Hint"
        BaseScore = 30
        Description = "A principal has Validated-DNS-Host-Name rights on objects in this OU. This validated write allows modifying dNSHostName with certain validation constraints. Typically granted to computer accounts for self-management."
        Impact = @(
            "Can modify dNSHostName with validation rules"
            "Validated writes have more restrictions than direct WriteProperty"
            "Computer Self rights for this are normal and expected"
            "Non-computer principals with this right should be reviewed"
        )
        Attack = @(
            "Attack surface is limited by validation rules"
            "Computer accounts using Self rights is legitimate"
            "Non-SELF rights may still enable some relay scenarios"
        )
        Remediation = @(
            "Computer accounts having Self rights for this is expected"
            "Review if non-computer principals need this permission"
            "Consider removing from user accounts"
            "Monitor for unusual DNS name changes"
        )
        References = @(
            @{ Title = "Validated Writes in AD"; Url = "https://docs.microsoft.com/en-us/windows/win32/adschema/validated-writes" }
        )
        Tools = @("PowerView", "ADACLScanner")
        MITRE = "T1557.001"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'Validated-DNS-Host-Name|Self \(Validated-DNS-Host-Name\)|WriteProperty \(Validated-DNS-Host-Name\)'; Severity = 'Hint' }
        )
    }

    'OU_PERM_SCRIPTPATH' = @{
        Title = "WriteProperty (scriptPath) on OU"
        Risk = "Finding"
        BaseScore = 50
        Description = "A principal can modify the scriptPath attribute on user accounts in this OU. This attribute specifies a logon script that executes when the user logs in, enabling code execution in the user's context."
        Impact = @(
            "Can specify arbitrary logon script for any user in the OU"
            "Script executes with user's privileges on next logon"
            "If privileged user, code runs with elevated privileges"
            "Enables persistence and lateral movement"
        )
        Attack = @(
            "1. Attacker creates malicious script on accessible share"
            "2. Modifies scriptPath of target user to point to malicious script"
            "3. User logs in and script executes"
            "4. Attacker gains code execution as the user"
        )
        Remediation = @(
            "Remove scriptPath write permissions from non-admin principals"
            "Use Group Policy for logon scripts instead of per-user settings"
            "Monitor for scriptPath changes on user accounts"
            "Protect privileged accounts in separate OUs"
        )
        RemediationCommands = @(
            @{
                Description = "View current ACL on OU to identify principals with WriteProperty on scriptPath"
                Command = "(Get-Acl 'AD:\\OU=TARGET_OU,DC=domain,DC=com').Access | Where-Object {`$_.ActiveDirectoryRights -match 'WriteProperty' -and `$_.ObjectType -eq 'bf9679f1-0de6-11d0-a285-00aa003049e2'} | Format-Table IdentityReference,ActiveDirectoryRights,ObjectType,AccessControlType -AutoSize"
            }
            @{
                Description = "Remove WriteProperty permission on scriptPath from specific principal"
                Command = "`$acl = Get-Acl 'AD:\\OU=TARGET_OU,DC=domain,DC=com'; `$ace = `$acl.Access | Where-Object {`$_.IdentityReference -eq 'DOMAIN\\USER' -and `$_.ActiveDirectoryRights -match 'WriteProperty' -and `$_.ObjectType -eq 'bf9679f1-0de6-11d0-a285-00aa003049e2'}; `$ace | ForEach-Object {`$acl.RemoveAccessRule(`$_)}; Set-Acl -Path 'AD:\\OU=TARGET_OU,DC=domain,DC=com' -AclObject `$acl"
            }
            @{
                Description = "Find all users in OU with scriptPath configured"
                Command = "Get-ADUser -Filter {scriptPath -like '*'} -SearchBase 'OU=TARGET_OU,DC=domain,DC=com' -Properties scriptPath,AdminCount | Select-Object Name,SamAccountName,scriptPath,AdminCount"
            }
            @{
                Description = "Clear scriptPath attribute from all users in OU (prepare for GPO-based scripts)"
                Command = "Get-ADUser -Filter {scriptPath -like '*'} -SearchBase 'OU=TARGET_OU,DC=domain,DC=com' | Set-ADUser -Clear scriptPath"
            }
        )
        References = @(
            @{ Title = "Logon Scripts Persistence"; Url = "https://attack.mitre.org/techniques/T1037/001/" }
            @{ Title = "Logon Script Attribute - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows/win32/adschema/a-scriptpath" }
            @{ Title = "Set-Acl - Microsoft Learn"; Url = "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl" }
        )
        Tools = @("PowerView", "BloodHound")
        MITRE = "T1037.001"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'WriteProperty \(scriptPath\)'; Severity = 'Finding' }
        )
    }

    'OU_PERM_CONSTRAINED_DELEGATION' = @{
        Title = "WriteProperty (msDS-AllowedToDelegateTo) on OU"
        Risk = "Finding"
        BaseScore = 55
        Description = "A principal can modify the msDS-AllowedToDelegateTo attribute on accounts in this OU. This attribute configures Constrained Delegation, allowing the account to impersonate users to specific services."
        Impact = @(
            "Can configure Constrained Delegation on any account in the OU"
            "Allows impersonation of users to specified services"
            "If targeting sensitive services (LDAP, CIFS on DC), enables privilege escalation"
            "Constrained Delegation is a powerful impersonation mechanism"
        )
        Attack = @(
            "1. Attacker modifies msDS-AllowedToDelegateTo on a controlled account"
            "2. Configures delegation to sensitive service (e.g., ldap/dc.domain.com)"
            "3. Uses S4U2Self and S4U2Proxy to obtain service ticket as admin"
            "4. Authenticates to the service as the impersonated admin"
        )
        Remediation = @(
            "Remove delegation attribute write permissions from non-admin principals"
            "Review all accounts with Constrained Delegation configured"
            "Consider using Resource-Based Constrained Delegation (RBCD) with proper controls"
            "Monitor for msDS-AllowedToDelegateTo changes"
        )
        RemediationCommands = @(
            @{
                Description = "Find who can write msDS-AllowedToDelegateTo on OU"
                Command = "(Get-Acl 'AD:\\OU=Servers,DC=domain,DC=com').Access | Where-Object { `$_.ObjectType -eq '800d94d7-b7a1-42a1-b14d-7cae1423d07f' -and `$_.ActiveDirectoryRights -match 'WriteProperty' }"
            }
            @{
                Description = "Remove dangerous ACE from OU (replace PRINCIPAL_SID with actual SID)"
                Command = @'
`$ou = 'OU=Servers,DC=domain,DC=com'
`$acl = Get-Acl "AD:\\`$ou"
`$ace = `$acl.Access | Where-Object { `$_.IdentityReference -match 'PRINCIPAL_SID' -and `$_.ObjectType -eq '800d94d7-b7a1-42a1-b14d-7cae1423d07f' }
`$acl.RemoveAccessRule(`$ace)
Set-Acl -Path "AD:\\`$ou" -AclObject `$acl
'@
            }
            @{
                Description = "Enable auditing for Directory Service Changes"
                Command = "auditpol /set /subcategory:'Directory Service Changes' /success:enable"
            }
        )
        References = @(
            @{ Title = "Constrained Delegation Attacks"; Url = "https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained" }
            @{ Title = "S4U2Self and S4U2Proxy"; Url = "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94" }
        )
        Tools = @("Rubeus", "Impacket", "PowerView")
        MITRE = "T1558"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'WriteProperty \(msDS-AllowedToDelegateTo\)'; Severity = 'Finding' }
        )
    }

    'OU_PERM_RBCD' = @{
        Title = "WriteProperty (msDS-AllowedToActOnBehalfOfOtherIdentity) on OU"
        Risk = "Finding"
        BaseScore = 60
        Description = "A principal can modify the msDS-AllowedToActOnBehalfOfOtherIdentity attribute on accounts in this OU. This configures Resource-Based Constrained Delegation (RBCD), allowing specified accounts to impersonate ANY user to the target."
        Impact = @(
            "Can configure RBCD on any account in the OU"
            "RBCD allows impersonation of ANY domain user (except Protected Users)"
            "More powerful than regular Constrained Delegation"
            "If targeting computer accounts, enables full computer compromise"
        )
        Attack = @(
            "1. Attacker creates or controls a computer account"
            "2. Modifies target's msDS-AllowedToActOnBehalfOfOtherIdentity"
            "3. Adds their controlled account to the RBCD configuration"
            "4. Uses S4U2Self/S4U2Proxy to obtain ticket as admin to target"
            "5. Achieves full compromise of target resource"
        )
        Remediation = @(
            "Remove RBCD attribute write permissions from non-admin principals"
            "This is one of the most commonly abused ACL misconfigurations"
            "Lower ms-DS-MachineAccountQuota to prevent machine account creation"
            "Monitor for msDS-AllowedToActOnBehalfOfOtherIdentity changes"
        )
        RemediationCommands = @(
            @{
                Description = "View current ACL on OU to identify principals with WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity"
                Command = "(Get-Acl 'AD:\\OU=TARGET_OU,DC=domain,DC=com').Access | Where-Object {`$_.ActiveDirectoryRights -match 'WriteProperty' -and `$_.ObjectType -eq '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'} | Format-Table IdentityReference,ActiveDirectoryRights,ObjectType,AccessControlType -AutoSize"
            }
            @{
                Description = "Remove WriteProperty permission on msDS-AllowedToActOnBehalfOfOtherIdentity from specific principal"
                Command = "`$acl = Get-Acl 'AD:\\OU=TARGET_OU,DC=domain,DC=com'; `$ace = `$acl.Access | Where-Object {`$_.IdentityReference -eq 'DOMAIN\\USER' -and `$_.ActiveDirectoryRights -match 'WriteProperty' -and `$_.ObjectType -eq '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'}; `$ace | ForEach-Object {`$acl.RemoveAccessRule(`$_)}; Set-Acl -Path 'AD:\\OU=TARGET_OU,DC=domain,DC=com' -AclObject `$acl"
            }
            @{
                Description = "Find all computers with RBCD configured in the OU"
                Command = "Get-ADComputer -Filter * -SearchBase 'OU=TARGET_OU,DC=domain,DC=com' -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | Where-Object {`$_.'msDS-AllowedToActOnBehalfOfOtherIdentity'} | Select-Object Name,@{Name='AllowedPrincipals';Expression={([System.Security.Principal.SecurityIdentifier]`$_.'msDS-AllowedToActOnBehalfOfOtherIdentity').Value}}"
            }
            @{
                Description = "Lower ms-DS-MachineAccountQuota to prevent unauthorized machine account creation"
                Command = "Set-ADDomain -Identity 'domain.com' -Replace @{'ms-DS-MachineAccountQuota'=0}"
            }
        )
        References = @(
            @{ Title = "RBCD Attack"; Url = "https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd" }
            @{ Title = "Resource-Based Constrained Delegation Abuse"; Url = "https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html" }
            @{ Title = "Kerberos RBCD - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview" }
            @{ Title = "Set-Acl - Microsoft Learn"; Url = "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl" }
        )
        Tools = @("Rubeus", "Impacket", "PowerMad")
        MITRE = "T1558"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'WriteProperty \(msDS-AllowedToActOnBehalfOfOtherIdentity\)'; Severity = 'Finding' }
        )
    }

    'OU_PERM_LAPS_READ' = @{
        Title = "LAPS Password Read Rights on OU"
        Risk = "Hint"
        BaseScore = 40
        Description = "A principal can read LAPS password attributes on computer accounts in this OU. LAPS (Local Administrator Password Solution) stores unique local admin passwords. Access to these passwords enables local administrator access to computers."
        Impact = @(
            "Can retrieve local administrator passwords for computers in the OU"
            "Enables local admin access to all affected computers"
            "Can be used for lateral movement"
            "May expose service accounts or backup admin passwords"
        )
        Attack = @(
            "1. Attacker reads LAPS password from computer account"
            "2. Uses retrieved password to authenticate locally on the computer"
            "3. Has local administrator access"
            "4. Can pivot to other systems or extract credentials"
        )
        Remediation = @(
            "Review LAPS read permissions - should be limited to designated admins"
            "Use tiered administration - only Tier 0/1 admins should read DC passwords"
            "Audit LAPS password access (Windows LAPS supports auditing)"
            "Consider shorter password rotation intervals"
        )
        References = @(
            @{ Title = "Windows LAPS"; Url = "https://docs.microsoft.com/en-us/windows-server/identity/laps/laps-overview" }
            @{ Title = "LAPS Best Practices"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory" }
        )
        Tools = @("LAPSToolkit", "PowerView", "ldapsearch")
        MITRE = "T1552.006"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'ReadProperty.*LAPS|ms-Mcs-AdmPwd|msLAPS-'; Severity = 'Hint' }
        )
    }

    'OU_PERM_CREATE_CHILD' = @{
        Title = "CreateChild Rights on OU"
        Risk = "Finding"
        BaseScore = 50
        Description = "A principal can create new child objects in this OU. This is particularly dangerous for computer object creation, as created computer accounts can be used for Resource-Based Constrained Delegation attacks."
        Impact = @(
            "Can create new objects (users, computers, groups) in the OU"
            "Computer object creation enables RBCD attacks"
            "Created objects may inherit dangerous permissions"
            "Can be used to establish persistence"
        )
        Attack = @(
            "1. Attacker creates a computer account in the OU"
            "2. Uses the computer account for RBCD attack against target"
            "3. Or creates user account for persistence"
        )
        Remediation = @(
            "Remove CreateChild rights from non-admin principals"
            "If delegation is needed, limit to specific object types"
            "Lower ms-DS-MachineAccountQuota domain-wide"
            "Monitor for new object creation in sensitive OUs"
        )
        RemediationCommands = @(
            @{
                Description = "View current ACL on OU to identify principals with CreateChild rights"
                Command = "(Get-Acl 'AD:\\OU=TARGET_OU,DC=domain,DC=com').Access | Where-Object {`$_.ActiveDirectoryRights -match 'CreateChild'} | Format-Table IdentityReference,ActiveDirectoryRights,AccessControlType -AutoSize"
            }
            @{
                Description = "Remove CreateChild permission from specific principal"
                Command = "`$acl = Get-Acl 'AD:\\OU=TARGET_OU,DC=domain,DC=com'; `$ace = `$acl.Access | Where-Object {`$_.IdentityReference -eq 'DOMAIN\\USER' -and `$_.ActiveDirectoryRights -match 'CreateChild'}; `$ace | ForEach-Object {`$acl.RemoveAccessRule(`$_)}; Set-Acl -Path 'AD:\\OU=TARGET_OU,DC=domain,DC=com' -AclObject `$acl"
            }
            @{
                Description = "Check current ms-DS-MachineAccountQuota (default is 10)"
                Command = "Get-ADDomain | Select-Object -ExpandProperty DistinguishedName | ForEach-Object { Get-ADObject `$_ -Properties 'ms-DS-MachineAccountQuota' | Select-Object 'ms-DS-MachineAccountQuota' }"
            }
            @{
                Description = "Lower ms-DS-MachineAccountQuota to 0 (prevent unauthorized computer account creation)"
                Command = "Set-ADDomain -Identity 'domain.com' -Replace @{'ms-DS-MachineAccountQuota'=0}"
            }
        )
        References = @(
            @{ Title = "Machine Account Quota Abuse"; Url = "https://www.thehacker.recipes/ad/movement/builtins/machineaccountquota" }
            @{ Title = "MachineAccountQuota Attribute - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota" }
            @{ Title = "Set-Acl - Microsoft Learn"; Url = "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl" }
        )
        Tools = @("PowerMad", "Impacket", "PowerView")
        MITRE = "T1136.002"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'CreateChild'; Severity = 'Finding' }
        )
    }

    'OU_PERM_GPLINK' = @{
        Title = "WriteProperty (gPLink) on OU"
        Risk = "Finding"
        BaseScore = 55
        Description = "A principal can modify the gPLink attribute on this OU. This attribute controls which Group Policy Objects are linked to the OU, enabling the attacker to apply arbitrary policies to all objects in the OU."
        Impact = @(
            "Can link any GPO to the OU"
            "GPO settings apply to all users and computers in the OU"
            "Can deploy malicious scripts, scheduled tasks, or software"
            "Can modify security settings to weaken defenses"
        )
        Attack = @(
            "1. Attacker creates or modifies a GPO with malicious content"
            "2. Links the GPO to target OU by modifying gPLink"
            "3. Policy applies on next Group Policy refresh"
            "4. Malicious scripts execute or settings are applied"
        )
        Remediation = @(
            "Remove gPLink write permissions from non-admin principals"
            "GPO management should be restricted to Group Policy administrators"
            "Monitor for gPLink changes on OUs"
            "Review linked GPOs regularly for unauthorized modifications"
        )
        RemediationCommands = @(
            @{
                Description = "View current ACL on OU to identify principals with WriteProperty on gPLink"
                Command = "(Get-Acl 'AD:\\OU=TARGET_OU,DC=domain,DC=com').Access | Where-Object {`$_.ActiveDirectoryRights -match 'WriteProperty' -and `$_.ObjectType -eq 'f30e3bbe-9ff0-11d1-b603-0000f80367c1'} | Format-Table IdentityReference,ActiveDirectoryRights,ObjectType,AccessControlType -AutoSize"
            }
            @{
                Description = "Remove WriteProperty permission on gPLink from specific principal"
                Command = "`$acl = Get-Acl 'AD:\\OU=TARGET_OU,DC=domain,DC=com'; `$ace = `$acl.Access | Where-Object {`$_.IdentityReference -eq 'DOMAIN\\USER' -and `$_.ActiveDirectoryRights -match 'WriteProperty' -and `$_.ObjectType -eq 'f30e3bbe-9ff0-11d1-b603-0000f80367c1'}; `$ace | ForEach-Object {`$acl.RemoveAccessRule(`$_)}; Set-Acl -Path 'AD:\\OU=TARGET_OU,DC=domain,DC=com' -AclObject `$acl"
            }
            @{
                Description = "View GPOs currently linked to OU"
                Command = "Get-ADOrganizationalUnit -Identity 'OU=TARGET_OU,DC=domain,DC=com' -Properties gPLink | Select-Object Name,DistinguishedName,gPLink"
            }
            @{
                Description = "Enable auditing for GPO link changes (Event ID 5136)"
                Command = "# Configure via Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy > DS Access > Audit Directory Service Changes = Success, Failure"
            }
        )
        References = @(
            @{ Title = "GPO Abuse"; Url = "https://www.thehacker.recipes/ad/movement/group-policies" }
            @{ Title = "WriteGPLink - BloodHound"; Url = "https://bloodhound.specterops.io/resources/edges/overview" }
            @{ Title = "Group Policy Overview - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview" }
            @{ Title = "Set-Acl - Microsoft Learn"; Url = "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl" }
        )
        Tools = @("SharpGPOAbuse", "PowerView", "BloodHound")
        MITRE = "T1484.001"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'WriteProperty \(gPLink\)'; Severity = 'Finding' }
        )
    }

    'OU_PERM_GENERICWRITE' = @{
        Title = "GenericWrite on OU"
        Risk = "Finding"
        BaseScore = 55
        Description = "A principal has GenericWrite permission on this OU. GenericWrite includes WriteProperty, WriteSelf, and WritePropertyExtended rights, allowing modification of many attributes including security-sensitive ones."
        Impact = @(
            "Can write to most attributes on affected objects"
            "Includes ability to modify SPN, scriptPath, and delegation settings"
            "Less than GenericAll but still very powerful"
            "Enables targeted Kerberoasting and other attacks"
        )
        Attack = @(
            "Same attacks as WriteProperty (All Properties)"
            "Add SPN for Kerberoasting"
            "Modify scriptPath for code execution"
            "Configure delegation attributes"
        )
        Remediation = @(
            "Replace GenericWrite with specific attribute permissions"
            "GenericWrite is overly broad for most delegation needs"
            "Review all principals with GenericWrite"
            "Use delegation wizards for specific tasks"
        )
        RemediationCommands = @(
            @{
                Description = "View current ACL on OU to identify principals with GenericWrite"
                Command = "(Get-Acl 'AD:\\OU=TARGET_OU,DC=domain,DC=com').Access | Where-Object {`$_.ActiveDirectoryRights -match 'GenericWrite'} | Format-Table IdentityReference,ActiveDirectoryRights,AccessControlType -AutoSize"
            }
            @{
                Description = "Remove GenericWrite permission from specific principal"
                Command = "`$acl = Get-Acl 'AD:\\OU=TARGET_OU,DC=domain,DC=com'; `$ace = `$acl.Access | Where-Object {`$_.IdentityReference -eq 'DOMAIN\\USER' -and `$_.ActiveDirectoryRights -match 'GenericWrite'}; `$ace | ForEach-Object {`$acl.RemoveAccessRule(`$_)}; Set-Acl -Path 'AD:\\OU=TARGET_OU,DC=domain,DC=com' -AclObject `$acl"
            }
            @{
                Description = "Delegate specific task using Delegation of Control Wizard (safer than GenericWrite)"
                Command = "# Use Active Directory Users and Computers > OU > Right-click > Delegate Control > Choose specific task (e.g., Reset user passwords) instead of granting GenericWrite"
            }
            @{
                Description = "List common delegation tasks that can replace GenericWrite"
                Command = "# Common delegation tasks: Reset user passwords, Modify group membership, Manage user accounts, Join computer to domain - Use Delegation of Control Wizard for granular permissions"
            }
        )
        References = @(
            @{ Title = "BloodHound GenericWrite"; Url = "https://bloodhound.specterops.io/resources/edges/generic-write" }
            @{ Title = "AD Delegation Best Practices - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/delegating-administration-by-using-ou-objects" }
            @{ Title = "Set-Acl - Microsoft Learn"; Url = "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl" }
        )
        Tools = @("BloodHound", "PowerView", "ADACLScanner")
        MITRE = "T1222.001"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'GenericWrite'; Severity = 'Finding' }
        )
    }

    'OU_PERM_READALL' = @{
        Title = "ReadProperty (All Properties) on OU"
        Risk = "Hint"
        BaseScore = 20
        Description = "A principal has ReadProperty (All Properties) permission on an OU. While read-only, this grants access to all attributes of objects in the OU, including sensitive ones like LAPS passwords, confidential attributes, and security descriptors."
        Impact = @(
            "Can read LAPS passwords if stored on computer objects in this OU"
            "Can enumerate all user attributes including confidential ones"
            "Can read security descriptors to map further attack paths"
        )
        Remediation = @(
            "Review if broad read access is necessary for this principal"
            "Consider using more granular read permissions per attribute"
            "Ensure LAPS password read is restricted via separate ACLs"
        )
        References = @(
            @{ Title = "AD Confidential Attributes"; Url = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/mark-attribute-as-confidential" }
        )
        Tools = @("BloodHound", "PowerView", "ADACLScanner")
        MITRE = "T1087.002"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'ReadProperty \(All Properties\)'; Severity = 'Hint' }
        )
    }

    # ============================================================================
    # ACCOUNT SECURITY FINDINGS
    # ============================================================================

    'PASSWORD_NEVER_EXPIRES' = @{
        Title = "Password Never Expires"
        Risk = "Hint"
        BaseScore = 25
        Description = "This account has the 'Password never expires' flag set. While sometimes required for service accounts, this increases the risk of credential compromise over time as passwords are not rotated."
        Impact = @(
            "Passwords are not rotated, increasing compromise window"
            "If password is leaked or cracked, it remains valid indefinitely"
            "Service accounts with old passwords are high-value targets"
            "Violates security best practices and compliance requirements"
        )
        Attack = @(
            "1. Attacker obtains password through phishing, leak, or cracking"
            "2. Password remains valid indefinitely"
            "3. Attacker maintains persistent access"
        )
        Remediation = @(
            "Enable password expiration for user accounts"
            "For service accounts, use Group Managed Service Accounts (gMSA)"
            "Implement regular password rotation policies"
            "Monitor for accounts with this flag set"
        )
        RemediationCommands = @(
            @{
                Description = "Enable password expiration for a single user account"
                Command = "Set-ADUser -Identity 'USERNAME' -PasswordNeverExpires `$false"
            }
            @{
                Description = "Enable password expiration for all users in a specific OU"
                Command = "Get-ADUser -Filter {PasswordNeverExpires -eq `$true} -SearchBase 'OU=Users,DC=domain,DC=com' | Set-ADUser -PasswordNeverExpires `$false"
            }
            @{
                Description = "View all users with PasswordNeverExpires flag set"
                Command = "Get-ADUser -Filter {PasswordNeverExpires -eq `$true} -Properties PasswordNeverExpires,PasswordLastSet | Select-Object Name,SamAccountName,PasswordNeverExpires,PasswordLastSet"
            }
        )
        References = @(
            @{ Title = "Set-ADUser PasswordNeverExpires - Microsoft Q&A"; Url = "https://learn.microsoft.com/en-us/answers/questions/316870/powershell-active-directory-password-never-expires" }
            @{ Title = "Password Policy Best Practices"; Url = "https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-password-ban-bad-on-premises" }
        )
        Tools = @("PowerView", "AD Administrative Center")
        MITRE = "T1078"
        Triggers = @(
            @{ Attribute = 'userAccountControl'; Pattern = 'DONT_EXPIRE_PASSWORD|PASSWORD_NEVER_EXPIRES'; Severity = 'Hint' }
        )
    }

    'PASSWORD_NOT_REQUIRED' = @{
        Title = "Password Not Required Flag Set"
        Risk = "Finding"
        BaseScore = 35
        Description = "This account has the PASSWD_NOTREQD flag set, meaning the account can have an empty password. This is a severe security misconfiguration that allows authentication without a password."
        Impact = @(
            "Account may have no password set"
            "Enables authentication with blank password"
            "Often indicates legacy or misconfigured accounts"
            "Easy target for attackers"
        )
        Attack = @(
            "1. Attacker identifies accounts with PASSWD_NOTREQD"
            "2. Attempts authentication with empty password"
            "3. If successful, gains access to the account"
        )
        Remediation = @(
            "Remove the PASSWD_NOTREQD flag from all accounts"
            "Set strong passwords on these accounts"
            "Investigate why the flag was set and remediate root cause"
            "Consider disabling accounts that don't need to be active"
        )
        RemediationCommands = @(
            @{
                Description = "Remove PasswordNotRequired flag from a single user account"
                Command = "Set-ADUser -Identity 'USERNAME' -PasswordNotRequired `$false"
            }
            @{
                Description = "Remove flag from all users in a specific OU (using LDAP filter for userAccountControl bit 32)"
                Command = "Get-ADUser -LDAPFilter '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))' -SearchBase 'OU=Users,DC=domain,DC=com' | Set-ADUser -PasswordNotRequired `$false"
            }
            @{
                Description = "Find all enabled accounts with PasswordNotRequired flag set"
                Command = "Get-ADUser -Filter {PasswordNotRequired -eq `$true -and Enabled -eq `$true} -Properties PasswordNotRequired,PasswordLastSet | Select-Object Name,SamAccountName,PasswordNotRequired,PasswordLastSet,Enabled"
            }
            @{
                Description = "Set a strong password after removing the flag"
                Command = "`$NewPwd = ConvertTo-SecureString -String 'NewStrongPassword123!' -AsPlainText -Force; Set-ADAccountPassword -Identity 'USERNAME' -NewPassword `$NewPwd -Reset"
            }
        )
        References = @(
            @{ Title = "Removing PasswordNotRequired - Microsoft Q&A"; Url = "https://learn.microsoft.com/en-us/answers/questions/988004/removing-passwordnotrequired-settings-or-poilcy-fr" }
            @{ Title = "Understanding PASSWD_NOTREQD - Microsoft Learn"; Url = "https://learn.microsoft.com/en-us/archive/blogs/russellt/passwd_notreqd" }
            @{ Title = "AD Account Properties"; Url = "https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties" }
        )
        Tools = @("PowerView", "LDAP queries")
        MITRE = "T1078"
        Triggers = @(
            @{ Attribute = 'userAccountControl'; Pattern = 'PASSWD_NOTREQD'; Severity = 'Finding' }
        )
    }

    'INTERDOMAIN_TRUST_ACCOUNT' = @{
        Title = "Inter-Domain Trust Account"
        Risk = "Hint"
        BaseScore = 20
        Description = "This is a trust account (INTERDOMAIN_TRUST_ACCOUNT) representing a trust relationship between two Active Directory domains. Trust accounts store a shared secret used to authenticate cross-domain Kerberos requests. The account name typically matches the trusted domain name with a trailing dollar sign."
        Impact = @(
            "Trust accounts hold the shared secret for the entire trust relationship"
            "Compromising the trust key allows forging inter-realm TGTs"
            "An attacker with the trust key can create cross-domain Golden Tickets"
            "Combined with PASSWD_NOTREQD: the trust password could potentially be empty"
            "Trust keys are equivalent to krbtgt keys for cross-domain access"
        )
        Attack = @(
            "1. Extract the trust key from the trust account (DCSync or NTDS.dit)"
            "2. Forge an inter-realm TGT with SIDHistory of Enterprise Admins"
            "3. Present the forged ticket to the trusted domain's KDC"
            "4. Gain administrative access across the trust boundary"
        )
        Remediation = @(
            "Ensure trust accounts do NOT have the PASSWD_NOTREQD flag"
            "Rotate trust passwords regularly (netdom trust /resetOnTrustee)"
            "Monitor trust account modifications with Event ID 4738"
            "Consider Selective Authentication to limit trust scope"
            "Use SID Filtering to prevent SIDHistory-based escalation across trusts"
        )
        References = @(
            @{ Title = "Trust Account Attack - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/inter-forest-and-cross-domain-attacks.html" }
            @{ Title = "Kerberos Trust Tickets - MITRE ATT&CK"; Url = "https://attack.mitre.org/techniques/T1558/003/" }
            @{ Title = "Domain Trust Discovery - Microsoft"; Url = "https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-unsecure-domain-trust" }
        )
        Tools = @("Mimikatz", "Impacket", "Rubeus", "netdom")
        MITRE = "T1134.005"
        Triggers = @(
            @{ Attribute = 'userAccountControl'; Pattern = 'INTERDOMAIN_TRUST_ACCOUNT'; Severity = 'Hint' }
        )
    }

    'ADMIN_COUNT_SET' = @{
        Title = "AdminCount Attribute Set (Protected Object)"
        Risk = "Note"
        BaseScore = 15
        Description = "This account has AdminCount=1, indicating it is or was a member of a protected administrative group. The Security Descriptor Propagator (SDProp) process manages ACLs on these accounts, which can have security implications."
        Impact = @(
            "Account is protected by SDProp ACL management"
            "Custom ACLs are reset every 60 minutes"
            "May indicate orphaned admin (AdminCount=1 but no longer admin)"
            "Password cannot be reset by Help Desk through normal delegation"
        )
        Attack = @(
            "Orphaned admin accounts retain AdminCount but lose protection oversight"
            "May have residual permissions without active monitoring"
        )
        Remediation = @(
            "Review accounts with AdminCount=1 that are not in admin groups"
            "Use dsmod or PowerShell to clear AdminCount on orphaned accounts"
            "Run SDProp manually to update ACLs after admin group changes"
        )
        RemediationCommands = @(
            @{
                Description = "Find all users with AdminCount=1"
                Command = "Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount,MemberOf | Select-Object SamAccountName,AdminCount,@{Name='Groups';Expression={`$_.MemberOf -join '; '}}"
            }
            @{
                Description = "Clear AdminCount attribute on orphaned admin accounts"
                Command = "Set-ADUser -Identity 'USERNAME' -Clear AdminCount"
            }
            @{
                Description = "Find orphaned admin accounts (AdminCount=1 but not in protected groups)"
                Command = "`$protectedGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Server Operators','Print Operators','Backup Operators'); Get-ADUser -Filter {AdminCount -eq 1} -Properties MemberOf | Where-Object { -not (`$_.MemberOf | Where-Object { `$protectedGroups -contains (`$_ -replace '^CN=([^,]+).*','`$1') }) } | Select-Object SamAccountName,DistinguishedName"
            }
            @{
                Description = "Manually trigger SDProp to update protected object ACLs (runs on PDC Emulator)"
                Command = "Invoke-Command -ComputerName PDC_EMULATOR -ScriptBlock { `$rootDSE = [ADSI]'LDAP://RootDSE'; `$rootDSE.Put('FixUpInheritance','1'); `$rootDSE.SetInfo() }"
            }
        )
        References = @(
            @{ Title = "AdminSDHolder and SDProp"; Url = "https://adsecurity.org/?p=1906" }
            @{ Title = "Protected Accounts and Groups - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory" }
        )
        Tools = @("PowerView", "ADACLScanner")
        MITRE = "T1078.002"
    }

    'PRIVILEGED_GROUP_MEMBERSHIP' = @{
        Title = "Privileged Group Membership (Tier 0)"
        Risk = "Finding"
        BaseScore = 15
        Description = "This account is a member of one or more highly privileged Active Directory groups. According to Microsoft's Enterprise Access Model (Tier Model), these are Tier 0 assets - the most sensitive resources that control the identity infrastructure. Compromise of Tier 0 accounts enables full domain/forest takeover."
        Impact = @(
            "Tier 0 - Domain Admins: Full control over all domain objects and Domain Controllers"
            "Tier 0 - Enterprise Admins: Full control over all domains in the forest"
            "Tier 0 - Schema Admins: Can modify the AD schema (forest-wide impact)"
            "Tier 0 - Administrators: Local admin on all Domain Controllers"
            "Tier 0 - Account/Server/Backup Operators: Can escalate to Domain Admin through various techniques"
            "Tier violation: If a Tier 0 account is used on Tier 1/2 systems, credentials can be stolen"
        )
        Attack = @(
            "1. Attacker compromises the Tier 0 account (phishing, credential theft, Tier violation)"
            "2. Uses privileges to access Domain Controllers"
            "3. Extracts all credentials via DCSync, LSASS dump, or NTDS.dit"
            "4. Creates Golden Tickets for persistent forest-wide access"
        )
        Remediation = @(
            "Implement Microsoft's Enterprise Access Model (Tier Model)"
            "Tier 0 accounts: Only use on Tier 0 systems (DCs, PAWs)"
            "Minimize the number of Tier 0 accounts"
            "Use dedicated admin accounts (not used for daily activities)"
            "Add Tier 0 accounts to 'Protected Users' group"
            "Implement Privileged Access Workstations (PAWs) for Tier 0 administration"
            "Enable multi-factor authentication for Tier 0 accounts"
            "Monitor for Tier violations (Tier 0 credentials on non-Tier 0 systems)"
        )
        References = @(
            @{ Title = "Microsoft Enterprise Access Model"; Url = "https://docs.microsoft.com/en-us/security/compass/privileged-access-access-model" }
            @{ Title = "Securing Privileged Access"; Url = "https://docs.microsoft.com/en-us/security/compass/privileged-access-accounts" }
            @{ Title = "Active Directory Tier Model"; Url = "https://adsecurity.org/?p=3299" }
            @{ Title = "Get-ADGroupMember"; Url = "https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adgroupmember" }
            @{ Title = "Remove-ADGroupMember"; Url = "https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adgroupmember" }
            @{ Title = "Securing Domain Admins Groups"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-f--securing-domain-admins-groups-in-active-directory" }
        )
        RemediationCommands = @(
            @{
                Description = "List all members of Domain Admins group (including nested)"
                Command = "Get-ADGroupMember -Identity 'Domain Admins' -Recursive | Select-Object Name,SamAccountName,ObjectClass,DistinguishedName | Format-Table -AutoSize"
            }
            @{
                Description = "List all members of Enterprise Admins group (including nested)"
                Command = "Get-ADGroupMember -Identity 'Enterprise Admins' -Recursive | Select-Object Name,SamAccountName,ObjectClass,DistinguishedName | Format-Table -AutoSize"
            }
            @{
                Description = "List all members of Schema Admins group (including nested)"
                Command = "Get-ADGroupMember -Identity 'Schema Admins' -Recursive | Select-Object Name,SamAccountName,ObjectClass,DistinguishedName | Format-Table -AutoSize"
            }
            @{
                Description = "Remove specific user from Domain Admins group"
                Command = "Remove-ADGroupMember -Identity 'Domain Admins' -Members 'USERNAME' -Confirm:`$false"
            }
            @{
                Description = "Audit all privileged group memberships (Tier 0 groups)"
                Command = "`$privilegedGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Server Operators','Backup Operators','Print Operators'); `$privilegedGroups | ForEach-Object { Write-Host `"Group: `$_`" -ForegroundColor Cyan; Get-ADGroupMember -Identity `$_ -Recursive -ErrorAction SilentlyContinue | Select-Object Name,SamAccountName | Format-Table -AutoSize }"
            }
            @{
                Description = "Add Tier 0 account to Protected Users group (enforces strict security policies)"
                Command = "Add-ADGroupMember -Identity 'Protected Users' -Members 'TIER0_ACCOUNT'"
            }
        )
        Tools = @("BloodHound", "PowerView", "PingCastle")
        MITRE = "T1078.002"
        Triggers = @(
            # SID-based classification: Privileged group SID = Finding
            # Order matters: is_privileged_sid MUST come before is_dnsadmins_sid
            @{ Attribute = 'privilegedGroups'; Custom = 'is_privileged_sid'; Severity = 'Finding' }
            @{ Attribute = 'privilegedGroups'; Custom = 'is_dnsadmins_sid'; Severity = 'Finding' }
            @{ Attribute = 'Member'; Custom = 'is_privileged_sid'; Severity = 'Finding' }
            @{ Attribute = 'MemberOf'; Custom = 'is_privileged_sid'; Severity = 'Finding' }
            @{ Attribute = 'MemberOf'; Custom = 'is_dnsadmins_sid'; Severity = 'Finding' }
        )
    }

    # Operator/Broad Group Membership (Yellow/Hint)
    'OPERATOR_GROUP_MEMBERSHIP' = @{
        Title = "Operator or Broad Group Membership"
        Risk = "Hint"
        BaseScore = 10
        Description = "This account is a member of an operator-level or broad-access group such as Account Operators, Backup Operators, Print Operators, Cert Publishers, or similar groups with elevated but not full domain control privileges. These groups have specific permissions that can be abused for privilege escalation."
        Impact = @(
            "Account Operators: Can create accounts and modify non-admin accounts"
            "Backup Operators: Can back up and restore files on DCs, including NTDS.dit"
            "Print Operators: Can load drivers on DCs (potential kernel-mode code execution)"
            "Cert Publishers: Can modify certificate templates and CA configuration"
            "Server Operators: Can log on to DCs and manage services"
        )
        Remediation = @(
            "Review if membership in this group is necessary"
            "Follow least-privilege principle for group assignments"
            "Monitor membership changes in these groups"
            "Consider using delegated permissions instead of broad group membership"
        )
        References = @(
            @{ Title = "AD Built-In Groups"; Url = "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory" }
            @{ Title = "Abusing Backup Operators"; Url = "https://www.bordergate.co.uk/backup-operator-privilege-escalation/" }
        )
        MITRE = "T1078.002"
        Triggers = @(
            # SID-based classification: Operator group SID = Hint
            @{ Attribute = 'privilegedGroups'; Custom = 'is_operator_sid'; Severity = 'Hint' }
            @{ Attribute = 'Member'; Custom = 'is_operator_sid'; Severity = 'Hint' }
            @{ Attribute = 'MemberOf'; Custom = 'is_operator_sid'; Severity = 'Hint' }
        )
    }

    'EXCHANGE_GROUP_PERMISSIONS' = @{
        Title = "Exchange Service Group Permissions (By-Design)"
        Risk = "Note"
        BaseScore = 45
        Description = "This is an Exchange service group with extensive Active Directory permissions. These permissions are required for Exchange Server to function properly and cannot be removed without breaking Exchange functionality. The group resides in the 'OU=Microsoft Exchange Security Groups' organizational unit."
        Impact = @(
            "Exchange groups have broad permissions including password reset rights on certain OUs"
            "These permissions are by-design and necessary for Exchange operations"
            "Compromise of these groups would grant significant AD access"
            "However, these groups are managed by Exchange and not directly user-controlled"
        )
        Attack = @(
            "Attackers may target Exchange servers to gain access to these privileged groups"
            "Exchange vulnerabilities (e.g., ProxyLogon, ProxyShell) could provide access"
            "Once Exchange is compromised, attackers can leverage these permissions"
        )
        Remediation = @(
            "NOTE: These permissions CANNOT and SHOULD NOT be removed"
            "Keep Exchange servers fully patched and updated"
            "Monitor Exchange service group membership for unexpected changes"
            "Implement network segmentation for Exchange servers"
            "Use dedicated admin accounts for Exchange administration"
            "Consider implementing Extended Protection for Authentication (EPA)"
        )
        References = @(
            @{ Title = "Exchange Permissions Deep Dive"; Url = "https://docs.microsoft.com/en-us/exchange/permissions" }
            @{ Title = "ProxyLogon Vulnerability"; Url = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855" }
        )
        Tools = @("BloodHound", "PingCastle")
        MITRE = "T1078.002"
    }

    'EXCHANGE_GROUP_LOW_PRIV_MEMBER' = @{
        Title = "Low-Privileged Account in Exchange Service Group"
        Risk = "Finding"
        BaseScore = 20
        Description = "A low-privileged (non-administrator) account is a member of an Exchange service group. Exchange service groups have extensive Active Directory permissions and should only contain Exchange service accounts, computer accounts, and administrative accounts. Regular users should NEVER be members of these groups."
        Impact = @(
            "Low-privileged user gains Exchange-level permissions in Active Directory"
            "Can potentially reset passwords for users in affected OUs"
            "May be able to modify Exchange-related attributes"
            "Significant privilege escalation pathway"
        )
        Attack = @(
            "1. Attacker compromises the low-privileged account"
            "2. Account is already member of Exchange service group (misconfiguration)"
            "3. Attacker leverages Exchange group permissions for privilege escalation"
            "4. Can potentially reset admin passwords or modify sensitive attributes"
        )
        Remediation = @(
            "IMMEDIATELY remove the low-privileged account from the Exchange service group"
            "Audit all Exchange service group memberships"
            "Investigate how the account was added (intentional or compromise)"
            "Review group membership change logs in Security Event Log"
            "Implement alerting for changes to Exchange security groups"
        )
        RemediationCommands = @(
            @{
                Description = "Remove a specific user from an Exchange service group"
                Command = "Remove-ADGroupMember -Identity 'Exchange Trusted Subsystem' -Members 'CN=User Name,OU=Users,DC=contoso,DC=com' -Confirm:`$false"
            }
            @{
                Description = "List all members of Exchange service groups to audit membership"
                Command = "Get-ADGroup -Filter ""Name -like 'Exchange*'"" | ForEach-Object { Write-Host `"Group: `$(`$_.Name)`" -ForegroundColor Yellow; Get-ADGroupMember -Identity `$_ | Select-Object Name, ObjectClass, SamAccountName }"
            }
            @{
                Description = "Find all Exchange security groups in the domain"
                Command = "Get-ADGroup -Filter ""(Name -like 'Exchange*') -and (GroupCategory -eq 'Security')"" -Properties Description | Select-Object Name, GroupScope, Description"
            }
            @{
                Description = "Check recent group membership changes in Security Event Log (Event ID 4728, 4732, 4756)"
                Command = "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4728,4732,4756; StartTime=(Get-Date).AddDays(-7)} | Where-Object { `$_.Message -match 'Exchange' } | Select-Object TimeCreated, Message | Format-List"
            }
        )
        References = @(
            @{ Title = "Exchange Security Groups"; Url = "https://docs.microsoft.com/en-us/exchange/permissions/permissions?view=exchserver-2019" }
            @{ Title = "AD Group Membership Auditing"; Url = "https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-security-group-management" }
            @{ Title = "Remove-ADGroupMember"; Url = "https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adgroupmember" }
            @{ Title = "Get-ADGroup Filter Examples"; Url = "https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adgroup" }
        )
        Tools = @("BloodHound", "PowerView")
        MITRE = "T1078.002"
    }

    # ============================================================================
    # LDAP / DOMAIN CONFIGURATION FINDINGS
    # ============================================================================

    'LDAP_SIGNING_NOT_REQUIRED' = @{
        Title = "LDAP Signing Not Required"
        Risk = "Finding"
        BaseScore = 25
        Description = "The GPO does not configure LDAP signing requirements. Note: 'Not Configured' in GPO does not necessarily mean the setting is insecure - it may be configured locally on the Domain Controller or enforced by OS defaults (Windows Server 2025+ requires signing by default). However, best practice is to enforce security settings via GPO for consistent configuration across all systems."
        Impact = @(
            "LDAP traffic can be intercepted and modified"
            "NTLM relay attacks can target LDAP services"
            "Credentials can be captured or modified in transit"
            "Enables attacks like NTLM relay to LDAP for adding users to groups"
        )
        Attack = @(
            "1. Attacker positions for man-in-the-middle"
            "2. Coerces authentication from target (PetitPotam, PrinterBug)"
            "3. Relays NTLM authentication to DC LDAP"
            "4. Performs privileged LDAP operations (RBCD, group membership)"
        )
        Remediation = @(
            "Enable 'Domain controller: LDAP server signing requirements' = Require signing"
            "Configure via GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options"
            "Best practice: Always configure security settings via GPO rather than local policy"
            "Test applications for LDAP signing compatibility before enforcing"
        )
        RemediationCommands = @(
            @{
                Description = "Enable LDAP signing requirement via registry on Domain Controller (Value 2 = Require Signing)"
                Command = "New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters' -Name LdapServerIntegrity -Value 2 -PropertyType DWORD -Force"
            }
            @{
                Description = "Verify current LDAP signing configuration on Domain Controller"
                Command = "Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters' -Name LdapServerIntegrity | Select-Object LdapServerIntegrity"
            }
            @{
                Description = "Configure LDAP signing via Group Policy (preferred method for consistent configuration)"
                Command = "# In Group Policy Management: Default Domain Controller Policy > Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > 'Domain controller: LDAP server signing requirements' = Require signing"
            }
            @{
                Description = "Test LDAP signing enforcement before deployment (check for unsigned binds)"
                Command = "# Use Event Viewer on DC: Security log Event ID 2889 indicates unsigned LDAP binds. Filter by Task Category 'LDAP Interface' to identify clients requiring updates"
            }
        )
        References = @(
            @{ Title = "How to enable LDAP signing - Windows Server"; Url = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server" }
            @{ Title = "Domain controller: LDAP server signing requirements"; Url = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/domain-controller-ldap-server-signing-requirements" }
            @{ Title = "Manage LDAP signing using Group Policy for Active Directory"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/manage-ldap-signing-group-policy" }
            @{ Title = "LDAP Relay Attacks"; Url = "https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/" }
        )
        Tools = @("ntlmrelayx", "Impacket", "Responder")
        MITRE = "T1557"
        Triggers = @(
            @{ Attribute = 'LDAPSigning'; Pattern = '^(None|Not Configured|Disabled|Not Required|Unknown)$'; Severity = 'Finding' }
            @{ Attribute = 'LDAPSigning'; Pattern = '^Optional$'; Severity = 'Hint' }
        )
    }

    'LDAP_CHANNEL_BINDING_NOT_REQUIRED' = @{
        Title = "LDAP Channel Binding Not Enforced"
        Risk = "Finding"
        BaseScore = 25
        Description = "The GPO does not configure LDAP channel binding. Note: 'Not Configured' in GPO does not necessarily mean the setting is insecure - it may be configured locally on the Domain Controller via registry or enforced by OS defaults (Windows Server 2025+ enforces channel binding by default). However, best practice is to enforce security settings via GPO for consistent configuration across all DCs."
        Impact = @(
            "LDAPS connections can be relayed"
            "Provides additional attack surface for NTLM relay"
            "Weakens overall LDAP security posture"
        )
        Attack = @(
            "1. Attacker performs LDAP relay over TLS"
            "2. Without channel binding, relay succeeds"
            "3. Attacker performs privileged LDAP operations"
        )
        Remediation = @(
            "Enable LDAP channel binding on Domain Controllers"
            "Set registry: HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LdapEnforceChannelBinding = 2"
            "Best practice: Deploy via GPO Preferences for consistent configuration"
            "Test application compatibility before enforcing"
        )
        RemediationCommands = @(
            @{
                Description = "Enable LDAP channel binding enforcement on Domain Controller (Value 2 = Always require channel binding)"
                Command = "New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters' -Name LdapEnforceChannelBinding -Value 2 -PropertyType DWORD -Force"
            }
            @{
                Description = "Set to 'When Supported' mode for initial testing (Value 1 = Only enforce for updated clients)"
                Command = "New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters' -Name LdapEnforceChannelBinding -Value 1 -PropertyType DWORD -Force"
            }
            @{
                Description = "Verify current LDAP channel binding configuration on Domain Controller"
                Command = "Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters' -Name LdapEnforceChannelBinding -ErrorAction SilentlyContinue | Select-Object LdapEnforceChannelBinding"
            }
            @{
                Description = "Configure LDAP channel binding via Group Policy (Server 2025+)"
                Command = "# In Group Policy Management: Default Domain Controller Policy > Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > 'Domain controller: LDAP server channel binding token requirements' = Always"
            }
        )
        References = @(
            @{ Title = "2020, 2023, and 2024 LDAP channel binding and LDAP signing requirements"; Url = "https://support.microsoft.com/en-us/topic/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a" }
            @{ Title = "KB4034879: Use the LdapEnforceChannelBinding registry entry"; Url = "https://support.microsoft.com/en-us/topic/kb4034879-use-the-ldapenforcechannelbinding-registry-entry-to-make-ldap-authentication-over-ssl-tls-more-secure-e9ecfa27-5e57-8519-6ba3-d2c06b21812e" }
            @{ Title = "Active Directory Hardening Series - Part 5 - Enforcing LDAP Channel Binding"; Url = "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-5-%E2%80%93-enforcing-ldap-channel-binding/4235497" }
        )
        Tools = @("ntlmrelayx", "Impacket")
        MITRE = "T1557"
        Triggers = @(
            @{ Attribute = 'ChannelBinding'; Pattern = '^(Never|Not Configured|Disabled|Not Required)$'; Severity = 'Finding' }
            @{ Attribute = 'ChannelBinding'; Pattern = '^When Supported$'; Severity = 'Hint' }
        )
    }

    'LDAP_ANONYMOUS_BINDING_ALLOWED' = @{
        Title = "Anonymous LDAP Binding Allowed"
        Risk = "Hint"
        BaseScore = 30
        Description = "The GPO does not restrict anonymous LDAP binding. Note: 'Not Configured' in GPO does not necessarily mean anonymous access is allowed - it may be restricted locally on the Domain Controller or by OS defaults (disabled by default since Windows Server 2003). However, best practice is to explicitly configure security settings via GPO for consistent configuration and auditability."
        Impact = @(
            "Unauthenticated enumeration of Active Directory objects"
            "Discovery of usernames, group memberships, and organizational structure"
            "Information gathering for targeted attacks"
            "Potential exposure of sensitive attributes"
        )
        Attack = @(
            "1. Attacker connects to LDAP without credentials"
            "2. Enumerates users, groups, and computers"
            "3. Identifies high-value targets and attack paths"
            "4. Uses gathered information for further attacks"
        )
        Remediation = @(
            "Explicitly disable anonymous LDAP access via GPO"
            "Review 'Network access: Do not allow anonymous enumeration of SAM accounts and shares'"
            "Configure dsHeuristics to remove ANONYMOUS LOGON access"
            "Best practice: Explicitly configure security settings via GPO rather than relying on defaults"
        )
        RemediationCommands = @(
            @{
                Description = "Disable anonymous LDAP access via Group Policy"
                Command = "# In Group Policy Management: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' = Enabled"
            }
            @{
                Description = "Check current dsHeuristics value (7th character controls anonymous access)"
                Command = "Get-ADObject 'CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=domain,DC=com' -Properties dsHeuristics | Select-Object dsHeuristics"
            }
            @{
                Description = "Remove anonymous LDAP access by modifying dsHeuristics (set 7th character to 0)"
                Command = "`$dn = 'CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=domain,DC=com'; `$current = (Get-ADObject `$dn -Properties dsHeuristics).dsHeuristics; if (`$current.Length -ge 7) { `$new = `$current.Substring(0,6) + '0' + `$current.Substring(7); Set-ADObject `$dn -Replace @{dsHeuristics=`$new} }"
            }
            @{
                Description = "Test anonymous LDAP access (should fail if properly configured)"
                Command = "# From non-domain-joined system: ldapsearch -x -h dc01.domain.com -b 'DC=domain,DC=com' '(objectClass=user)' sAMAccountName"
            }
        )
        References = @(
            @{ Title = "Anonymous LDAP Operations"; Url = "https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/anonymous-ldap-operations-active-directory-disabled" }
        )
        Tools = @("ldapsearch", "windapsearch", "ldapdomaindump")
        MITRE = "T1087"
        Triggers = @(
            @{ Attribute = 'anonymousLDAPAccess'; Severity = 'Finding' }
            @{ Attribute = 'AnonymousBinding'; Pattern = '^Allowed$'; Severity = 'Finding' }
            @{ Attribute = 'AnonymousBinding'; Pattern = '^Not Configured$'; Severity = 'Hint' }
        )
    }

    # ============================================================================
    # SID HISTORY FINDINGS
    # ============================================================================

    'SID_HISTORY_INJECTION' = @{
        Title = "SID History Attribute Set"
        Risk = "Finding"
        BaseScore = 80
        Description = "This account has SID History entries. While legitimate during domain migrations, SID History can be abused to maintain persistent privileged access by injecting privileged SIDs that bypass normal access control."
        Impact = @(
            "Account may have hidden privileged access through historical SIDs"
            "Access is granted based on SID History without group membership visibility"
            "Attackers can inject Domain Admin SIDs for persistent access"
            "Very difficult to detect without specifically checking SID History"
            "Survives password resets and most remediation attempts"
        )
        Attack = @(
            "1. Attacker gains write access to an account's SID History"
            "2. Injects Domain Admin SID (RID 512) into SID History"
            "3. Account now has Domain Admin access without visible group membership"
            "4. Standard 'net group' and 'Get-ADGroupMember' won't show the access"
            "5. Attacker maintains access even after initial compromise is remediated"
        )
        Remediation = @(
            "Audit all accounts with SID History entries"
            "Remove SID History after migration is complete"
            "Use 'Get-ADUser -Properties SIDHistory' to identify affected accounts"
            "Enable SID Filtering on trusts to block SID History injection"
            "Monitor for SID History modifications (Event ID 4765, 4766)"
        )
        RemediationCommands = @(
            @{
                Description = "Find all users with SID History"
                Command = "Get-ADUser -Filter {SIDHistory -like '*'} -Properties SIDHistory,SamAccountName | Select-Object SamAccountName,@{Name='SIDHistory';Expression={`$_.SIDHistory -join '; '}}"
            }
            @{
                Description = "Remove all SID History entries from a specific user"
                Command = "Get-ADUser 'USERNAME' -Properties SIDHistory | ForEach-Object { Set-ADUser `$_ -Remove @{SIDHistory=`$_.SIDHistory.Value} }"
            }
            @{
                Description = "Remove SID History from all users in a specific OU"
                Command = "Get-ADUser -SearchBase 'OU=MigratedUsers,DC=domain,DC=com' -Filter {SIDHistory -like '*'} -Properties SIDHistory | ForEach-Object { Set-ADUser `$_ -Remove @{SIDHistory=`$_.SIDHistory.Value} }"
            }
            @{
                Description = "Enable SID Filtering on a trust to block SID History injection (quarantine trust)"
                Command = "netdom trust TRUSTINGDOMAIN /domain:TRUSTEDDOMAIN /quarantine:yes"
            }
        )
        References = @(
            @{ Title = "SID History Injection - MITRE ATT&CK"; Url = "https://attack.mitre.org/techniques/T1134/005/" }
            @{ Title = "Accounts security posture assessment - unsecure SID History"; Url = "https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-unsecure-sid-history-attribute" }
            @{ Title = "SID History Attack"; Url = "https://adsecurity.org/?p=1772" }
            @{ Title = "SID Filtering and SID History - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-cleanup" }
        )
        Tools = @("Mimikatz", "DSInternals", "PowerView")
        MITRE = "T1134.005"
        Triggers = @(
            # SID-based classification: Privileged SID in sIDHistory = Finding (critical)
            @{ Attribute = 'sIDHistory'; Custom = 'is_privileged_sid'; Severity = 'Finding' }
            # Non-privileged SID in sIDHistory = Hint (still noteworthy migration artifact)
            @{ Attribute = 'sIDHistory'; Severity = 'Hint' }
            @{ Attribute = 'privilegedSIDHistory'; Severity = 'Finding' }
        )
    }

    # ============================================================================
    # GPO SECURITY FINDINGS
    # ============================================================================

    'GPO_DANGEROUS_PERMISSIONS' = @{
        Title = "Dangerous GPO Permissions"
        Risk = "Finding"
        BaseScore = 50
        Description = "This Group Policy Object has dangerous permissions that allow non-privileged users to modify it. GPO modifications can be used to execute code, deploy malware, or change security settings on all computers where the GPO is linked."
        Impact = @(
            "Attacker can modify GPO to execute code on target computers"
            "Can deploy scheduled tasks, startup scripts, or registry modifications"
            "Affects all computers and users in the GPO's scope"
            "Changes propagate automatically during Group Policy refresh"
            "Can be used to compromise Domain Controllers if linked at domain level"
        )
        Attack = @(
            "1. Attacker identifies GPO with write permissions"
            "2. Modifies GPO to add malicious scheduled task or startup script"
            "3. Waits for Group Policy refresh (or forces via gpupdate)"
            "4. Malicious code executes on all affected computers"
            "5. If targeting DCs, achieves domain compromise"
        )
        Remediation = @(
            "Remove unnecessary write permissions from GPOs"
            "Only Domain Admins and specific GPO management groups should have write access"
            "Use GPO delegation carefully - prefer read-only access"
            "Monitor GPO modifications (Event ID 5136)"
            "Implement GPO change management process"
        )
        RemediationCommands = @(
            @{
                Description = "View current GPO permissions"
                Command = "Get-GPPermission -Name 'GPO_NAME' -All | Format-Table Trustee,Permission,Inherited -AutoSize"
            }
            @{
                Description = "Remove all permissions for a specific user/group from a GPO (set to None)"
                Command = "Set-GPPermission -Name 'GPO_NAME' -PermissionLevel None -TargetName 'DOMAIN\User' -TargetType User -Replace"
            }
            @{
                Description = "Grant read-only access instead of write access to a GPO"
                Command = "Set-GPPermission -Name 'GPO_NAME' -PermissionLevel GpoRead -TargetName 'DOMAIN\Group' -TargetType Group -Replace"
            }
            @{
                Description = "Find all GPOs with write permissions for a specific principal"
                Command = "Get-GPO -All | ForEach-Object { `$perms = Get-GPPermission -Guid `$_.Id -All | Where-Object { `$_.Trustee.Name -eq 'USERNAME' -and `$_.Permission -match 'Edit|Write' }; if (`$perms) { [PSCustomObject]@{GPOName=`$_.DisplayName; Permission=`$perms.Permission} } }"
            }
        )
        References = @(
            @{ Title = "GPO Abuse - MITRE ATT&CK"; Url = "https://attack.mitre.org/techniques/T1484/001/" }
            @{ Title = "Set-GPPermission cmdlet"; Url = "https://learn.microsoft.com/en-us/powershell/module/grouppolicy/set-gppermission" }
            @{ Title = "Get-GPPermission cmdlet"; Url = "https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gppermission" }
            @{ Title = "GPO Abuse - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/acl-persistence-abuse/README.html#gpo-abuse" }
        )
        Tools = @("BloodHound", "PowerView", "SharpGPOAbuse")
        MITRE = "T1484.001"
        Triggers = @(
            @{ Attribute = 'DangerousSettings'; Severity = 'Finding' }
        )
    }

    'GPO_SCOPE_DOMAIN_WIDE' = @{
        Title = "GPO Linked at Domain Root (Domain-Wide Scope)"
        Risk = "Finding"
        BaseScore = 40
        Description = "This Group Policy Object is linked directly at the domain root. This means it applies to ALL computers and users in the domain, making any misconfiguration or vulnerability a domain-wide issue."
        Impact = @(
            "Every computer in the domain processes this GPO during Group Policy refresh"
            "Every user logging on to any domain computer is affected"
            "Malicious modifications impact the entire domain simultaneously"
            "Domain Controllers are also affected (highest security impact)"
            "Scope amplifies any other finding on this GPO to critical severity"
        )
        Attack = @(
            "1. Attacker identifies a domain-wide GPO with weak permissions"
            "2. Modifies GPO to deploy a scheduled task or startup script"
            "3. Within 90 minutes (default refresh), ALL domain computers execute the payload"
            "4. Includes Domain Controllers - immediate domain compromise"
        )
        Remediation = @(
            "Minimize the number of GPOs linked at domain root"
            "Ensure strict permissions on domain-wide GPOs (only Domain Admins)"
            "Use OU-level GPO linking for more granular control"
            "Consider security filtering (WMI filters) to limit GPO scope"
            "Monitor GPO link changes at domain level (Event ID 5136)"
        )
        RemediationCommands = @(
            @{
                Description = "List all GPOs linked at domain root"
                Command = "Get-ADDomain | Select-Object -ExpandProperty LinkedGroupPolicyObjects | ForEach-Object { Get-GPO -Guid (`$_ -replace '.*\\{|\\}.*') } | Select-Object DisplayName,Id,GpoStatus"
            }
            @{
                Description = "Unlink a GPO from the domain root"
                Command = "Remove-GPLink -Name 'GPO_NAME' -Target (Get-ADDomain).DistinguishedName"
            }
            @{
                Description = "Link a GPO to a specific OU instead of domain root"
                Command = "New-GPLink -Name 'GPO_NAME' -Target 'OU=Workstations,DC=domain,DC=com' -LinkEnabled Yes"
            }
            @{
                Description = "Apply security filtering to limit GPO scope (only apply to specific security group)"
                Command = "Set-GPPermission -Name 'GPO_NAME' -TargetName 'Authenticated Users' -TargetType Group -PermissionLevel None -Replace; Set-GPPermission -Name 'GPO_NAME' -TargetName 'DOMAIN\SpecificGroup' -TargetType Group -PermissionLevel GpoApply"
            }
        )
        References = @(
            @{ Title = "GPO Abuse - MITRE ATT&CK"; Url = "https://attack.mitre.org/techniques/T1484/001/" }
            @{ Title = "Remove-GPLink cmdlet"; Url = "https://learn.microsoft.com/en-us/powershell/module/grouppolicy/remove-gplink" }
            @{ Title = "New-GPLink cmdlet"; Url = "https://learn.microsoft.com/en-us/powershell/module/grouppolicy/new-gplink" }
            @{ Title = "Group Policy Security - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview" }
        )
        Tools = @("BloodHound", "PowerView", "SharpGPOAbuse")
        MITRE = "T1484.001"
        Triggers = @(
            @{ Attribute = 'Scope'; Pattern = 'Domain-wide'; Custom = 'is_gpo_finding_object'; Severity = 'Finding' }
            @{ Attribute = 'LinkedOUs'; Pattern = '^DC=[^,]+,DC='; Custom = 'is_gpo_finding_object'; Severity = 'Finding' }
        )
    }

    'GPO_CREDENTIAL_EXPOSURE' = @{
        Title = "Credentials in Group Policy Preferences"
        Risk = "Finding"
        BaseScore = 50
        Description = "Group Policy Preferences contain embedded credentials. The GPP password is encrypted with a publicly known AES key, making any stored password trivially recoverable by any authenticated user."
        Impact = @(
            "Passwords are encrypted with a KNOWN key (published by Microsoft)"
            "Any domain user can read SYSVOL and decrypt the passwords"
            "Often contains local administrator passwords"
            "Historical GPPs may contain domain admin credentials"
            "Credentials remain valid until manually changed"
        )
        Attack = @(
            "1. Attacker reads Groups.xml, ScheduledTasks.xml, etc. from SYSVOL"
            "2. Finds cpassword attribute in the XML"
            "3. Decrypts using the known AES key"
            "4. Uses credentials to access systems or escalate privileges"
        )
        Remediation = @(
            "Remove all GPP files containing cpassword"
            "Use LAPS for local administrator password management"
            "Never store credentials in GPP - use secure alternatives"
            "Search SYSVOL for cpassword: findstr /S cpassword \\\\domain\\SYSVOL\\*"
            "Consider Microsoft KB2962486 to block new GPP credential storage"
        )
        RemediationCommands = @(
            @{
                Description = "Search SYSVOL for all XML files containing cpassword attributes"
                Command = "Get-ChildItem -Path '\\\\domain.com\\SYSVOL\\domain.com\\Policies' -Recurse -Include *.xml | Select-String -Pattern 'cpassword' | Select-Object Path,LineNumber"
            }
            @{
                Description = "Find specific GPP files that commonly contain passwords"
                Command = "`$gpoPath = '\\\\domain.com\\SYSVOL\\domain.com\\Policies'; Get-ChildItem -Path `$gpoPath -Recurse -Include Groups.xml,ScheduledTasks.xml,Services.xml,DataSources.xml | ForEach-Object { if (Select-String -Path `$_.FullName -Pattern 'cpassword' -Quiet) { `$_ } }"
            }
            @{
                Description = "Remove cpassword from GPP via GPMC (preferred method)"
                Command = "# In GPMC: Navigate to the GPO > Preferences, locate the preference with password, change Action to 'Delete', save, then after GPO refresh delete the entire preference item"
            }
        )
        References = @(
            @{ Title = "MS14-025 - GPP Password Vulnerability"; Url = "https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-60734e15-af79-26ca-ea53-8cd617073c30" }
            @{ Title = "GPP Abuse - MITRE ATT&CK"; Url = "https://attack.mitre.org/techniques/T1552/006/" }
            @{ Title = "GPO Abuse - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/acl-persistence-abuse/README.html#gpp-group-policy-preferences" }
        )
        Tools = @("Get-GPPPassword", "gpp-decrypt", "Metasploit")
        MITRE = "T1552.006"
        Triggers = @(
            @{ Attribute = 'password'; Context = 'credential'; Severity = 'Finding' }
            @{ Attribute = 'userName'; Context = 'credential'; Severity = 'Finding' }
        )
    }

    'SCRIPT_CREDENTIAL_EXPOSURE' = @{
        Title = "Credentials in SYSVOL Scripts"
        Risk = "Finding"
        BaseScore = 50
        Description = "Scripts or configuration files in SYSVOL/NETLOGON contain plaintext credentials or credential patterns. Any authenticated domain user can read SYSVOL and extract these credentials."
        Impact = @(
            "Plaintext credentials readable by all domain users"
            "Often contains service account or admin credentials"
            "Scripts may have been in SYSVOL for years unnoticed"
            "Credentials likely still valid and unchanged"
            "Enables immediate privilege escalation or lateral movement"
        )
        Attack = @(
            "1. Attacker enumerates SYSVOL for script files (.ps1, .bat, .vbs, .cmd, .ini, .config)"
            "2. Searches for patterns like passwords, credentials, net use /user:"
            "3. Extracts usernames and passwords from script content"
            "4. Uses credentials to access systems or escalate privileges"
        )
        Remediation = @(
            "Remove all credentials from SYSVOL scripts immediately"
            "Use Windows Credential Manager or gMSA for automated tasks"
            "Implement a SYSVOL scanning process for credential exposure"
            "Rotate any exposed credentials after removal"
            "Consider using PowerShell SecretManagement for secrets"
        )
        RemediationCommands = @(
            @{
                Description = "Search SYSVOL for password patterns"
                Command = "findstr /S /I /M /C:`"password`" /C:`"credential`" /C:`"pwd`" \\\\domain\\SYSVOL\\*"
            }
            @{
                Description = "List all script files in SYSVOL"
                Command = "Get-ChildItem -Path \\\\domain\\SYSVOL -Recurse -Include *.ps1,*.bat,*.vbs,*.cmd,*.ini,*.config"
            }
        )
        References = @(
            @{ Title = "Credential Hunting in SYSVOL"; Url = "https://adsecurity.org/?p=2288" }
            @{ Title = "Unsecured Credentials - MITRE ATT&CK"; Url = "https://attack.mitre.org/techniques/T1552/001/" }
            @{ Title = "SYSVOL Security Best Practices"; Url = "https://learn.microsoft.com/en-us/troubleshoot/windows-client/group-policy/create-and-manage-central-store" }
        )
        Tools = @("findstr", "Grep", "PowerShell", "Snaffler")
        MITRE = "T1552.001"
    }

    # ============================================================================
    # LAPS FINDINGS
    # ============================================================================

    'LAPS_NOT_DEPLOYED' = @{
        Title = "LAPS Not Deployed"
        Risk = "Finding"
        BaseScore = 35
        Description = "Local Administrator Password Solution (LAPS) is not deployed on this computer. Without LAPS, local administrator passwords are likely the same across multiple systems, enabling lateral movement if one password is compromised."
        Impact = @(
            "Local admin passwords may be identical across systems"
            "Compromising one system's local admin enables lateral movement"
            "No automatic password rotation for local accounts"
            "Pass-the-Hash attacks are highly effective"
            "Violates security best practices and compliance requirements"
        )
        Attack = @(
            "1. Attacker compromises one workstation and extracts local admin hash"
            "2. Uses hash to authenticate to other workstations (Pass-the-Hash)"
            "3. Moves laterally across the network"
            "4. Eventually reaches high-value targets"
        )
        Remediation = @(
            "Deploy Windows LAPS (built into Windows 11 22H2+ and Server 2019+)"
            "Or deploy legacy Microsoft LAPS for older systems"
            "Configure LAPS via GPO for password complexity and rotation"
            "Restrict LAPS password read access to appropriate administrators"
            "Enable LAPS password encryption for enhanced security"
        )
        RemediationCommands = @(
            @{
                Description = "Update Active Directory schema to support Windows LAPS (one-time forest-wide operation)"
                Command = "Update-LapsADSchema"
            }
            @{
                Description = "Grant computer objects permission to update their LAPS passwords in a specific OU"
                Command = "Set-LapsADComputerSelfPermission -Identity 'OU=Workstations,DC=domain,DC=com'"
            }
            @{
                Description = "Enable LAPS via Group Policy (Computer Configuration -> Policies -> Administrative Templates -> System -> LAPS)"
                Command = "# Set 'Enable password backup' to Enabled in GPO, then configure password complexity, length, and maximum age settings"
            }
            @{
                Description = "Verify LAPS deployment status for all computers in an OU"
                Command = "Get-ADComputer -Filter * -SearchBase 'OU=Workstations,DC=domain,DC=com' -Properties ms-Mcs-AdmPwdExpirationTime | Select-Object Name,DNSHostName,ms-Mcs-AdmPwdExpirationTime"
            }
        )
        References = @(
            @{ Title = "Windows LAPS Overview"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview" }
            @{ Title = "Get started with Windows LAPS and Windows Server Active Directory"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory" }
            @{ Title = "Set-LapsADComputerSelfPermission cmdlet"; Url = "https://learn.microsoft.com/en-us/powershell/module/laps/set-lapsadcomputerselfpermission" }
            @{ Title = "Configure Policy Settings for Windows LAPS"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings" }
            @{ Title = "LAPS - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/laps.html" }
        )
        Tools = @("LAPSToolkit", "PowerView")
        MITRE = "T1078.003"
        Triggers = @(
            @{ Attribute = 'affectedComputers'; Severity = 'Finding' }
        )
    }

    'LAPS_PASSWORD_READABLE' = @{
        Title = "LAPS Password Readable"
        Risk = "Finding"
        BaseScore = 55
        Description = "The current user can read the LAPS password for this computer. While this may be intentional for IT administrators, unexpected read access could enable privilege escalation or lateral movement."
        Impact = @(
            "LAPS password provides local administrator access to the computer"
            "If attacker can read password, they can fully compromise the system"
            "Local admin access enables credential harvesting (Mimikatz)"
            "Can be used as stepping stone for lateral movement"
        )
        Attack = @(
            "1. Attacker identifies computers where they can read LAPS password"
            "2. Reads ms-Mcs-AdmPwd or msLAPS-Password attribute"
            "3. Uses password to gain local admin access"
            "4. Dumps credentials from memory for further attacks"
        )
        Remediation = @(
            "Review LAPS password read permissions"
            "Use tiered administration - only Tier 0 admins read DC LAPS passwords"
            "Enable LAPS password encryption (Windows LAPS)"
            "Audit LAPS password reads (Event ID 4662)"
            "Use Just-In-Time access for LAPS password retrieval"
        )
        RemediationCommands = @(
            @{
                Description = "Grant specific group permission to read LAPS passwords for computers in an OU"
                Command = "Set-LapsADReadPasswordPermission -Identity 'OU=Workstations,DC=domain,DC=com' -AllowedPrincipals 'DOMAIN\IT-Admins'"
            }
            @{
                Description = "View current LAPS password read permissions on an OU using Active Directory ACL"
                Command = "(Get-Acl 'AD:\OU=Workstations,DC=domain,DC=com').Access | Where-Object {`$_.ObjectType -eq 'ms-Mcs-AdmPwd' -or `$_.ObjectType -eq 'msLAPS-Password'} | Select-Object IdentityReference,ActiveDirectoryRights,AccessControlType"
            }
            @{
                Description = "Enable auditing for LAPS password reads (requires legacy LAPS PowerShell module for Set-AdmPwdAuditing)"
                Command = "Import-Module AdmPwd.PS; Set-AdmPwdAuditing -OrgUnit 'OU=Workstations,DC=domain,DC=com' -AuditedPrincipals 'DOMAIN\IT-Admins'"
            }
            @{
                Description = "Query who has read access to LAPS passwords in a specific OU"
                Command = "Find-AdmPwdExtendedRights -Identity 'OU=Workstations,DC=domain,DC=com' | Select-Object ExtendedRightHolders"
            }
        )
        References = @(
            @{ Title = "Windows LAPS Security"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview" }
            @{ Title = "Set-LapsADReadPasswordPermission cmdlet"; Url = "https://learn.microsoft.com/en-us/powershell/module/laps/set-lapsadreadpasswordpermission" }
            @{ Title = "Auditing Access to LAPS Passwords"; Url = "https://petri.com/auditing-access-to-laps-passwords-in-active-directory/" }
            @{ Title = "LAPS - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/laps.html" }
        )
        Tools = @("LAPSToolkit", "PowerView")
        MITRE = "T1552.004"
        Triggers = @(
            @{ Attribute = 'ms-Mcs-AdmPwd'; Severity = 'Finding' }
            @{ Attribute = 'msLAPS-Password'; Severity = 'Finding' }
            @{ Attribute = 'msLAPS-EncryptedPassword'; Severity = 'Finding' }
        )
    }

    'LAPS_PASSWORD_READ_ACCESS' = @{
        Title = "LAPS Password Read Permissions"
        Risk = "Finding"
        BaseScore = 45
        Description = "A non-privileged principal has been granted explicit permissions to read LAPS passwords. This allows them to obtain local administrator credentials for computers in the affected OUs, potentially enabling lateral movement."
        Impact = @(
            "Principal can read local admin passwords for affected computers"
            "Enables lateral movement to any computer where they have read access"
            "Compromising this principal grants access to all computers in scope"
            "May violate tiered administration model"
        )
        Attack = @(
            "1. Attacker compromises account with LAPS read permissions"
            "2. Enumerates computers where the account can read passwords"
            "3. Retrieves LAPS passwords via LDAP (ms-Mcs-AdmPwd or msLAPS-Password)"
            "4. Uses credentials for local admin access and credential harvesting"
        )
        Remediation = @(
            "Review and restrict LAPS password read permissions"
            "Follow tiered administration - only appropriate tier admins should read passwords"
            "Use security groups for LAPS access, not individual accounts"
            "Consider Windows LAPS with encrypted passwords for additional protection"
            "Audit LAPS password reads (Event ID 4662)"
        )
        RemediationCommands = @(
            @{
                Description = "Enumerate who has LAPS password read permissions on a specific OU"
                Command = "Find-AdmPwdExtendedRights -Identity 'OU=Workstations,DC=domain,DC=com' | Select-Object ExtendedRightHolders,ObjectDN"
            }
            @{
                Description = "View detailed ACL entries for LAPS password attributes on an OU"
                Command = "(Get-Acl 'AD:\OU=Workstations,DC=domain,DC=com').Access | Where-Object {`$_.ObjectType -eq 'ms-Mcs-AdmPwd' -or `$_.ObjectType -eq 'msLAPS-Password'} | Format-Table IdentityReference,ActiveDirectoryRights,AccessControlType,IsInherited -AutoSize"
            }
            @{
                Description = "Remove explicit LAPS read permission for a specific principal using Active Directory ACL manipulation"
                Command = "`$ou = [ADSI]'LDAP://OU=Workstations,DC=domain,DC=com'; `$acl = `$ou.PSBase.ObjectSecurity; `$ace = `$acl.Access | Where-Object {`$_.IdentityReference -eq 'DOMAIN\Username' -and `$_.ObjectType -eq 'ms-Mcs-AdmPwd'}; `$acl.RemoveAccessRule(`$ace); `$ou.PSBase.CommitChanges()"
            }
            @{
                Description = "Grant LAPS read permission to appropriate security group only"
                Command = "Set-LapsADReadPasswordPermission -Identity 'OU=Workstations,DC=domain,DC=com' -AllowedPrincipals 'DOMAIN\Tier1-Admins'"
            }
        )
        References = @(
            @{ Title = "Windows LAPS Security"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview" }
            @{ Title = "LAPS Access Control"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory" }
            @{ Title = "Set-LapsADReadPasswordPermission cmdlet"; Url = "https://learn.microsoft.com/en-us/powershell/module/laps/set-lapsadreadpasswordpermission" }
        )
        Tools = @("LAPSToolkit", "PowerView", "Get-LapsADPassword")
        MITRE = "T1552.004"
        Triggers = @(
            @{ Attribute = 'dangerousRights'; Pattern = 'LAPS Password Read'; Severity = 'Finding' }
            @{ Attribute = 'DangerousPermissions'; Pattern = 'LAPS Password Read'; Severity = 'Finding' }
        )
    }

    # ============================================================================
    # SMB SIGNING FINDINGS
    # ============================================================================

    'SMB_SIGNING_DISABLED' = @{
        Title = "SMB Signing Not Required"
        Risk = "Finding"
        BaseScore = 30
        Description = "The GPO does not configure SMB signing requirements. Note: 'Not Configured' in GPO does not necessarily mean SMB signing is disabled - it may be configured locally on the system or enforced by OS defaults (Windows Server 2022+ and Windows 11 require SMB signing by default). However, best practice is to enforce security settings via GPO for consistent configuration across all systems, especially for in-place upgraded systems that may retain legacy settings."
        Impact = @(
            "SMB connections can be intercepted and relayed"
            "NTLM relay attacks can target SMB services"
            "Attackers can authenticate to other systems using relayed credentials"
            "Can lead to remote code execution on target systems"
            "Enables lateral movement without knowing passwords"
        )
        Attack = @(
            "1. Attacker positions for man-in-the-middle"
            "2. Coerces authentication from target (PetitPotam, PrinterBug, etc.)"
            "3. Relays NTLM authentication to a system without SMB signing"
            "4. Executes commands or accesses files as the relayed user"
        )
        Remediation = @(
            "Enable SMB signing on all systems: RequireSecuritySignature = True"
            "Deploy via GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options"
            "Microsoft network server: Digitally sign communications (always) = Enabled"
            "Best practice: Always configure security settings via GPO rather than relying on local policy or OS defaults"
            "Test application compatibility before enforcing"
        )
        RemediationCommands = @(
            @{
                Description = "Enable SMB server signing (require signing for inbound connections)"
                Command = "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force"
            }
            @{
                Description = "Enable SMB client signing (require signing for outbound connections)"
                Command = "Set-SmbClientConfiguration -RequireSecuritySignature `$true -Force"
            }
            @{
                Description = "Verify current SMB signing configuration"
                Command = "Get-SmbServerConfiguration | Select-Object RequireSecuritySignature,EnableSecuritySignature; Get-SmbClientConfiguration | Select-Object RequireSecuritySignature,EnableSecuritySignature"
            }
            @{
                Description = "Configure SMB signing via Group Policy (recommended for domain-wide enforcement)"
                Command = "# In Group Policy Management: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > 'Microsoft network server: Digitally sign communications (always)' = Enabled AND 'Microsoft network client: Digitally sign communications (always)' = Enabled"
            }
        )
        References = @(
            @{ Title = "Control SMB signing behavior"; Url = "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing" }
            @{ Title = "Configure SMB Signing with Confidence"; Url = "https://techcommunity.microsoft.com/blog/filecab/configure-smb-signing-with-confidence/2418102" }
            @{ Title = "SMB Signing Overview"; Url = "https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing" }
            @{ Title = "NTLM Relay - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/ntlm/index.html" }
        )
        Tools = @("ntlmrelayx", "Responder", "NetExec")
        MITRE = "T1557.001"
        Triggers = @(
            @{ Attribute = 'ServerSigning'; Pattern = '^Disabled$'; Severity = 'Finding' }
            @{ Attribute = 'ServerSigning'; Pattern = '^(Optional|Not Configured|Not Required)$'; Severity = 'Hint' }
            @{ Attribute = 'ClientSigning'; Pattern = '^Disabled$'; Severity = 'Finding' }
            @{ Attribute = 'ClientSigning'; Pattern = '^(Optional|Not Configured|Not Required)$'; Severity = 'Hint' }
        )
    }

    # ============================================================================
    # CREDENTIAL EXPOSURE FINDINGS
    # ============================================================================

    'CREDENTIAL_IN_DESCRIPTION' = @{
        Title = "Credentials Found in Description/Info Field"
        Risk = "Finding"
        BaseScore = 45
        Description = "The description or info attribute of this object contains what appears to be a password or credential. These fields are readable by any authenticated user, exposing credentials to all domain users."
        Impact = @(
            "Passwords visible to any authenticated domain user"
            "Often contains actual working passwords"
            "Common for service accounts and shared accounts"
            "No authentication or special permissions required to read"
            "Credentials may grant access to critical systems"
        )
        Attack = @(
            "1. Attacker queries AD for all objects with non-empty description/info"
            "2. Parses for password patterns (pass=, pwd:, password, etc.)"
            "3. Tests discovered credentials against accounts"
            "4. Uses valid credentials for access or privilege escalation"
        )
        Remediation = @(
            "Remove all passwords from description and info fields immediately"
            "Use a proper password manager for credential storage"
            "Educate administrators about this security risk"
            "Implement regular scans for credentials in AD attributes"
            "Consider using managed service accounts (gMSA/sMSA) which don't need stored passwords"
        )
        RemediationCommands = @(
            @{
                Description = "Find all users with potentially sensitive data in description field"
                Command = "Get-ADUser -Filter {Description -like '*pass*' -or Description -like '*pwd*' -or Description -like '*pw:*'} -Properties Description | Select-Object SamAccountName,Description"
            }
            @{
                Description = "Clear description field for a specific user"
                Command = "Set-ADUser -Identity 'USERNAME' -Description `$null"
            }
            @{
                Description = "Find all users with potentially sensitive data in info field"
                Command = "Get-ADUser -Filter * -Properties Info | Where-Object {`$_.Info -match 'pass|pwd|pw:|secret|credential'} | Select-Object SamAccountName,Info"
            }
            @{
                Description = "Clear info field for a specific user"
                Command = "Set-ADUser -Identity 'USERNAME' -Clear Info"
            }
        )
        References = @(
            @{ Title = "Finding Passwords in AD"; Url = "https://adsecurity.org/?p=2288" }
            @{ Title = "Credential Hunting - MITRE ATT&CK"; Url = "https://attack.mitre.org/techniques/T1552/006/" }
            @{ Title = "AD Attribute Security - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory" }
        )
        Tools = @("PowerView", "ADRecon", "LDAP queries")
        MITRE = "T1552.001"
        Triggers = @(
            @{ Attribute = 'description'; Pattern = 'passw|pwd\s*[=:]|pw\s*[=:]|\bpass\s*[=:]|kennwort|secret|credential|parol[ae]?'; Severity = 'Finding' }
            @{ Attribute = 'info'; Pattern = 'passw|pwd\s*[=:]|pw\s*[=:]|\bpass\s*[=:]|kennwort|secret|credential|parol[ae]?'; Severity = 'Finding' }
        )
    }

    'CREDENTIAL_GPP_PASSWORD' = @{
        Title = "Group Policy Preferences Password (GPP)"
        Risk = "Finding"
        BaseScore = 50
        Description = "A Group Policy Preferences (GPP) file contains an encrypted password (cpassword attribute). The encryption key was publicly disclosed by Microsoft in 2012 (MS14-025), allowing anyone to decrypt these passwords. This is a well-known vulnerability actively exploited in penetration tests and real attacks."
        Impact = @(
            "Password can be instantly decrypted by any domain user"
            "GPP files are readable by all authenticated users via SYSVOL"
            "Often contains local administrator or service account passwords"
            "Credentials may still be valid and in use"
            "Common finding in domain compromises"
        )
        Attack = @(
            "1. Attacker accesses SYSVOL share (any domain user can read)"
            "2. Searches for Groups.xml, ScheduledTasks.xml, Services.xml, etc."
            "3. Extracts cpassword attribute from XML files"
            "4. Decrypts password using publicly known AES key"
            "5. Uses credentials for lateral movement or privilege escalation"
        )
        Remediation = @(
            "Delete ALL GPP files containing cpassword attributes immediately"
            "Install KB2962486 to prevent new GPP passwords from being created"
            "Change any passwords that were stored in GPP files"
            "Use LAPS for local administrator password management"
            "Use gMSA for service accounts instead of GPP-deployed passwords"
        )
        RemediationCommands = @(
            @{
                Description = "Find all XML files in SYSVOL containing cpassword attributes (recursively)"
                Command = "Get-ChildItem -Path '\\\\domain.com\\SYSVOL\\domain.com\\Policies' -Recurse -Include *.xml | Select-String -Pattern 'cpassword' | Select-Object Path,LineNumber"
            }
            @{
                Description = "Find specific GPP files that commonly contain passwords (Groups.xml, ScheduledTasks.xml, Services.xml, DataSources.xml)"
                Command = "`$gpoPath = '\\\\domain.com\\SYSVOL\\domain.com\\Policies'; Get-ChildItem -Path `$gpoPath -Recurse -Include Groups.xml,ScheduledTasks.xml,Services.xml,DataSources.xml,Printers.xml,Drives.xml | ForEach-Object { if (Select-String -Path `$_.FullName -Pattern 'cpassword' -Quiet) { `$_ } }"
            }
            @{
                Description = "Remove cpassword from GPP via GPMC (recommended method - opens GPO for manual cleanup)"
                Command = "# In GPMC: Navigate to GPO > User/Computer Configuration > Preferences, locate the affected preference item, change Action to 'Delete' or remove the password field, save changes, then after GPO refresh cycles complete, delete the entire preference item"
            }
            @{
                Description = "Delete specific GPP XML file after backing up (use with caution - ensure GPO is no longer needed)"
                Command = "# Backup first: Copy-Item 'PATH_TO_GPP_FILE.xml' 'PATH_TO_BACKUP_LOCATION'; Remove-Item 'PATH_TO_GPP_FILE.xml' -Force"
            }
        )
        References = @(
            @{ Title = "MS14-025 - GPP Password Vulnerability"; Url = "https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-60734e15-af79-26ca-ea53-8cd617073c30" }
            @{ Title = "How to remove cPassword values from Active Directory"; Url = "https://www.grouppolicy.biz/2014/05/remove-cpassword-values-active-directory/" }
            @{ Title = "Finding Passwords in SYSVOL - ADSecurity"; Url = "https://adsecurity.org/?p=2288" }
            @{ Title = "Exploiting GPP - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/acl-persistence-abuse/README.html#gpp-group-policy-preferences" }
        )
        Tools = @("Get-GPPPassword", "gpp-decrypt", "PowerSploit", "Impacket")
        MITRE = "T1552.006"
        Triggers = @(
            @{ Attribute = 'credentialType'; Pattern = 'GPP Password'; Severity = 'Finding' }
            @{ Attribute = 'cpassword'; Severity = 'Finding' }
        )
    }

    'CREDENTIAL_AUTOADMINLOGON' = @{
        Title = "AutoAdminLogon Credentials in GPO"
        Risk = "Finding"
        BaseScore = 45
        Description = "A Group Policy deploys AutoAdminLogon registry settings with plaintext credentials. These credentials are stored unencrypted in Registry.xml files in SYSVOL, readable by any authenticated domain user. AutoAdminLogon automatically logs in a user at system startup."
        Impact = @(
            "Username and password stored in PLAINTEXT (not even encrypted like GPP)"
            "Readable by ANY authenticated domain user via SYSVOL"
            "Often contains administrative credentials for unattended deployments"
            "Credentials apply to workstations/servers where the GPO is linked"
            "Enables automatic administrative access to target systems"
        )
        Attack = @(
            "1. Attacker accesses SYSVOL share (any domain user can read)"
            "2. Searches for Registry.xml files containing AutoAdminLogon"
            "3. Extracts DefaultUserName, DefaultPassword, and DefaultDomainName"
            "4. Uses credentials directly (no decryption needed!)"
            "5. Logs into systems where AutoAdminLogon is configured"
        )
        Remediation = @(
            "Remove AutoAdminLogon GPO settings immediately"
            "Change the exposed password on all affected accounts"
            "Use Windows Autopilot or MDT for unattended deployments instead"
            "If AutoAdminLogon is required, configure it locally (not via GPO)"
            "Consider using autologon.exe from Sysinternals which encrypts credentials"
        )
        RemediationCommands = @(
            @{
                Description = "Search SYSVOL for Registry.xml files containing AutoAdminLogon settings"
                Command = "Get-ChildItem -Path '\\\\domain.com\\SYSVOL\\domain.com\\Policies' -Recurse -Include Registry.xml | Select-String -Pattern 'AutoAdminLogon|DefaultUserName|DefaultPassword' | Select-Object Path,LineNumber"
            }
            @{
                Description = "Remove AutoAdminLogon registry value from a GPO using Remove-GPRegistryValue"
                Command = "Remove-GPRegistryValue -Name 'GPO_NAME' -Key 'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -ValueName 'AutoAdminLogon'"
            }
            @{
                Description = "Remove all Winlogon registry settings from a GPO (AutoAdminLogon, DefaultUserName, DefaultPassword)"
                Command = "Remove-GPRegistryValue -Name 'GPO_NAME' -Key 'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'"
            }
            @{
                Description = "Disable AutoAdminLogon locally on a specific computer"
                Command = "Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon' -Value 0"
            }
        )
        References = @(
            @{ Title = "Winlogon AutoAdminLogon Registry Keys"; Url = "https://docs.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon" }
            @{ Title = "SYSVOL Credential Hunting"; Url = "https://adsecurity.org/?p=2288" }
            @{ Title = "Remove-GPRegistryValue cmdlet"; Url = "https://learn.microsoft.com/en-us/powershell/module/grouppolicy/remove-gpregistryvalue" }
        )
        Tools = @("PowerView", "Snaffler", "Manual SYSVOL search")
        MITRE = "T1552.001"
        Triggers = @(
            @{ Attribute = 'credentialType'; Pattern = 'AutoAdminLogon'; Severity = 'Finding' }
        )
    }

    'CREDENTIAL_NET_USE' = @{
        Title = "Net Use Command with Embedded Password"
        Risk = "Finding"
        BaseScore = 40
        Description = "A login script or batch file contains a 'net use' command with an embedded password. These scripts are stored in SYSVOL and readable by all authenticated domain users, exposing the credentials to potential attackers."
        Impact = @(
            "Password visible in plaintext in script files"
            "Scripts in SYSVOL/NETLOGON readable by all domain users"
            "Often used to map network drives at user logon"
            "May contain service account or shared account credentials"
            "Credentials may provide access to file servers or other resources"
        )
        Attack = @(
            "1. Attacker accesses SYSVOL/NETLOGON share"
            "2. Searches login scripts for 'net use' with /user: parameter"
            "3. Extracts username and password from the command"
            "4. Uses credentials to access the target resource"
            "5. Potentially pivots to other systems using same credentials"
        )
        Remediation = @(
            "Remove passwords from all login scripts immediately"
            "Use Group Policy Preferences drive mappings (without cpassword)"
            "Implement Kerberos authentication for network resources"
            "Use the user's own credentials via SSO for drive mappings"
            "Change any exposed passwords"
        )
        RemediationCommands = @(
            @{
                Description = "Search SYSVOL for login scripts containing 'net use' with passwords"
                Command = "Get-ChildItem -Path '\\\\domain.com\\SYSVOL\\domain.com\\' -Recurse -Include *.bat,*.cmd,*.vbs,*.ps1 | Select-String -Pattern 'net use.*\/user:.*' | Select-Object Path,LineNumber,Line"
            }
            @{
                Description = "Find specific patterns for net use commands with embedded credentials"
                Command = "`$patterns = 'net use .* \/user:', 'net use .* /user:', 'password'; Get-ChildItem '\\\\domain.com\\SYSVOL' -Recurse -Include *.bat,*.cmd | ForEach-Object { Select-String -Path `$_.FullName -Pattern `$patterns }"
            }
            @{
                Description = "Remove login script path from all users in a specific OU"
                Command = "Get-ADUser -Filter * -SearchBase 'OU=Users,DC=domain,DC=com' -Properties scriptPath | Where-Object {`$_.scriptPath} | Set-ADUser -Clear scriptPath"
            }
            @{
                Description = "List all users with login scripts assigned to identify affected accounts"
                Command = "Get-ADUser -Filter {scriptPath -like '*'} -Properties scriptPath,distinguishedName | Select-Object Name,scriptPath,distinguishedName"
            }
        )
        References = @(
            @{ Title = "Credential Hunting in Scripts"; Url = "https://adsecurity.org/?p=2288" }
            @{ Title = "SYSVOL Security - Microsoft"; Url = "https://learn.microsoft.com/en-us/troubleshoot/windows-client/group-policy/create-and-manage-central-store" }
            @{ Title = "Hunting Passwords In SYSVOL"; Url = "https://www.networkintelligence.ai/blogs/hunting-passwords-in-sysvol/" }
        )
        Tools = @("Snaffler", "grep/findstr", "Manual script review")
        MITRE = "T1552.001"
        Triggers = @(
            @{ Attribute = 'credentialType'; Pattern = 'Net Use'; Severity = 'Finding' }
        )
    }

    'CREDENTIAL_SCRIPT_PASSWORD' = @{
        Title = "Password Found in Script File"
        Risk = "Finding"
        BaseScore = 45
        Description = "A script file in SYSVOL contains what appears to be a hardcoded password or credential. Scripts in SYSVOL are readable by all authenticated domain users, exposing these credentials to the entire domain."
        Impact = @(
            "Credentials visible to any authenticated domain user"
            "May be used for service accounts, database connections, or administrative access"
            "Scripts often contain credentials for automation purposes"
            "Could expose access to critical systems or databases"
        )
        Attack = @(
            "1. Attacker searches SYSVOL for common password patterns"
            "2. Reviews scripts for hardcoded credentials"
            "3. Identifies context of the credential (database, service, admin)"
            "4. Uses credential to access the target resource or system"
        )
        Remediation = @(
            "Remove all hardcoded credentials from scripts"
            "Use Windows Credential Manager or secure vaults"
            "Implement service accounts with Kerberos delegation"
            "Use gMSA accounts for services where possible"
            "Change all exposed passwords immediately"
        )
        RemediationCommands = @(
            @{
                Description = "Search SYSVOL for script files with common password patterns"
                Command = "`$patterns = 'password\s*=', 'pwd\s*=', 'passwd\s*=', 'credential', 'SecureString', 'ConvertTo-SecureString', '-AsPlainText'; Get-ChildItem '\\\\domain.com\\SYSVOL' -Recurse -Include *.ps1,*.vbs,*.bat,*.cmd,*.ini,*.config | Select-String -Pattern `$patterns | Select-Object Path,LineNumber,Line"
            }
            @{
                Description = "Install PowerShell SecretManagement module for secure credential storage"
                Command = "Install-Module -Name Microsoft.PowerShell.SecretManagement -Force -Scope CurrentUser; Install-Module -Name Microsoft.PowerShell.SecretStore -Force -Scope CurrentUser"
            }
            @{
                Description = "Register a SecretStore vault and store credentials securely"
                Command = "Register-SecretVault -Name LocalVault -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault; Set-Secret -Name 'ServiceAccountPassword' -Secret (Read-Host -AsSecureString -Prompt 'Enter Password')"
            }
            @{
                Description = "Retrieve credentials from SecretStore vault in scripts instead of hardcoding"
                Command = "`$password = Get-Secret -Name 'ServiceAccountPassword' -AsPlainText; `$credential = New-Object System.Management.Automation.PSCredential('domain\\user', (Get-Secret -Name 'ServiceAccountPassword'))"
            }
        )
        References = @(
            @{ Title = "Credential Hunting Techniques"; Url = "https://attack.mitre.org/techniques/T1552/" }
            @{ Title = "SYSVOL Security - Microsoft"; Url = "https://learn.microsoft.com/en-us/troubleshoot/windows-client/group-policy/create-and-manage-central-store" }
            @{ Title = "PowerShell Secret Management"; Url = "https://learn.microsoft.com/en-us/powershell/utility-modules/secretmanagement/how-to/manage-secretstore" }
            @{ Title = "Secure Password Management in PowerShell"; Url = "https://www.secureideas.com/blog/secure-password-management-in-powershell-best-practices" }
        )
        Tools = @("Snaffler", "trufflehog", "grep", "Manual review")
        MITRE = "T1552.001"
        Triggers = @(
            @{ Attribute = 'credentialType'; Pattern = 'Password|Credential|PSExec|Schtasks|Cmdkey|SecureString|API key'; Severity = 'Finding' }
            @{ Attribute = 'matchedLine'; Severity = 'Finding' }
        )
    }

    'CREDENTIAL_CONNECTION_STRING' = @{
        Title = "Database Connection String with Credentials"
        Risk = "Finding"
        BaseScore = 40
        Description = "A configuration file or script contains a database connection string with embedded credentials. These files are often stored in SYSVOL or shared locations, exposing database access credentials to domain users."
        Impact = @(
            "Direct access to database server without further authentication"
            "May expose SQL Server, Oracle, MySQL, or other database credentials"
            "Database may contain sensitive business data, PII, or financial records"
            "SQL Server accounts may have elevated privileges (sysadmin)"
        )
        Attack = @(
            "1. Attacker finds connection string in config file or script"
            "2. Extracts server, database, username, and password"
            "3. Connects to database server using exposed credentials"
            "4. Extracts data or escalates privileges (xp_cmdshell, etc.)"
        )
        Remediation = @(
            "Remove credentials from connection strings"
            "Use Windows Integrated Authentication where possible"
            "Store connection strings in encrypted configuration sections"
            "Use Azure Key Vault or similar secret management"
            "Rotate all exposed database credentials"
        )
        RemediationCommands = @(
            @{
                Description = "Search SYSVOL for files containing database connection strings"
                Command = "`$patterns = 'Server=', 'Data Source=', 'Initial Catalog=', 'User ID=', 'Password=', 'connection\s*string'; Get-ChildItem '\\\\domain.com\\SYSVOL' -Recurse -Include *.config,*.xml,*.ini,*.ps1,*.vbs | Select-String -Pattern `$patterns | Select-Object Path,LineNumber,Line"
            }
            @{
                Description = "Convert SQL Server connection string to Windows Integrated Authentication (remove credentials)"
                Command = "# Replace: 'Server=myServer;Database=myDB;User Id=sa;Password=P@ss;' with: 'Server=myServer;Database=myDB;Integrated Security=SSPI;Trusted_Connection=Yes;Encrypt=True;'"
            }
            @{
                Description = "Find all connection strings with embedded credentials in configuration files"
                Command = "Get-ChildItem -Path '\\\\domain.com\\SYSVOL' -Recurse -Include *.config | ForEach-Object { Select-Xml -Path `$_.FullName -XPath '//connectionStrings/add[@connectionString]' | Where-Object { `$_.Node.connectionString -match 'password=|pwd=' } | Select-Object @{Name='File';Expression={`$_.Path}}, @{Name='Name';Expression={`$_.Node.name}}, @{Name='ConnectionString';Expression={`$_.Node.connectionString}} }"
            }
            @{
                Description = "Store database credentials securely in Azure Key Vault (alternative to hardcoded connection strings)"
                Command = "# Install-Module Az.KeyVault; `$secret = ConvertTo-SecureString 'MySecretPassword' -AsPlainText -Force; Set-AzKeyVaultSecret -VaultName 'MyVault' -Name 'DbPassword' -SecretValue `$secret"
            }
        )
        References = @(
            @{ Title = "Connection String Attacks"; Url = "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-mssql-microsoft-sql-server.html" }
            @{ Title = "SQL Server Security - Microsoft"; Url = "https://learn.microsoft.com/en-us/sql/relational-databases/security/securing-sql-server" }
            @{ Title = "SQL Server Connection String Syntax"; Url = "https://learn.microsoft.com/en-us/sql/connect/ado-net/connection-string-syntax" }
            @{ Title = "How to Access SQL Server Using Windows Integrated Security"; Url = "https://learn.microsoft.com/en-us/previous-versions/aspnet/bsz5788z(v=vs.100)" }
        )
        Tools = @("Snaffler", "trufflehog", "sqlcmd")
        MITRE = "T1552.001"
        Triggers = @(
            @{ Attribute = 'credentialType'; Pattern = 'connection\s*string|DB connection'; Severity = 'Finding' }
        )
    }

    'CREDENTIAL_MENTION_REVIEW' = @{
        Title = "Possible Credential Reference (Needs Review)"
        Risk = "Note"
        BaseScore = 20
        Description = "A script or configuration file contains a term that may indicate credential storage or usage. This is a lower-confidence finding that requires manual review to determine if actual credentials are exposed."
        Impact = @(
            "May indicate hardcoded passwords requiring further investigation"
            "Could be documentation, comments, or actual credential exposure"
            "False positives are common with generic password mentions"
            "Manual review needed to assess actual risk"
        )
        Attack = @(
            "1. Attacker searches scripts for credential keywords"
            "2. Reviews context to determine if actual credentials are present"
            "3. If credentials found, extracts and uses them for access"
        )
        Remediation = @(
            "Review the matched line to determine if credentials are present"
            "If credentials exist, remove them and use secure alternatives"
            "Document password policies rather than embedding examples"
            "Use secure credential storage mechanisms"
        )
        References = @(
            @{ Title = "Credential Hunting - MITRE ATT&CK"; Url = "https://attack.mitre.org/techniques/T1552/" }
            @{ Title = "SYSVOL Security - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory" }
        )
        Tools = @("Manual review", "Snaffler")
        MITRE = "T1552.001"
        Triggers = @(
            @{ Attribute = 'credentialType'; Pattern = '\(needs review\)'; Severity = 'Note' }
            @{ Attribute = 'matchedLine'; Context = 'needs review'; Severity = 'Note' }
        )
    }

    'REVERSIBLE_ENCRYPTION' = @{
        Title = "Password Stored with Reversible Encryption"
        Risk = "Finding"
        BaseScore = 30
        Description = "This account has 'Store password using reversible encryption' enabled. This means the password is stored in a way that can be decrypted, effectively storing it in clear text."
        Impact = @(
            "Password can be recovered in clear text from AD database"
            "Anyone with DCSync rights can extract the actual password"
            "NTDS.dit extraction reveals the password"
            "Required for some legacy protocols but severe security risk"
        )
        Attack = @(
            "1. Attacker performs DCSync or extracts NTDS.dit"
            "2. Uses DSInternals to decrypt reversibly encrypted passwords"
            "3. Obtains actual password in clear text"
            "4. Uses password for authentication or further attacks"
        )
        Remediation = @(
            "Disable 'Store password using reversible encryption' for all accounts"
            "Force password change after disabling the setting"
            "Review applications requiring this setting - find alternatives"
            "Use modern authentication protocols that don't require reversible encryption"
        )
        RemediationCommands = @(
            @{
                Description = "Disable reversible encryption for a single user account"
                Command = "Set-ADUser -Identity 'USERNAME' -AllowReversiblePasswordEncryption `$false"
            }
            @{
                Description = "Disable reversible encryption for all users in a specific OU"
                Command = "Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq `$true} -SearchBase 'OU=Users,DC=domain,DC=com' | Set-ADUser -AllowReversiblePasswordEncryption `$false"
            }
            @{
                Description = "Find all users with reversible encryption enabled"
                Command = "Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq `$true} -Properties AllowReversiblePasswordEncryption,PasswordLastSet | Select-Object Name,SamAccountName,AllowReversiblePasswordEncryption,PasswordLastSet"
            }
            @{
                Description = "Force password change after disabling (required to remove stored reversible password)"
                Command = "Set-ADUser -Identity 'USERNAME' -ChangePasswordAtLogon `$true"
            }
        )
        References = @(
            @{ Title = "Reversible Encryption Password Storage"; Url = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption" }
            @{ Title = "Extracting Reversible Passwords"; Url = "https://adsecurity.org/?p=2288" }
        )
        Tools = @("DSInternals", "Mimikatz", "Impacket")
        MITRE = "T1003.006"
        Triggers = @(
            @{ Attribute = 'userAccountControl'; Pattern = 'ENCRYPTED_TEXT_PWD_ALLOWED'; Severity = 'Finding' }
            @{ Attribute = 'reversibleEncryption'; Pattern = 'Enabled'; Severity = 'Finding' }
        )
    }

    # ============================================================================
    # GMSA / SERVICE ACCOUNT FINDINGS
    # ============================================================================

    'GMSA_PASSWORD_READABLE' = @{
        Title = "gMSA Password Retrievable"
        Risk = "Finding"
        BaseScore = 55
        Description = "The current user can read the managed password for this Group Managed Service Account. gMSA passwords are cryptographically strong but grant full access to the service account if retrieved."
        Impact = @(
            "gMSA password allows impersonation of the service account"
            "Service accounts often have elevated privileges"
            "Can access all resources the gMSA has permissions to"
            "May enable lateral movement or privilege escalation"
        )
        Attack = @(
            "1. Attacker identifies gMSA accounts they can read"
            "2. Retrieves msDS-ManagedPassword attribute"
            "3. Decodes the BLOB to obtain NT hash"
            "4. Uses hash for Pass-the-Hash or Kerberos ticket requests"
        )
        Remediation = @(
            "Review PrincipalsAllowedToRetrieveManagedPassword"
            "Restrict password retrieval to only systems that need it"
            "Use tiered administration for gMSA management"
            "Audit gMSA password retrievals"
        )
        RemediationCommands = @(
            @{
                Description = "View which principals can retrieve the gMSA password"
                Command = "Get-ADServiceAccount -Identity 'GMSA_NAME' -Properties PrincipalsAllowedToRetrieveManagedPassword | Select-Object Name,PrincipalsAllowedToRetrieveManagedPassword"
            }
            @{
                Description = "Set specific security group as the only principal allowed to retrieve gMSA password"
                Command = "Set-ADServiceAccount -Identity 'GMSA_NAME' -PrincipalsAllowedToRetrieveManagedPassword 'DOMAIN\Tier1-Servers'"
            }
            @{
                Description = "Add additional principals to retrieve gMSA password (append to existing list)"
                Command = "`$current = (Get-ADServiceAccount -Identity 'GMSA_NAME' -Properties PrincipalsAllowedToRetrieveManagedPassword).PrincipalsAllowedToRetrieveManagedPassword; `$current += Get-ADComputer 'SERVER01'; Set-ADServiceAccount -Identity 'GMSA_NAME' -PrincipalsAllowedToRetrieveManagedPassword `$current"
            }
            @{
                Description = "Find all gMSA accounts and check their retrieval permissions"
                Command = "Get-ADServiceAccount -Filter {ObjectClass -eq 'msDS-GroupManagedServiceAccount'} -Properties PrincipalsAllowedToRetrieveManagedPassword | Select-Object Name,PrincipalsAllowedToRetrieveManagedPassword"
            }
        )
        References = @(
            @{ Title = "Group Managed Service Accounts"; Url = "https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview" }
            @{ Title = "gMSA - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/golden-dmsa-gmsa.html" }
            @{ Title = "gMSA Attack Techniques"; Url = "https://adsecurity.org/?p=4367" }
            @{ Title = "Set-ADServiceAccount cmdlet"; Url = "https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adserviceaccount" }
            @{ Title = "Manage Group Managed Service Accounts"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/manage-group-managed-service-accounts" }
        )
        Tools = @("GMSAPasswordReader", "DSInternals", "Impacket")
        MITRE = "T1552"
        Triggers = @(
            @{ Attribute = 'msDS-ManagedPassword'; Severity = 'Finding' }
            @{ Attribute = 'gMSAPassword'; Severity = 'Finding' }
            @{ Attribute = 'ntHash'; Severity = 'Finding' }
            @{ Attribute = 'previousNTHash'; Severity = 'Finding' }
            # SID-based: Broad groups (Everyone, Auth Users, Domain Users) can retrieve gMSA password
            @{ Attribute = 'PrincipalsAllowedToRetrievePassword'; Custom = 'is_broad_group_sid'; Severity = 'Finding' }
        )
    }

    # ============================================================================
    # SHADOW CREDENTIALS FINDINGS
    # ============================================================================

    'SHADOW_CREDENTIALS' = @{
        Title = "Shadow Credentials (msDS-KeyCredentialLink)"
        Risk = "Finding"
        BaseScore = 60
        Description = "The msDS-KeyCredentialLink attribute contains key credentials that allow certificate-based authentication. If an attacker can write to this attribute, they can add their own key and authenticate as the target."
        Impact = @(
            "Allows certificate-based authentication without knowing the password"
            "Attacker with write access can add their own credentials"
            "Enables persistent access that survives password resets"
            "Very stealthy - no password change required"
            "Works on any Windows Server 2016+ domain"
        )
        Attack = @(
            "1. Attacker identifies target with writable msDS-KeyCredentialLink"
            "2. Generates a new key pair"
            "3. Adds their public key to the target's KeyCredentialLink"
            "4. Uses the private key for PKINIT authentication as the target"
            "5. Maintains access even after password changes"
        )
        Remediation = @(
            "Audit permissions on msDS-KeyCredentialLink attribute"
            "Remove unnecessary write access to this attribute"
            "Monitor changes to KeyCredentialLink (Event ID 5136)"
            "Review existing KeyCredentialLink entries for unexpected keys"
            "Consider using Credential Guard to protect against key theft"
        )
        RemediationCommands = @(
            @{
                Description = "View all key credentials in msDS-KeyCredentialLink for a user or computer"
                Command = "Get-ADUser -Identity 'USERNAME' -Properties msDS-KeyCredentialLink | Select-Object Name,msDS-KeyCredentialLink"
            }
            @{
                Description = "Clear all key credentials from msDS-KeyCredentialLink attribute (WARNING: Breaks Windows Hello for Business if configured)"
                Command = "Set-ADUser -Identity 'USERNAME' -Clear msDS-KeyCredentialLink"
            }
            @{
                Description = "View ACL permissions on msDS-KeyCredentialLink to identify who can write to this attribute"
                Command = "(Get-Acl 'AD:\CN=User,OU=Users,DC=domain,DC=com').Access | Where-Object {`$_.ObjectType -eq '5b47d60f-6090-40b2-9f37-2a4de88f3063'} | Format-Table IdentityReference,ActiveDirectoryRights,AccessControlType -AutoSize"
            }
            @{
                Description = "Enable auditing for changes to msDS-KeyCredentialLink (Event ID 5136 for directory service changes)"
                Command = "# In Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > DS Access > Audit Directory Service Changes = Success, Failure"
            }
        )
        References = @(
            @{ Title = "Shadow Credentials Attack"; Url = "https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab" }
            @{ Title = "Shadow Credentials - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.html" }
            @{ Title = "Key Credential Link"; Url = "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f3f01e95-6d0c-4fe6-8b43-d585167658fa" }
            @{ Title = "Exploiting and Detecting Shadow Credentials"; Url = "https://medium.com/@NightFox007/exploiting-and-detecting-shadow-credentials-and-msds-keycredentiallink-in-active-directory-9268a587d204" }
            @{ Title = "Detecting Shadow Credentials"; Url = "https://cyberstoph.org/posts/2022/03/detecting-shadow-credentials/" }
        )
        Tools = @("Whisker", "Certipy", "PyWhisker", "DSInternals")
        MITRE = "T1556.006"
        Triggers = @(
            @{ Attribute = 'msDS-KeyCredentialLink'; Severity = 'Finding' }
        )
    }

    # ============================================================================
    # TRUST RELATIONSHIP FINDINGS
    # ============================================================================

    'TRUST_SID_FILTERING_DISABLED' = @{
        Title = "SID Filtering Disabled on Trust"
        Risk = "Finding"
        BaseScore = 50
        Description = "SID Filtering is disabled on this trust relationship. This allows SID History from the trusted domain to be honored, enabling cross-trust privilege escalation attacks."
        Impact = @(
            "Attackers in trusted domain can inject privileged SIDs"
            "SID History injection enables Domain Admin access across trusts"
            "Compromising trusted domain can lead to trusting domain compromise"
            "Bypasses normal forest trust boundaries"
        )
        Attack = @(
            "1. Attacker compromises account in trusted domain"
            "2. Injects trusting domain's DA SID into their SID History"
            "3. Authenticates across trust using injected SID"
            "4. Gains Domain Admin access in trusting domain"
        )
        Remediation = @(
            "Enable SID Filtering: netdom trust /quarantine:yes"
            "Review why SID Filtering was disabled"
            "Use Selective Authentication where possible"
            "Monitor cross-trust authentication for SID History abuse"
        )
        RemediationCommands = @(
            @{
                Description = "Enable SID Filtering (quarantine) on trust"
                Command = "netdom trust TRUSTINGDOMAIN /domain:TRUSTEDDOMAIN /quarantine:yes"
            }
            @{
                Description = "Verify SID Filtering status on all trusts"
                Command = "Get-ADTrust -Filter * | Select-Object Name,Direction,SIDFilteringQuarantined,TrustType"
            }
            @{
                Description = "Enable SID Filtering using PowerShell (alternative method)"
                Command = "Set-ADTrust -Identity 'TrustedDomain' -SIDFilteringQuarantined `$true"
            }
            @{
                Description = "Disable SID Filtering only if explicitly required (use with extreme caution)"
                Command = "netdom trust TRUSTINGDOMAIN /domain:TRUSTEDDOMAIN /quarantine:no"
            }
        )
        References = @(
            @{ Title = "SID Filtering - Microsoft"; Url = "https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772633(v=ws.10)" }
            @{ Title = "Get-ADTrust cmdlet"; Url = "https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adtrust" }
            @{ Title = "SID History Injection - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/sid-history-injection.html" }
        )
        Tools = @("Mimikatz", "Rubeus")
        MITRE = "T1134.005"
        Triggers = @(
            # Order matters: specific (Custom) before general!
            # Within-forest trusts: SID Filtering disabled is by design (no tooltip, just Standard severity)
            @{ Attribute = 'isQuarantined'; Pattern = '^False$'; Custom = 'is_within_forest_trust'; Severity = 'Standard'; SeverityOnly = $true }
            # External/Forest trusts: SID Filtering disabled = security risk
            @{ Attribute = 'isQuarantined'; Pattern = '^False$'; Severity = 'Finding' }
            # Enabled = Secure (no tooltip needed, just severity coloring)
            @{ Attribute = 'isQuarantined'; Pattern = '^True$'; Severity = 'Secure'; SeverityOnly = $true }
        )
    }

    'TRUST_USES_RC4' = @{
        Title = "Trust Uses Weak RC4 Encryption"
        Risk = "Finding"
        BaseScore = 40
        Description = "This trust relationship is configured to use RC4 encryption. RC4 is cryptographically weak and vulnerable to offline brute-force attacks, similar to Kerberoasting."
        Impact = @(
            "Trust traffic can be decrypted with offline attacks"
            "Inter-realm TGTs use weak encryption keys"
            "Enables Kerberoast-style attacks on trust authentication"
            "Reduces security of cross-domain authentication"
        )
        Attack = @(
            "1. Attacker captures Kerberos traffic across trust"
            "2. Extracts RC4-encrypted inter-realm TGT"
            "3. Performs offline brute-force attack on RC4 key"
            "4. Decrypts trust traffic or forges tickets"
        )
        Remediation = @(
            "Upgrade trust to use AES encryption"
            "Ensure both domains support AES (Server 2008+)"
            "Re-create trust after AES is enabled on both sides"
            "Monitor for RC4 usage: Event ID 4769 with 0x17 encryption"
        )
        RemediationCommands = @(
            @{
                Description = "View current trust encryption types"
                Command = "Get-ADTrust -Filter * -Properties msDS-SupportedEncryptionTypes | Select-Object Name,Direction,@{Name='EncryptionTypes';Expression={`$_.'msDS-SupportedEncryptionTypes'}}"
            }
            @{
                Description = "Set trust to support AES encryption (requires trust recreation)"
                Command = "# Step 1: Delete existing trust using Active Directory Domains and Trusts GUI or: netdom trust TRUSTINGDOMAIN /domain:TRUSTEDDOMAIN /remove; Step 2: Recreate trust with AES support on both sides"
            }
            @{
                Description = "Configure domain to support AES encryption types via Group Policy"
                Command = "# In Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > 'Network security: Configure encryption types allowed for Kerberos' = Enable AES128_HMAC_SHA1, AES256_HMAC_SHA1"
            }
            @{
                Description = "Monitor for RC4 usage in Kerberos (Event ID 4769 with encryption type 0x17)"
                Command = "Get-WinEvent -FilterHashtable @{LogName='Security';ID=4769} -MaxEvents 100 | Where-Object {`$_.Message -match '0x17'} | Select-Object TimeCreated,Message | Format-Table -Wrap"
            }
        )
        References = @(
            @{ Title = "Kerberos Encryption Types - Microsoft"; Url = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos" }
            @{ Title = "RC4 Deprecation in Kerberos"; Url = "https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797" }
        )
        Tools = @("Rubeus", "Hashcat", "John the Ripper")
        MITRE = "T1558"
        Triggers = @(
            @{ Attribute = 'usesRC4'; Pattern = '^True$'; Severity = 'Finding' }
        )
    }

    'TRUST_BIDIRECTIONAL' = @{
        Title = "Bidirectional Trust Relationship"
        Risk = "Hint"
        BaseScore = 20
        Description = "This trust relationship is bidirectional, allowing authentication in both directions. While often required for functionality, this expands the attack surface compared to one-way trusts."
        Impact = @(
            "Compromise of either domain can affect the other"
            "Attack paths exist in both directions"
            "Lateral movement possible across trust boundary"
            "Increases blast radius of security incidents"
        )
        Attack = @(
            "1. Attacker compromises account in one domain"
            "2. Uses trust to access resources in partner domain"
            "3. Escalates privileges across trust boundary"
            "4. Potentially compromises both domains"
        )
        Remediation = @(
            "Review if bidirectional trust is required"
            "Consider one-way trust where possible"
            "Implement Selective Authentication to limit scope"
            "Enable SID Filtering to prevent SID History attacks"
        )
        References = @(
            @{ Title = "Trust Direction - Microsoft"; Url = "https://docs.microsoft.com/en-us/azure/active-directory-domain-services/concepts-forest-trust" }
        )
        Triggers = @(
            @{ Attribute = 'isBidirectional'; Pattern = '^True$'; Severity = 'Hint' }
        )
    }

    'TRUST_TRANSITIVE' = @{
        Title = "Transitive Trust Relationship"
        Risk = "Hint"
        BaseScore = 15
        Description = "This trust relationship is transitive, meaning trust extends to other domains that the partner trusts. This can create unintended trust paths and expand the attack surface."
        Impact = @(
            "Trust extends beyond directly connected domains"
            "May create unintended authentication paths"
            "Increases complexity of trust relationships"
            "Harder to audit all possible access paths"
        )
        Attack = @(
            "1. Attacker maps transitive trust chains"
            "2. Identifies indirect trust relationships"
            "3. Uses transitive trust to reach target domain"
            "4. Bypasses direct trust restrictions"
        )
        Remediation = @(
            "Document all transitive trust paths"
            "Consider non-transitive trusts for external partners"
            "Use Selective Authentication where possible"
            "Regularly audit trust relationships"
        )
        References = @(
            @{ Title = "Trust Transitivity - Microsoft"; Url = "https://docs.microsoft.com/en-us/azure/active-directory-domain-services/concepts-forest-trust" }
        )
        Triggers = @(
            # Within-forest trusts are always transitive by design (no special coloring)
            @{ Attribute = 'isTransitive'; Pattern = '^True$'; Custom = 'is_within_forest_trust'; Severity = 'Standard'; SeverityOnly = $true }
            @{ Attribute = 'isTransitive'; Pattern = '^True$'; Severity = 'Hint' }
        )
    }

    'TRUST_SELECTIVE_AUTH' = @{
        Title = "Selective Authentication Enabled"
        Risk = "Secure"
        BaseScore = 0
        Description = "This trust has Selective Authentication (Cross-Organization) enabled. Users from the trusted domain can only access resources they have been explicitly granted permissions to, rather than having forest-wide authentication capability."
        Impact = @(
            "Restricts cross-trust authentication to explicitly permitted resources"
            "Prevents automatic forest-wide authentication for trusted users"
            "Requires explicit access grants on each resource server"
            "Significantly reduces the attack surface of the trust"
        )
        Remediation = @(
            "No action required - this is a recommended security configuration"
            "Ensure resource-side permissions are granted correctly"
            "Document which servers have Allowed-To-Authenticate configured"
        )
        References = @(
            @{ Title = "Selective Authentication - Microsoft"; Url = "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models" }
            @{ Title = "Trust Security Recommendations"; Url = "https://adsecurity.org/?p=1640" }
        )
        Triggers = @(
            @{ Attribute = 'isCrossOrg'; Pattern = '^True$'; Severity = 'Secure' }
        )
    }

    'TRUST_TREAT_AS_EXTERNAL' = @{
        Title = "Trust Treated as External"
        Risk = "Secure"
        BaseScore = 0
        Description = "This trust is configured with the TREAT_AS_EXTERNAL flag, which enforces SID Filtering even on within-forest trusts. This provides additional security by restricting SID History usage across the trust boundary."
        Impact = @(
            "SID Filtering enforced regardless of trust type"
            "Prevents SID History injection across this trust"
            "Provides external-trust-level security on forest trusts"
            "Reduces risk of cross-domain privilege escalation"
        )
        Remediation = @(
            "No action required - this is a recommended security configuration"
            "Verify that required cross-domain functionality is not broken"
        )
        References = @(
            @{ Title = "Trust Attributes - Microsoft"; Url = "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646571e5720" }
        )
        Triggers = @(
            @{ Attribute = 'isTreatAsExternal'; Pattern = '^True$'; Severity = 'Secure' }
        )
    }

    # ============================================================================
    # OUTDATED SYSTEMS FINDINGS
    # ============================================================================

    'OUTDATED_OS' = @{
        Title = "End-of-Life Operating System"
        Risk = "Finding"
        BaseScore = 40
        Description = "This computer is running an operating system that has reached End-of-Life (EOL). EOL systems no longer receive security updates, making them vulnerable to all publicly disclosed exploits."
        Impact = @(
            "No security patches available for new vulnerabilities"
            "Known exploits exist with no fixes available"
            "Often targeted first in attacks due to guaranteed vulnerabilities"
            "May not support modern security features (Credential Guard, etc.)"
            "Compliance violations in regulated environments"
        )
        Attack = @(
            "1. Attacker identifies EOL systems in the environment"
            "2. Uses known exploits (EternalBlue, BlueKeep, etc.)"
            "3. Gains remote code execution"
            "4. Uses system as pivot point for further attacks"
        )
        Remediation = @(
            "Upgrade to supported operating system version"
            "If upgrade not possible, isolate system from network"
            "Implement compensating controls (strict firewall, monitoring)"
            "Plan migration path for legacy applications"
            "Document and accept risk if system must remain"
        )
        RemediationCommands = @(
            @{
                Description = "Identify all computers with end-of-life operating systems in the domain"
                Command = "Get-ADComputer -Filter * -Properties OperatingSystem,OperatingSystemVersion | Where-Object {`$_.OperatingSystem -match 'Windows (XP|Vista|7|8|Server 2003|Server 2008|Server 2012)'} | Select-Object Name,OperatingSystem,OperatingSystemVersion,DistinguishedName"
            }
            @{
                Description = "Check current OS version and build on local system"
                Command = "Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion,OsBuildNumber,OsHardwareAbstractionLayer"
            }
            @{
                Description = "Perform in-place upgrade to Windows Server 2025 (requires setup media)"
                Command = "# Mount Server 2025 ISO, then run: D:\setup.exe /auto upgrade /dynamicupdate enable /compat scanonly (test first), then: D:\setup.exe /auto upgrade /dynamicupdate enable (actual upgrade)"
            }
            @{
                Description = "Migrate server roles to new Windows Server using Windows Server Migration Tools"
                Command = "# On source server: Export-SmigServerSetting -Path C:\Migration -Verbose; On destination server: Import-SmigServerSetting -Path C:\Migration -SourcePhysicalAddress <MAC> -TargetPhysicalAddress <MAC> -Verbose"
            }
        )
        References = @(
            @{ Title = "Windows Lifecycle"; Url = "https://docs.microsoft.com/en-us/lifecycle/products/" }
            @{ Title = "EternalBlue (MS17-010)"; Url = "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010" }
            @{ Title = "Overview of Windows Server Upgrades"; Url = "https://learn.microsoft.com/en-us/windows-server/get-started/upgrade-overview" }
            @{ Title = "Perform an In-Place Upgrade of Windows Server"; Url = "https://learn.microsoft.com/en-us/windows-server/get-started/perform-in-place-upgrade" }
        )
        Tools = @("nmap", "Metasploit", "BlueKeep scanner")
        MITRE = "T1210"
        Triggers = @(
            @{ Attribute = 'eolDate'; Severity = 'Finding' }
            @{ Attribute = 'daysSinceEoL'; Severity = 'Finding' }
            @{ Attribute = 'operatingSystem'; Pattern = 'Windows (XP|Vista|7|8|Server 2003|Server 2008|Server 2012)'; Severity = 'Finding' }
        )
    }

    # Aging OS (Yellow/Hint) - still supported but nearing/past mainstream EOL
    'AGING_OS' = @{
        Title = "Aging Operating System"
        Risk = "Hint"
        BaseScore = 15
        Description = "This computer is running an operating system that is nearing end of extended support. While still receiving security updates (or ESU), these systems should be planned for migration before they reach EOL."
        Impact = @(
            "Windows Server 2016: Extended support ends Jan 2027 - approaching EOL"
            "Windows 10: Standard support ended Oct 2025, ESU available until Oct 2028"
            "May not support latest security features (Credential Guard enhancements, etc.)"
            "Reduced vendor support and slower security response"
        )
        Remediation = @(
            "Plan migration to current OS version (Server 2022/2025, Windows 11)"
            "Ensure Extended Security Updates (ESU) are active if available"
            "Monitor for security advisories specific to this OS version"
            "Prioritize these systems in your upgrade roadmap"
        )
        References = @(
            @{ Title = "Windows Server Lifecycle"; Url = "https://docs.microsoft.com/en-us/lifecycle/products/windows-server-2016" }
            @{ Title = "Windows 10 Lifecycle"; Url = "https://docs.microsoft.com/en-us/lifecycle/products/windows-10-enterprise-and-education" }
        )
        MITRE = "T1210"
        Triggers = @(
            @{ Attribute = 'operatingSystem'; Pattern = 'Windows 10\b|Server 2016'; Severity = 'Hint' }
        )
    }

    # ============================================================================
    # EXCHANGE FINDINGS
    # ============================================================================

    'EXCHANGE_VULNERABLE_VERSION' = @{
        Title = "Vulnerable Exchange Server Version"
        Risk = "Finding"
        BaseScore = 45
        Description = "This Exchange server is running a version with known critical vulnerabilities (ProxyLogon, ProxyShell, etc.). These vulnerabilities allow unauthenticated remote code execution."
        Impact = @(
            "Remote code execution without authentication"
            "Complete server compromise from the internet"
            "Access to all email and potentially AD compromise"
            "Often targeted by APT groups and ransomware operators"
            "Exchange often has Domain Admin-equivalent permissions"
        )
        Attack = @(
            "1. Attacker scans for vulnerable Exchange servers"
            "2. Exploits ProxyLogon/ProxyShell/ProxyNotShell"
            "3. Gains SYSTEM shell on Exchange server"
            "4. Dumps credentials or leverages Exchange permissions for AD compromise"
        )
        Remediation = @(
            "Apply all security updates immediately"
            "Run Exchange Health Checker to identify missing patches"
            "Enable Extended Protection for Authentication"
            "Restrict external access where possible"
            "Consider migration to Exchange Online"
        )
        RemediationCommands = @(
            @{
                Description = "Check current Exchange Server version and build number"
                Command = "Get-Command Exsetup.exe | ForEach-Object {`$_.FileVersionInfo}"
            }
            @{
                Description = "Download and run Exchange Server Health Checker script to identify missing patches"
                Command = "`$url='https://aka.ms/ExchangeHealthChecker'; `$path='C:\Temp\HealthChecker.ps1'; Invoke-WebRequest -Uri `$url -OutFile `$path; Set-Location C:\Temp; .\HealthChecker.ps1"
            }
            @{
                Description = "Check for latest Exchange security updates"
                Command = "# Visit https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates to identify latest CU and SU for your Exchange version"
            }
            @{
                Description = "Enable Extended Protection for Authentication (mitigates NTLM relay attacks)"
                Command = "# Run Exchange Emergency Mitigation Service (EEMS): Get-Mitigations.ps1 script from Microsoft, or manually configure via IIS Manager for each virtual directory"
            }
        )
        References = @(
            @{ Title = "Exchange Vulnerabilities Overview"; Url = "https://docs.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates" }
            @{ Title = "ProxyShell - CISA"; Url = "https://www.cisa.gov/uscert/ncas/alerts/aa21-321a" }
            @{ Title = "ProxyLogon Information"; Url = "https://proxylogon.com/" }
            @{ Title = "Microsoft Exchange ProxyNotShell Vulnerability"; Url = "https://www.csoonline.com/article/574205/microsoft-exchange-proxynotshell-vulnerability-explained-and-how-to-mitigate-it.html" }
        )
        Tools = @("Nmap", "Metasploit", "ProxyShell PoC")
        MITRE = "T1190"
        Triggers = @(
            @{ Attribute = 'ExchangeVersion'; Custom = 'is_exchange_eol'; Severity = 'Finding' }
            @{ Attribute = 'ExchangeBuildNumber'; Custom = 'is_exchange_eol'; Severity = 'Finding' }
        )
    }

    'EXCHANGE_DANGEROUS_PERMISSIONS' = @{
        Title = "Exchange with Dangerous AD Permissions"
        Risk = "Finding"
        BaseScore = 45
        Description = "Exchange security groups have dangerous permissions on Active Directory objects that can be abused for privilege escalation. Historically, Exchange had write access to all AD objects."
        Impact = @(
            "Exchange Trusted Subsystem may have DCSync rights"
            "Exchange Windows Permissions group can modify AD ACLs"
            "Compromising Exchange can lead to immediate AD compromise"
            "PrivExchange attack allows any Exchange user to escalate"
        )
        Attack = @(
            "1. Attacker with any Exchange mailbox triggers PrivExchange"
            "2. Relays Exchange's NTLM authentication to DC"
            "3. Uses Exchange's DCSync rights to dump credentials"
            "4. Or modifies AD ACLs for persistence"
        )
        Remediation = @(
            "Apply Exchange security updates"
            "Review and reduce Exchange permissions in AD"
            "Remove DCSync rights from Exchange groups"
            "Enable Extended Protection on Exchange"
            "Consider Split Permissions model"
        )
        RemediationCommands = @(
            @{
                Description = "Check Exchange permissions on the domain root (including DCSync-related rights)"
                Command = "(Get-Acl 'AD:\DC=domain,DC=com').Access | Where-Object {`$_.IdentityReference -match 'Exchange' -and (`$_.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' -or `$_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')} | Format-Table IdentityReference,ActiveDirectoryRights,ObjectType -AutoSize"
            }
            @{
                Description = "Remove DCSync rights (DS-Replication-Get-Changes) from Exchange groups"
                Command = "`$acl = Get-Acl 'AD:\DC=domain,DC=com'; `$ace = `$acl.Access | Where-Object {`$_.IdentityReference -match 'Exchange' -and `$_.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'}; `$ace | ForEach-Object {`$acl.RemoveAccessRule(`$_)}; Set-Acl -Path 'AD:\DC=domain,DC=com' -AclObject `$acl"
            }
            @{
                Description = "Configure Exchange for Active Directory Split Permissions model (prevents Exchange from modifying AD security principals)"
                Command = "# Run from Exchange installation directory: .\Setup.exe /PrepareAD /ActiveDirectorySplitPermissions:true /IAcceptExchangeServerLicenseTerms"
            }
            @{
                Description = "Review all Exchange security group permissions on domain object"
                Command = "Get-ADGroup -Filter {Name -like '*Exchange*'} | ForEach-Object { Write-Host `"Group: `$(`$_.Name)`" -ForegroundColor Yellow; (Get-Acl `"AD:`$(`$_.DistinguishedName)`").Access | Where-Object {`$_.IsInherited -eq `$false} | Format-Table IdentityReference,ActiveDirectoryRights,AccessControlType }"
            }
        )
        References = @(
            @{ Title = "PrivExchange Attack"; Url = "https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/" }
            @{ Title = "Exchange Permission Hardening"; Url = "https://learn.microsoft.com/en-us/exchange/permissions/split-permissions/split-permissions" }
            @{ Title = "Configure Exchange for Split Permissions"; Url = "https://learn.microsoft.com/en-us/exchange/permissions/split-permissions/configure-exchange-for-split-permissions" }
            @{ Title = "Mitigating Exchange Permission Paths"; Url = "https://adsecurity.org/?p=4119" }
        )
        Tools = @("PrivExchange", "ntlmrelayx", "BloodHound")
        MITRE = "T1068"
    }

    # ============================================================================
    # COMPUTER ACCOUNT FINDINGS
    # ============================================================================

    'MACHINE_QUOTA_UNRESTRICTED' = @{
        Title = "Unrestricted Machine Account Quota"
        Risk = "Hint"
        BaseScore = 15
        Description = "The ms-DS-MachineAccountQuota is greater than 0. This alone does not grant computer creation rights - it requires the SeMachineAccountPrivilege (typically granted via GPO). When both conditions are met, any authenticated user can add computer accounts that may be abused for RBCD attacks."
        Impact = @(
            "Any user can create machine accounts in the domain"
            "Machine accounts can be used for RBCD attacks"
            "Enables relay attacks requiring computer accounts"
            "Created accounts persist even if creator loses access"
        )
        Attack = @(
            "1. Attacker creates a computer account using quota"
            "2. Uses computer account for RBCD attack on target"
            "3. Impersonates any user to the target computer"
            "4. Achieves local admin on target"
        )
        Remediation = @(
            "Set ms-DS-MachineAccountQuota to 0"
            "Use dedicated groups for computer account creation"
            "Pre-stage computer accounts in AD"
            "Monitor for unexpected computer account creation"
        )
        References = @(
            @{ Title = "Machine Account Quota Abuse"; Url = "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution" }
            @{ Title = "MS-DS-MachineAccountQuota"; Url = "https://docs.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota" }
        )
        Tools = @("PowerMad", "Impacket", "SharpMad")
        MITRE = "T1136.002"
        Triggers = @(
            @{ Attribute = 'ms-DS-MachineAccountQuota'; Custom = 'gt_0'; Severity = 'Hint' }
        )
    }

    'PRE_WIN2K_COMPATIBLE_ACCESS' = @{
        Title = "Pre-Windows 2000 Compatible Access Group Has Members"
        Risk = "Finding"
        BaseScore = 35  # Excessive read access to domain
        Description = "The Pre-Windows 2000 Compatible Access group contains 'Authenticated Users' or other broad groups. This grants excessive read access to the domain, exposing sensitive information."
        Impact = @(
            "All authenticated users can read sensitive AD attributes"
            "Password hashes may be readable in certain configurations"
            "Enables reconnaissance and enumeration"
            "Legacy compatibility setting with security implications"
        )
        Attack = @(
            "1. Attacker authenticates with any domain account"
            "2. Reads attributes normally protected by ACLs"
            "3. Gathers information for further attacks"
        )
        Remediation = @(
            "Remove 'Authenticated Users' from Pre-Windows 2000 Compatible Access"
            "Add only explicitly required accounts"
            "Test application compatibility before removal"
            "Modern applications should not require this group"
        )
        RemediationCommands = @(
            @{
                Description = "View current members of Pre-Windows 2000 Compatible Access group"
                Command = "Get-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access' | Select-Object Name,SamAccountName,ObjectClass"
            }
            @{
                Description = "Remove Authenticated Users from Pre-Windows 2000 Compatible Access group"
                Command = "Remove-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access' -Members 'Authenticated Users' -Confirm:`$false"
            }
            @{
                Description = "Remove Everyone from Pre-Windows 2000 Compatible Access group (if present)"
                Command = "Remove-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access' -Members 'Everyone' -Confirm:`$false"
            }
        )
        References = @(
            @{ Title = "Pre-Windows 2000 Compatible Access"; Url = "https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups" }
        )
        Tools = @("PowerView", "ldapsearch")
        MITRE = "T1087.002"
        Triggers = @(
            @{ Attribute = 'preWin2kCompatibleAccess'; Pattern = 'Authenticated Users|Everyone|S-1-1-0|S-1-5-11'; Severity = 'Finding' }
        )
    }

    # ============================================================================
    # INACTIVE / STALE ACCOUNT FINDINGS
    # ============================================================================

    'INACTIVE_PRIVILEGED_ACCOUNT' = @{
        Title = "Inactive Privileged Account"
        Risk = "Finding"
        BaseScore = 30
        Description = "This privileged account has not been used for an extended period but remains a member of administrative groups. Inactive privileged accounts increase attack surface without providing legitimate value."
        Impact = @(
            "Unused credentials may be targeted for compromise"
            "Password may be weak or unchanged for long periods"
            "Account may have been abandoned after personnel change"
            "Provides unnecessary attack surface for privilege escalation"
        )
        Attack = @(
            "1. Attacker identifies inactive privileged accounts"
            "2. Targets these accounts for password spraying or credential stuffing"
            "3. Compromised credentials provide immediate admin access"
            "4. Attack may go unnoticed due to account inactivity"
        )
        Remediation = @(
            "Disable or remove accounts inactive for more than 90 days"
            "Remove privileged group memberships from inactive accounts"
            "Implement automated account lifecycle management"
            "Require periodic re-certification of privileged access"
            "Enable account activity monitoring and alerting"
        )
        RemediationCommands = @(
            @{
                Description = "Find all privileged accounts inactive for more than 90 days"
                Command = "`$privilegedGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators'); `$inactiveDate = (Get-Date).AddDays(-90); Get-ADUser -Filter {(Enabled -eq `$true) -and (LastLogonDate -lt `$inactiveDate)} -Properties LastLogonDate,MemberOf | Where-Object { `$_.MemberOf | Where-Object { `$privilegedGroups -contains (`$_ -replace '^CN=([^,]+).*','`$1') } } | Select-Object Name,SamAccountName,LastLogonDate,@{Name='DaysSinceLastLogon';Expression={(New-TimeSpan -Start `$_.LastLogonDate -End (Get-Date)).Days}}"
            }
            @{
                Description = "Disable inactive privileged account"
                Command = "Disable-ADAccount -Identity 'USERNAME'"
            }
            @{
                Description = "Remove privileged group membership from inactive account"
                Command = "Remove-ADGroupMember -Identity 'Domain Admins' -Members 'USERNAME' -Confirm:`$false"
            }
        )
        References = @(
            @{ Title = "Account Management Best Practices"; Url = "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory" }
        )
        Tools = @("PowerView", "ADRecon", "PingCastle")
        MITRE = "T1078.002"
        Triggers = @(
            @{ Attribute = 'daysSinceLastLogon'; Severity = 'Finding' }
        )
    }

    'ORPHANED_ADMIN_ACCOUNT' = @{
        Title = "Orphaned Admin Account (AdminCount without Membership)"
        Risk = "Hint"
        BaseScore = 30
        Description = "This account has AdminCount=1 but is no longer a member of any privileged group. These 'orphaned' accounts retain special ACL protections but may have residual permissions without active oversight."
        Impact = @(
            "Account may retain historical privileges not visible in group membership"
            "SDProp protection prevents normal ACL inheritance"
            "May have delegated permissions that persist after group removal"
            "Account management (password reset delegation) may be broken"
        )
        Attack = @(
            "1. Attacker identifies orphaned admin accounts"
            "2. These accounts may have residual permissions in AD"
            "3. May be overlooked in access reviews"
            "4. Can be used for stealthy privilege maintenance"
        )
        Remediation = @(
            "Clear AdminCount attribute on orphaned accounts"
            "Review and remove any residual permissions"
            "Run SDProp to reset ACLs to inherited defaults"
            "Implement regular audit of AdminCount vs group membership"
        )
        RemediationCommands = @(
            @{
                Description = "Find orphaned admin accounts (AdminCount=1 but not in protected groups)"
                Command = "`$protectedGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Server Operators','Print Operators','Backup Operators'); Get-ADUser -Filter {AdminCount -eq 1} -Properties MemberOf | Where-Object { -not (`$_.MemberOf | Where-Object { `$protectedGroups -contains (`$_ -replace '^CN=([^,]+).*','`$1') }) } | Select-Object SamAccountName,DistinguishedName"
            }
            @{
                Description = "Clear AdminCount attribute on orphaned account"
                Command = "Set-ADUser -Identity 'USERNAME' -Clear AdminCount"
            }
            @{
                Description = "Manually trigger SDProp to update ACLs (runs on PDC Emulator)"
                Command = "Invoke-Command -ComputerName PDC_EMULATOR -ScriptBlock { `$rootDSE = [ADSI]'LDAP://RootDSE'; `$rootDSE.Put('FixUpInheritance','1'); `$rootDSE.SetInfo() }"
            }
        )
        References = @(
            @{ Title = "AdminSDHolder and SDProp"; Url = "https://adsecurity.org/?p=1906" }
            @{ Title = "Protected Accounts and Groups - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory" }
        )
        Tools = @("PowerView", "ADACLScanner", "PingCastle")
        MITRE = "T1078.002"
        Triggers = @(
            @{ Attribute = 'isOrphaned'; Pattern = '^(True|Yes|1)$'; Severity = 'Hint' }
        )
    }

    'STALE_PASSWORD' = @{
        Title = "Stale Password (Not Changed for Extended Period)"
        Risk = "Finding"
        BaseScore = 35
        Description = "This account's password has not been changed for more than 5 years. Extremely stale passwords indicate severe password hygiene issues and significantly increase the risk of credential compromise."
        Impact = @(
            "Extremely high exposure window for brute-force or dictionary attacks"
            "Password very likely compromised or exposed over such a long period"
            "Old passwords may use severely outdated complexity requirements"
            "Service accounts with static passwords are prime targets for Kerberoasting"
            "Credentials almost certainly exist in old backups, password dumps, or breach databases"
        )
        Attack = @(
            "1. Attacker identifies accounts with very old passwords (via pwdLastSet attribute)"
            "2. Targets these accounts for password spraying with common/old passwords"
            "3. Service accounts: Kerberoasting yields hash for extended offline cracking"
            "4. Old passwords may match patterns from previous breaches"
            "5. Compromised credentials provide persistent access"
        )
        Remediation = @(
            "IMMEDIATE: Force password change for this account"
            "Implement regular password rotation policy (90-180 days for users, 30-60 days for service accounts)"
            "Use Group Managed Service Accounts (gMSA) for automatic password rotation"
            "Monitor pwdLastSet for accounts exceeding policy thresholds"
            "Enforce strong password complexity and minimum length"
            "Check compromised password lists (Have I Been Pwned, Azure AD Password Protection)"
            "Consider passwordless authentication methods (Windows Hello, FIDO2)"
        )
        RemediationCommands = @(
            @{
                Description = "Find all accounts with passwords older than 5 years"
                Command = "`$staleDate = (Get-Date).AddYears(-5); Get-ADUser -Filter {PasswordLastSet -lt `$staleDate} -Properties PasswordLastSet | Select-Object Name,SamAccountName,PasswordLastSet,@{Name='DaysSincePasswordChange';Expression={(New-TimeSpan -Start `$_.PasswordLastSet -End (Get-Date)).Days}}"
            }
            @{
                Description = "Force password change at next logon"
                Command = "Set-ADUser -Identity 'USERNAME' -ChangePasswordAtLogon `$true"
            }
            @{
                Description = "Set new random password and force change (for compromised accounts)"
                Command = "`$newPwd = [System.Web.Security.Membership]::GeneratePassword(20,5); Set-ADAccountPassword -Identity 'USERNAME' -NewPassword (ConvertTo-SecureString `$newPwd -AsPlainText -Force) -Reset; Set-ADUser -Identity 'USERNAME' -ChangePasswordAtLogon `$true"
            }
        )
        References = @(
            @{ Title = "Password Policy Best Practices - Microsoft"; Url = "https://docs.microsoft.com/en-us/microsoft-365/admin/misc/password-policy-recommendations" }
            @{ Title = "NIST Password Guidelines"; Url = "https://pages.nist.gov/800-63-3/sp800-63b.html" }
            @{ Title = "Password Age - MITRE ATT&CK"; Url = "https://attack.mitre.org/techniques/T1110/" }
        )
        Tools = @("PowerView", "ADRecon", "BloodHound", "PingCastle")
        MITRE = "T1110"
        Triggers = @(
            @{ Attribute = 'pwdLastSet'; Custom = 'pwdAge_gt_1825'; Severity = 'Finding' }
        )
    }

    'STALE_PASSWORD_MEDIUM' = @{
        Title = "Password Age Warning (Not Changed for 1-5 Years)"
        Risk = "Hint"
        BaseScore = 25
        Description = "This account's password has not been changed for 1-5 years. While not immediately critical, this indicates poor password hygiene and increases the risk of credential compromise over time."
        Impact = @(
            "Increased exposure window for brute-force or dictionary attacks"
            "Password may have been compromised without detection over time"
            "Old passwords may use weaker historical complexity requirements"
            "Service accounts with static passwords are targets for Kerberoasting"
        )
        Attack = @(
            "1. Attacker identifies accounts with old passwords (via pwdLastSet attribute)"
            "2. Targets these accounts for password spraying with common/old passwords"
            "3. Service accounts: Kerberoasting yields hash for offline cracking"
            "4. Old passwords may match patterns from previous breaches"
        )
        Remediation = @(
            "Implement regular password rotation policy (90-180 days for users, 30-60 days for service accounts)"
            "Use Group Managed Service Accounts (gMSA) for automatic password rotation"
            "Monitor pwdLastSet for accounts exceeding policy thresholds"
            "Enforce strong password complexity and minimum length"
            "Consider passwordless authentication methods (Windows Hello, FIDO2)"
        )
        References = @(
            @{ Title = "Password Policy Best Practices - Microsoft"; Url = "https://docs.microsoft.com/en-us/microsoft-365/admin/misc/password-policy-recommendations" }
            @{ Title = "NIST Password Guidelines"; Url = "https://pages.nist.gov/800-63-3/sp800-63b.html" }
        )
        Tools = @("PowerView", "ADRecon", "BloodHound", "PingCastle")
        MITRE = "T1110"
        Triggers = @(
            @{ Attribute = 'pwdLastSet'; Custom = 'pwdAge_365_1825'; Severity = 'Hint' }
        )
    }

    # ============================================================================
    # PRINT SPOOLER / COERCION FINDINGS
    # ============================================================================

    'PRINT_SPOOLER_ENABLED_DC' = @{
        Title = "Print Spooler Enabled on Domain Controller"
        Risk = "Finding"
        BaseScore = 45
        Description = "The Print Spooler service is running on a Domain Controller. This service can be abused to coerce authentication from the DC, enabling NTLM relay attacks or credential capture."
        Impact = @(
            "Enables PrinterBug/SpoolSample attack against Domain Controllers"
            "DC can be forced to authenticate to attacker-controlled server"
            "Combined with unconstrained delegation leads to DC compromise"
            "NTLM relay to LDAP/ADCS enables privilege escalation"
        )
        Attack = @(
            "1. Attacker sets up listener on compromised server"
            "2. Triggers PrinterBug/SpoolSample against DC"
            "3. DC authenticates to attacker with machine account"
            "4. Credential captured or relayed for privilege escalation"
        )
        Remediation = @(
            "Disable Print Spooler service on all Domain Controllers"
            "Use GPO to prevent service from starting"
            "Block RPC traffic to port 445 from untrusted networks"
            "Add DC machine accounts to Protected Users group"
        )
        RemediationCommands = @(
            @{
                Description = "Stop and disable Print Spooler service on Domain Controller"
                Command = "Invoke-Command -ComputerName 'DC_NAME' -ScriptBlock { Stop-Service -Name Spooler -Force; Set-Service -Name Spooler -StartupType Disabled }"
            }
            @{
                Description = "Disable Print Spooler via Group Policy on Domain Controllers OU"
                Command = "# In Group Policy Management: Create/Edit GPO linked to Domain Controllers OU > Computer Configuration > Policies > Windows Settings > Security Settings > System Services > Print Spooler > Startup Mode: Disabled"
            }
            @{
                Description = "Check Print Spooler status on all Domain Controllers"
                Command = "Get-ADDomainController -Filter * | ForEach-Object { Invoke-Command -ComputerName `$_.HostName -ScriptBlock { [PSCustomObject]@{DC=`$env:COMPUTERNAME; SpoolerStatus=(Get-Service Spooler).Status; StartType=(Get-Service Spooler).StartType} } }"
            }
            @{
                Description = "Verify Print Spooler is disabled on local Domain Controller"
                Command = "Get-Service Spooler | Select-Object Name,Status,StartType"
            }
        )
        References = @(
            @{ Title = "SpoolSample Attack"; Url = "https://github.com/leechristensen/SpoolSample" }
            @{ Title = "Printer Bug - MITRE"; Url = "https://attack.mitre.org/techniques/T1557/001/" }
            @{ Title = "Disable Print Spooler on DCs - Microsoft"; Url = "https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/identity-infrastructure" }
        )
        Tools = @("SpoolSample", "PrinterBug.py", "Rubeus", "ntlmrelayx")
        MITRE = "T1557.001"
        Triggers = @(
            @{ Attribute = 'SpoolerStatus'; Severity = 'Finding' }
            @{ Attribute = 'printSpoolerEnabled'; Severity = 'Finding' }
        )
    }

    # ============================================================================
    # WEBDAV / COERCION FINDINGS
    # ============================================================================

    'WEBDAV_COERCION_POSSIBLE' = @{
        Title = "WebDAV Client Enabled (Coercion Vector)"
        Risk = "Finding"
        BaseScore = 40
        Description = "The WebDAV client service (WebClient) is running, which can be abused to coerce NTLM authentication. This is particularly dangerous for workstations where users may click malicious links."
        Impact = @(
            "Enables authentication coercion via WebDAV requests"
            "Can be triggered by clicking links or opening Office documents"
            "NTLM authentication can be relayed to LDAP/SMB/ADCS"
            "No admin rights required to trigger the coercion"
        )
        Attack = @(
            "1. Attacker sends malicious link/document to victim"
            "2. Victim's WebDAV client authenticates to attacker's server"
            "3. NTLM credentials captured or relayed"
            "4. Attacker gains access as the victim user"
        )
        Remediation = @(
            "Disable WebClient service on servers and sensitive workstations"
            "Block outbound WebDAV traffic at the firewall"
            "Enable EPA (Extended Protection for Authentication)"
            "Require SMB signing and LDAP signing"
        )
        References = @(
            @{ Title = "WebDAV Coercion"; Url = "https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/webclient" }
            @{ Title = "WebClient Service - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-config" }
        )
        RemediationCommands = @(
            @{
                Description = "Check WebClient service status on local machine"
                Command = "Get-Service -Name WebClient -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType,DisplayName | Format-List"
            }
            @{
                Description = "Disable WebClient service on local machine"
                Command = "Stop-Service -Name WebClient -Force -ErrorAction SilentlyContinue; Set-Service -Name WebClient -StartupType Disabled"
            }
            @{
                Description = "Disable WebClient service via Group Policy (GPO)"
                Command = "# Create GPO: Computer Configuration -> Policies -> Windows Settings -> Security Settings -> System Services -> WebClient -> Set to Disabled"
            }
            @{
                Description = "Check WebClient service status on all domain computers (requires PS Remoting)"
                Command = "Get-ADComputer -Filter * | ForEach-Object { Invoke-Command -ComputerName `$_.Name -ScriptBlock { Get-Service -Name WebClient | Select-Object Name,Status,StartType } -ErrorAction SilentlyContinue } | Format-Table PSComputerName,Name,Status,StartType -AutoSize"
            }
            @{
                Description = "Disable WebClient service on all domain computers via scheduled task (GPO Immediate Task)"
                Command = "# Create GPO: Computer Configuration -> Preferences -> Control Panel Settings -> Scheduled Tasks -> New Scheduled Task (At least Windows 7) -> Action: sc.exe config WebClient start=disabled && sc.exe stop WebClient"
            }
        )
        Tools = @("PetitPotam", "Coercer", "ntlmrelayx")
        MITRE = "T1187"
        Triggers = @(
            @{ Attribute = 'WebDAVEnabled'; Severity = 'Finding' }
            @{ Attribute = 'webClientStatus'; Severity = 'Finding' }
        )
    }

    # ============================================================================
    # DNS SECURITY FINDINGS
    # ============================================================================

    'DNS_ZONE_TRANSFER_ALLOWED' = @{
        Title = "DNS Zone Transfer Allowed"
        Risk = "Hint"
        BaseScore = 30
        Description = "DNS zone transfers (AXFR) are permitted, allowing anyone to obtain a complete copy of the DNS zone. This reveals internal hostnames, IP addresses, and network topology."
        Impact = @(
            "Complete network reconnaissance without authentication"
            "Reveals all internal hostnames and IP addresses"
            "Exposes service locations and naming conventions"
            "Helps attackers map internal network structure"
        )
        Attack = @(
            "1. Attacker requests zone transfer from DNS server"
            "2. Obtains complete list of all DNS records"
            "3. Maps internal network topology"
            "4. Identifies high-value targets for further attacks"
        )
        Remediation = @(
            "Restrict zone transfers to authorized DNS servers only"
            "Configure 'Allow zone transfers: Only to servers listed on the Name Servers tab'"
            "Use DNS sec to protect zone data integrity"
            "Monitor for unauthorized zone transfer attempts"
        )
        RemediationCommands = @(
            @{
                Description = "Restrict zone transfers to only name servers listed in NS records"
                Command = "Set-DnsServerPrimaryZone -Name 'domain.com' -SecureSecondaries TransferToNameServer"
            }
            @{
                Description = "Disable zone transfers completely (if no secondary DNS servers)"
                Command = "Set-DnsServerPrimaryZone -Name 'domain.com' -SecureSecondaries NoTransfer"
            }
            @{
                Description = "Allow zone transfers only to specific IP addresses"
                Command = "Set-DnsServerPrimaryZone -Name 'domain.com' -SecureSecondaries TransferToSecureServers -SecondaryServers '192.168.1.10','192.168.1.11'"
            }
            @{
                Description = "View current zone transfer settings"
                Command = "Get-DnsServerZone -Name 'domain.com' | Select-Object ZoneName,SecureSecondaries,SecondaryServers"
            }
        )
        References = @(
            @{ Title = "Set-DnsServerPrimaryZone cmdlet"; Url = "https://learn.microsoft.com/en-us/powershell/module/dnsserver/set-dnsserverprimaryzone" }
            @{ Title = "DNS Zone Transfer Security"; Url = "https://learn.microsoft.com/en-us/windows-server/networking/dns/manage-dns-zones" }
        )
        Tools = @("dig", "nslookup", "dnsrecon", "fierce")
        MITRE = "T1590.002"
        Triggers = @(
            @{ Attribute = 'zoneTransfer'; Severity = 'Hint' }
            @{ Attribute = 'allowZoneTransfer'; Severity = 'Hint' }
        )
    }

    'ADIDNS_WILDCARD_RECORD' = @{
        Title = "ADIDNS Wildcard Record Exists"
        Risk = "Finding"
        BaseScore = 35
        Description = "A wildcard (*) DNS record exists in the Active Directory-Integrated DNS zone. This can be abused to redirect traffic for non-existent hostnames to attacker-controlled systems."
        Impact = @(
            "All unresolved DNS queries within the zone resolve to wildcard target"
            "Enables man-in-the-middle attacks"
            "Can capture NTLM authentication from systems looking up typos"
            "Useful for credential harvesting at scale"
        )
        Attack = @(
            "1. Attacker registers wildcard record pointing to their IP"
            "2. Victim systems with typos in hostnames resolve to attacker"
            "3. Attacker captures or relays authentication attempts"
            "4. Can also be used for WPAD attacks"
        )
        Remediation = @(
            "Remove unauthorized wildcard records"
            "Restrict who can create DNS records in AD"
            "Monitor for wildcard record creation"
            "Use DNSSEC where possible"
        )
        RemediationCommands = @(
            @{
                Description = "Find all wildcard DNS records in AD-Integrated zones"
                Command = "Get-DnsServerResourceRecord -ZoneName 'domain.com' | Where-Object {`$_.HostName -eq '*'} | Select-Object HostName,RecordType,RecordData"
            }
            @{
                Description = "Remove a wildcard DNS record"
                Command = "Remove-DnsServerResourceRecord -ZoneName 'domain.com' -Name '*' -RRType A -Force"
            }
            @{
                Description = "View ACL on DNS zone to identify who can create records"
                Command = "(Get-Acl 'AD:\DC=domain.com,CN=MicrosoftDNS,DC=DomainDnsZones,DC=domain,DC=com').Access | Where-Object {`$_.ActiveDirectoryRights -match 'CreateChild'} | Format-Table IdentityReference,ActiveDirectoryRights -AutoSize"
            }
            @{
                Description = "Remove DNS record create permissions for Authenticated Users"
                Command = "# Use Active Directory Sites and Services > Show Service Node (View menu) > navigate to DC=DomainDnsZones > zone object > Properties > Security > remove CreateChild for Authenticated Users"
            }
        )
        References = @(
            @{ Title = "ADIDNS Attacks"; Url = "https://www.netspi.com/blog/technical/network-penetration-testing/exploiting-adidns/" }
            @{ Title = "Remove-DnsServerResourceRecord cmdlet"; Url = "https://learn.microsoft.com/en-us/powershell/module/dnsserver/remove-dnsserverresourcerecord" }
            @{ Title = "AD-Integrated DNS Zones - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/networking/dns/zone-types#active-directory-integrated-zones" }
        )
        Tools = @("PowerMad", "Inveigh", "dnstool.py")
        MITRE = "T1557.001"
        Triggers = @(
            @{ Attribute = 'wildcardRecord'; Severity = 'Finding' }
            @{ Attribute = 'adidnsWildcard'; Severity = 'Finding' }
        )
    }

    # ============================================================================
    # NTLM SECURITY FINDINGS
    # ============================================================================

    'NTLM_NOT_RESTRICTED' = @{
        Title = "NTLM Authentication Not Restricted"
        Risk = "Finding"
        BaseScore = 30
        Description = "NTLM authentication is not restricted in the domain. NTLM is vulnerable to relay attacks and should be limited or disabled in favor of Kerberos authentication."
        Impact = @(
            "NTLM authentication subject to relay attacks"
            "Credentials can be captured and cracked offline"
            "Pass-the-Hash attacks remain effective"
            "Legacy protocol lacks modern security features"
        )
        Attack = @(
            "1. Attacker captures or relays NTLM authentication"
            "2. Relays to systems accepting NTLM"
            "3. Or cracks NTLM hashes offline"
            "4. Gains access without knowing passwords"
        )
        Remediation = @(
            "Enable NTLM auditing to identify NTLM usage"
            "Progressively restrict NTLM via GPO"
            "Configure 'Network security: Restrict NTLM' policies"
            "Block NTLM for sensitive accounts (Protected Users group)"
        )
        RemediationCommands = @(
            @{
                Description = "Enable NTLM auditing via Group Policy (Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options)"
                Command = "# Set 'Network security: Restrict NTLM: Audit NTLM authentication in this domain' = Enable all; Set 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' = Enable auditing for all accounts; Set 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' = Audit all"
            }
            @{
                Description = "View NTLM authentication events on Domain Controller (Event ID 8004 for NTLM usage)"
                Command = "Get-WinEvent -LogName 'Microsoft-Windows-NTLM/Operational' -FilterXPath '*[System[EventID=8004]]' -MaxEvents 100 | Select-Object TimeCreated,Message | Format-Table -Wrap"
            }
            @{
                Description = "Restrict NTLM authentication in domain via Group Policy"
                Command = "# In Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > 'Network security: Restrict NTLM: NTLM authentication in this domain' = Deny all OR Deny for domain accounts to domain servers"
            }
            @{
                Description = "Add privileged accounts to Protected Users group (blocks NTLM automatically)"
                Command = "Add-ADGroupMember -Identity 'Protected Users' -Members 'ADMIN_ACCOUNT'"
            }
        )
        References = @(
            @{ Title = "Network security: Restrict NTLM: Audit NTLM authentication in this domain"; Url = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-audit-ntlm-authentication-in-this-domain" }
            @{ Title = "Network security: Restrict NTLM: NTLM authentication in this domain"; Url = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-ntlm-authentication-in-this-domain" }
            @{ Title = "NTLM Relay Attacks"; Url = "https://en.hackndo.com/ntlm-relay/" }
        )
        Tools = @("ntlmrelayx", "Responder", "Inveigh")
        MITRE = "T1557.001"
        Triggers = @(
            @{ Attribute = 'NTLMEnabled'; Severity = 'Finding' }
            @{ Attribute = 'ntlmRestriction'; Severity = 'Finding' }
        )
    }

    # ============================================================================
    # PASSWORD POLICY FINDINGS
    # ============================================================================

    'WEAK_PASSWORD_POLICY' = @{
        Title = "Weak Domain Password Policy"
        Risk = "Finding"
        BaseScore = 25
        Description = "The domain password policy has weak settings that make password attacks more feasible. Short minimum lengths or missing complexity requirements allow easily guessable passwords."
        Impact = @(
            "Users can set weak, easily guessable passwords"
            "Password spraying attacks more likely to succeed"
            "Brute force attacks complete faster"
            "Compliance requirements may be violated"
        )
        Attack = @(
            "1. Attacker performs password spraying with common passwords"
            "2. Weak policy allows simple passwords like 'Summer2024'"
            "3. Multiple accounts compromised"
            "4. Attacker escalates using compromised accounts"
        )
        Remediation = @(
            "Set minimum password length to 14+ characters"
            "Enable password complexity requirements"
            "Implement password history (24+ passwords)"
            "Consider Fine-Grained Password Policies for privileged accounts"
            "Deploy Azure AD Password Protection for banned password list"
        )
        RemediationCommands = @(
            @{
                Description = "View current domain password policy"
                Command = "Get-ADDefaultDomainPasswordPolicy"
            }
            @{
                Description = "Set minimum password length to 14 characters and enable complexity"
                Command = "Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName -MinPasswordLength 14 -ComplexityEnabled `$true"
            }
            @{
                Description = "Configure password history and lockout settings"
                Command = "Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName -PasswordHistoryCount 24 -LockoutDuration 00:30:00 -LockoutObservationWindow 00:30:00 -LockoutThreshold 5"
            }
            @{
                Description = "Set all recommended password policy settings at once"
                Command = "Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName -MinPasswordLength 14 -ComplexityEnabled `$true -PasswordHistoryCount 24 -MaxPasswordAge 90.00:00:00 -MinPasswordAge 1.00:00:00 -ReversibleEncryptionEnabled `$false -LockoutThreshold 5 -LockoutDuration 00:30:00 -LockoutObservationWindow 00:30:00"
            }
        )
        References = @(
            @{ Title = "Set-ADDefaultDomainPasswordPolicy cmdlet"; Url = "https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-addefaultdomainpasswordpolicy" }
            @{ Title = "Password Policy Best Practices"; Url = "https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-password-ban-bad-on-premises" }
            @{ Title = "Password Spraying - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/password-spraying.html" }
        )
        Tools = @("NetExec", "Spray", "DomainPasswordSpray")
        MITRE = "T1110.003"
        Triggers = @(
            @{ Attribute = 'minPwdLength'; Custom = 'lt_12'; Severity = 'Finding' }
            @{ Attribute = 'passwordComplexity'; Pattern = 'Disabled'; Severity = 'Finding' }
        )
    }

    'NO_MAX_PASSWORD_AGE' = @{
        Title = "Maximum Password Age Disabled"
        Risk = "Finding"
        BaseScore = 20
        Description = "The maximum password age is disabled, meaning passwords never expire. While NIST SP 800-63B recommends against forced periodic rotation, never-expiring passwords combined with no breach detection means compromised passwords remain valid indefinitely."
        Impact = @(
            "Compromised passwords remain valid indefinitely"
            "No forced rotation after suspected breach"
            "Stale credentials accumulate over time"
            "Compliance violations (PCI-DSS, HIPAA require rotation)"
        )
        Attack = @(
            "1. Attacker obtains password through phishing or breach"
            "2. Password never expires - access persists indefinitely"
            "3. Even after detection, no automatic expiration"
            "4. Long-term persistent access maintained"
        )
        Remediation = @(
            "Set maximum password age to 365 days or less"
            "Implement breach detection and forced reset on compromise"
            "Deploy Azure AD Password Protection for leaked password detection"
            "Consider passwordless authentication (FIDO2, Windows Hello)"
        )
        RemediationCommands = @(
            @{
                Description = "View current domain password policy"
                Command = "Get-ADDefaultDomainPasswordPolicy -Identity 'domain.com' | Select-Object MaxPasswordAge,MinPasswordAge,LockoutDuration,LockoutThreshold,ComplexityEnabled"
            }
            @{
                Description = "Set maximum password age to 365 days"
                Command = "Set-ADDefaultDomainPasswordPolicy -Identity 'domain.com' -MaxPasswordAge '365.00:00:00'"
            }
            @{
                Description = "Set maximum password age to 180 days (stricter policy)"
                Command = "Set-ADDefaultDomainPasswordPolicy -Identity 'domain.com' -MaxPasswordAge '180.00:00:00'"
            }
            @{
                Description = "Set comprehensive password policy (365 days max age + complexity)"
                Command = "Set-ADDefaultDomainPasswordPolicy -Identity 'domain.com' -MaxPasswordAge '365.00:00:00' -MinPasswordAge '1.00:00:00' -MinPasswordLength 14 -ComplexityEnabled `$true -ReversibleEncryptionEnabled `$false"
            }
        )
        References = @(
            @{ Title = "Maximum Password Age Policy"; Url = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age" }
            @{ Title = "NIST SP 800-63B - Digital Identity Guidelines"; Url = "https://pages.nist.gov/800-63-3/sp800-63b.html" }
            @{ Title = "Set-ADDefaultDomainPasswordPolicy - Microsoft Learn"; Url = "https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-addefaultdomainpasswordpolicy" }
        )
        MITRE = "T1078.002"
        Triggers = @(
            @{ Attribute = 'maxPwdAge'; Pattern = 'Disabled|Never'; Severity = 'Finding' }
        )
    }

    'WEAK_LOCKOUT_DURATION' = @{
        Title = "Weak Account Lockout Duration"
        Risk = "Hint"
        BaseScore = 5
        Description = "The account lockout duration is very short, allowing locked accounts to automatically unlock quickly. This reduces the effectiveness of the lockout policy against sustained password attacks."
        Impact = @(
            "Attackers can resume password spraying after short wait"
            "Lockout provides minimal protection against persistent attacks"
            "Automated tools can pace attacks to avoid permanent lockout"
        )
        Attack = @(
            "1. Attacker triggers account lockout with failed attempts"
            "2. Waits for short lockout duration to expire"
            "3. Resumes password spraying"
            "4. Repeats cycle until password is found"
        )
        Remediation = @(
            "Set lockout duration to 30 minutes or more"
            "Consider permanent lockout (manual unlock required) for sensitive accounts"
            "Monitor for repeated lockout events"
            "Implement additional controls (MFA, conditional access)"
        )
        RemediationCommands = @(
            @{
                Description = "View current account lockout settings"
                Command = "Get-ADDefaultDomainPasswordPolicy -Identity 'domain.com' | Select-Object LockoutDuration,LockoutThreshold,LockoutObservationWindow"
            }
            @{
                Description = "Set lockout duration to 30 minutes with 5 failed attempts threshold"
                Command = "Set-ADDefaultDomainPasswordPolicy -Identity 'domain.com' -LockoutDuration '00:30:00' -LockoutThreshold 5 -LockoutObservationWindow '00:30:00'"
            }
            @{
                Description = "Set lockout duration to 60 minutes (stricter policy)"
                Command = "Set-ADDefaultDomainPasswordPolicy -Identity 'domain.com' -LockoutDuration '01:00:00' -LockoutThreshold 5 -LockoutObservationWindow '01:00:00'"
            }
            @{
                Description = "Set permanent lockout (requires manual unlock by administrator)"
                Command = "Set-ADDefaultDomainPasswordPolicy -Identity 'domain.com' -LockoutDuration '00:00:00' -LockoutThreshold 3 -LockoutObservationWindow '00:30:00'"
            }
        )
        References = @(
            @{ Title = "Account Lockout Duration Policy"; Url = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-duration" }
            @{ Title = "Set-ADDefaultDomainPasswordPolicy - Microsoft Learn"; Url = "https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-addefaultdomainpasswordpolicy" }
        )
        MITRE = "T1110.001"
        Triggers = @(
            @{ Attribute = 'lockoutDuration'; Custom = 'lt_10_minutes'; Severity = 'Hint' }
        )
    }

    'NO_ACCOUNT_LOCKOUT' = @{
        Title = "Account Lockout Policy Disabled or Weak"
        Risk = "Finding"
        BaseScore = 30
        Description = "The domain has no account lockout policy or a very weak one. This allows unlimited password guessing attempts without triggering lockouts, enabling brute force attacks."
        Impact = @(
            "Unlimited password guessing attempts possible"
            "Password spraying can be performed aggressively"
            "Brute force attacks can run indefinitely"
            "No automated response to authentication attacks"
        )
        Attack = @(
            "1. Attacker identifies accounts to target"
            "2. Performs unlimited password attempts"
            "3. No lockout triggers to slow attack"
            "4. Eventually guesses correct password"
        )
        Remediation = @(
            "Configure account lockout threshold (10-15 attempts)"
            "Set lockout duration (30+ minutes)"
            "Enable lockout counter reset (15-30 minutes)"
            "Implement additional controls (MFA, conditional access)"
            "Monitor for authentication failures"
        )
        RemediationCommands = @(
            @{
                Description = "View current account lockout policy settings"
                Command = "Get-ADDefaultDomainPasswordPolicy -Identity 'domain.com' | Select-Object LockoutDuration,LockoutThreshold,LockoutObservationWindow"
            }
            @{
                Description = "Enable account lockout policy with recommended settings (10 failed attempts, 30 minute lockout)"
                Command = "Set-ADDefaultDomainPasswordPolicy -Identity 'domain.com' -LockoutThreshold 10 -LockoutDuration '00:30:00' -LockoutObservationWindow '00:30:00'"
            }
            @{
                Description = "Enable stricter account lockout policy (5 failed attempts, 1 hour lockout)"
                Command = "Set-ADDefaultDomainPasswordPolicy -Identity 'domain.com' -LockoutThreshold 5 -LockoutDuration '01:00:00' -LockoutObservationWindow '01:00:00'"
            }
            @{
                Description = "Enable permanent lockout requiring administrator unlock (3 failed attempts)"
                Command = "Set-ADDefaultDomainPasswordPolicy -Identity 'domain.com' -LockoutThreshold 3 -LockoutDuration '00:00:00' -LockoutObservationWindow '00:15:00'"
            }
        )
        References = @(
            @{ Title = "Account Lockout Policy"; Url = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-policy" }
            @{ Title = "Set-ADDefaultDomainPasswordPolicy - Microsoft Learn"; Url = "https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-addefaultdomainpasswordpolicy" }
        )
        Tools = @("NetExec", "Spray", "Kerbrute")
        MITRE = "T1110.001"
        Triggers = @(
            @{ Attribute = 'lockoutThreshold'; Pattern = '^(0|Disabled)$'; Severity = 'Finding' }
        )
    }

    'NO_MIN_PASSWORD_AGE' = @{
        Title = "Minimum Password Age Disabled"
        Risk = "Hint"
        BaseScore = 10
        Description = "The minimum password age is set to 0 (disabled), allowing users to change their passwords immediately and repeatedly. This undermines password history enforcement because users can cycle through required password changes in rapid succession to reuse a previous password."
        Impact = @(
            "Password history policy can be bypassed by rapid cycling"
            "Users can revert to a previous favorite password"
            "Reduces effectiveness of password rotation policies"
        )
        Attack = @(
            "1. User is forced to change password"
            "2. Changes password N times in quick succession (N = history count)"
            "3. Sets password back to original"
            "4. Password history effectively circumvented"
        )
        Remediation = @(
            "Set minimum password age to at least 1 day"
            "Combine with password history (24+ passwords remembered)"
            "Consider deploying Azure AD Password Protection"
        )
        RemediationCommands = @(
            @{
                Description = "View current password age settings"
                Command = "Get-ADDefaultDomainPasswordPolicy -Identity 'domain.com' | Select-Object MinPasswordAge,MaxPasswordAge,PasswordHistoryCount"
            }
            @{
                Description = "Set minimum password age to 1 day (recommended to prevent password history bypass)"
                Command = "Set-ADDefaultDomainPasswordPolicy -Identity 'domain.com' -MinPasswordAge '1.00:00:00'"
            }
            @{
                Description = "Set minimum password age to 2 days (stricter policy)"
                Command = "Set-ADDefaultDomainPasswordPolicy -Identity 'domain.com' -MinPasswordAge '2.00:00:00'"
            }
            @{
                Description = "Configure comprehensive password policy with minimum age and history enforcement"
                Command = "Set-ADDefaultDomainPasswordPolicy -Identity 'domain.com' -MinPasswordAge '1.00:00:00' -MaxPasswordAge '365.00:00:00' -PasswordHistoryCount 24 -ComplexityEnabled `$true"
            }
        )
        References = @(
            @{ Title = "Minimum Password Age Policy"; Url = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/minimum-password-age" }
            @{ Title = "Set-ADDefaultDomainPasswordPolicy - Microsoft Learn"; Url = "https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-addefaultdomainpasswordpolicy" }
        )
        MITRE = "T1110.003"
        Triggers = @(
            @{ Attribute = 'minPwdAge'; Pattern = 'Disabled'; Severity = 'Hint' }
        )
    }

    # ============================================================================
    # ADCS ADDITIONAL FINDINGS
    # ============================================================================

    'ESC7_CA_PERMISSIONS' = @{
        Title = "ESC7 - Dangerous CA Permissions"
        Risk = "Finding"
        BaseScore = 65
        Description = "The Certificate Authority has dangerous permissions that allow non-privileged users to manage the CA. This can be abused to approve pending requests, enable vulnerable templates, or change CA configuration."
        Impact = @(
            "Attackers can approve their own certificate requests"
            "Can enable disabled vulnerable templates"
            "Can modify CA configuration settings"
            "Complete ADCS compromise possible"
        )
        Attack = @(
            "1. Attacker identifies CA management permissions"
            "2. Submits request for certificate with privileged SAN"
            "3. Approves their own pending request"
            "4. Uses certificate to authenticate as any user"
        )
        Remediation = @(
            "Audit CA permissions (ManageCA, ManageCertificates)"
            "Remove unnecessary permissions from non-admin users"
            "Only CA Admins should have ManageCA rights"
            "Monitor CA administrative actions"
        )
        RemediationCommands = @(
            @{
                Description = "Audit CA permissions using PowerShell (requires PSPKI module)"
                Command = @'
# Install PSPKI module if not present
# Install-Module -Name PSPKI -Force

# Get CA object from Active Directory
$configNC = (Get-ADRootDSE).configurationNamingContext
$caName = "CA-SERVER-NAME"  # Replace with your CA name
$caDN = "CN=$caName,CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"

# Get CA ACL
$caACL = Get-Acl -Path "AD:\$caDN"

# List all permissions
$caACL.Access | Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType | Format-Table -AutoSize

# Find dangerous permissions for non-admin users
$caACL.Access | Where-Object {
    $sid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
    $isAdmin = ($sid.Value -match '-512$|-519$') -or ($sid.Value -eq 'S-1-5-18')  # Domain/Enterprise Admins or SYSTEM

    -not $isAdmin -and (
        $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner"
    )
} | Format-Table -AutoSize
'@
            }
            @{
                Description = "Remove dangerous CA permissions from AD CA object (requires Enterprise Admin)"
                Command = @'
$configNC = (Get-ADRootDSE).configurationNamingContext
$caName = "CA-SERVER-NAME"  # Replace with your CA name
$caDN = "CN=$caName,CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"

# Get current ACL
$acl = Get-Acl -Path "AD:\$caDN"

# Remove dangerous rights for non-admin users
$acl.Access | Where-Object {
    $sid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
    # Keep only Domain Admins (512), Enterprise Admins (519), and SYSTEM
    $isAdmin = ($sid.Value -match '-512$|-519$') -or ($sid.Value -eq 'S-1-5-18')

    -not $isAdmin -and (
        $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner"
    )
} | ForEach-Object {
    $acl.RemoveAccessRule($_) | Out-Null
}

Set-Acl -Path "AD:\$caDN" -AclObject $acl
'@
            }
            @{
                Description = "Remove ManageCA and ManageCertificates rights using PSPKI (run on CA server or remotely)"
                Command = @'
# Install PSPKI module if not present
# Install-Module -Name PSPKI -Force

# Connect to CA
$ca = Get-CertificationAuthority -ComputerName "CA-SERVER-NAME"

# Get current CA ACL
$caACL = Get-CertificationAuthorityAcl -CertificationAuthority $ca

# Remove specific user/group ManageCA permission
Remove-CAAccessControlEntry -InputObject $caACL -Identity "DOMAIN\User" -AccessType Allow

# Remove specific user/group ManageCertificates permission
Remove-CAAccessControlEntry -InputObject $caACL -Identity "DOMAIN\User" -AccessType Allow

# Apply modified ACL (requires CA service restart)
$caACL | Set-CertificationAuthorityAcl -RestartCA

# Verify permissions
Get-CertificationAuthorityAcl -CertificationAuthority $ca | Format-Table -AutoSize
'@
            }
        )
        References = @(
            @{ Title = "Certified Pre-Owned - SpecterOps"; Url = "https://posts.specterops.io/certified-pre-owned-d95910965cd2" }
            @{ Title = "AD CS ESC7 - HackTricks"; Url = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.html#esc7" }
            @{ Title = "ESC7 Attack"; Url = "https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc7-dangerous-permissions-on-ca" }
            @{ Title = "CA Role-Based Administration - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts" }
        )
        Tools = @("Certify", "Certipy", "PSPKI")
        MITRE = "T1649"
        Triggers = @(
            @{ Attribute = 'ESC7'; Severity = 'Finding' }
            @{ Attribute = 'ManageCA'; Severity = 'Finding' }
            @{ Attribute = 'ManageCertificates'; Severity = 'Finding' }
        )
    }

    'ESC9_CT_NO_SECURITY_EXTENSION' = @{
        Title = "ESC9 - Certificate Template Without Security Extension"
        Risk = "Finding"
        BaseScore = 60
        Description = "The certificate template does not include the szOID_NTDS_CA_SECURITY_EXT security extension, which contains the requestor's SID. Without this, the certificate can be used by anyone who obtains it."
        Impact = @(
            "Certificates not cryptographically bound to requestor"
            "Stolen certificates can be used by anyone"
            "No SID validation during authentication"
            "Enables certificate theft attacks"
        )
        Attack = @(
            "1. Attacker obtains certificate (theft, file share, etc.)"
            "2. Certificate not bound to original requestor's SID"
            "3. Attacker uses certificate to authenticate as original user"
            "4. No way to detect that wrong user is using certificate"
        )
        Remediation = @(
            "Enable StrongCertificateBindingEnforcement on DCs"
            "Include szOID_NTDS_CA_SECURITY_EXT in certificate templates"
            "Monitor for certificate-based authentication anomalies"
        )
        RemediationCommands = @(
            @{
                Description = "Remove CT_FLAG_NO_SECURITY_EXTENSION flag from certificate template"
                Command = @'
$templateName = "VulnerableTemplate"
$configNC = (Get-ADRootDSE).configurationNamingContext
$templateDN = "CN=$templateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

# Get current enrollment flag
$template = Get-ADObject -Identity $templateDN -Properties msPKI-Enrollment-Flag
$currentFlag = $template.'msPKI-Enrollment-Flag'

# Remove CT_FLAG_NO_SECURITY_EXTENSION (0x80000)
$newFlag = $currentFlag -band (-bnot 0x80000)

# Update template
Set-ADObject -Identity $templateDN -Replace @{'msPKI-Enrollment-Flag' = $newFlag}
'@
            }
            @{
                Description = "Enable StrongCertificateBindingEnforcement on all Domain Controllers"
                Command = @'
# Set registry value on all DCs (run via GPO or remotely)
$DCs = Get-ADDomainController -Filter *
foreach ($DC in $DCs) {
    Invoke-Command -ComputerName $DC.HostName -ScriptBlock {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name 'StrongCertificateBindingEnforcement' -Value 2 -Type DWord
    }
}
'@
            }
            @{
                Description = "Verify certificate template includes szOID_NTDS_CA_SECURITY_EXT"
                Command = @'
# Check if template properly includes security extension
$templateName = "VulnerableTemplate"
$configNC = (Get-ADRootDSE).configurationNamingContext
$templateDN = "CN=$templateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
$template = Get-ADObject -Identity $templateDN -Properties msPKI-Enrollment-Flag
if (($template.'msPKI-Enrollment-Flag' -band 0x80000) -eq 0x80000) {
    Write-Host "WARNING: Template has CT_FLAG_NO_SECURITY_EXTENSION enabled" -ForegroundColor Red
} else {
    Write-Host "OK: Template will include security extension" -ForegroundColor Green
}
'@
            }
        )
        References = @(
            @{ Title = "ESC9 and ESC10"; Url = "https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-attack-paths-d34c41f59f4" }
            @{ Title = "KB5014754 - Certificate-Based Authentication Changes - Microsoft"; Url = "https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16" }
        )
        Tools = @("Certipy", "Certify")
        MITRE = "T1649"
        Triggers = @(
            @{ Attribute = 'Vulnerabilities'; Pattern = 'ESC9'; Severity = 'Finding' }
            @{ Attribute = 'NoSecurityExtension'; Pattern = '^(True|Yes)$'; Severity = 'Finding' }
        )
    }

    'ESC10_WEAK_CERTIFICATE_MAPPING' = @{
        Title = "ESC10 - Weak Certificate Mapping"
        Risk = "Finding"
        BaseScore = 60
        Description = "The domain uses weak certificate mapping that relies on UPN or DNS name in the certificate's SAN. This can be exploited if an attacker can obtain a certificate with a controlled SAN value."
        Impact = @(
            "Certificate-to-account mapping can be spoofed"
            "Enables cross-account certificate usage"
            "Weak binding allows certificate impersonation"
        )
        Attack = @(
            "1. Attacker obtains certificate with controlled SAN"
            "2. SAN contains target user's UPN"
            "3. Weak mapping allows authentication as target"
            "4. Strong binding would prevent this"
        )
        Remediation = @(
            "Enable StrongCertificateBindingEnforcement=2 (Full Enforcement)"
            "Set CertificateMappingMethods to exclude weak mappings"
            "Require szOID_NTDS_CA_SECURITY_EXT in templates"
        )
        RemediationCommands = @(
            @{
                Description = "Enable StrongCertificateBindingEnforcement (Full Enforcement) on all DCs"
                Command = @'
# Set to 2 (Full Enforcement) on all Domain Controllers
$DCs = Get-ADDomainController -Filter *
foreach ($DC in $DCs) {
    Invoke-Command -ComputerName $DC.HostName -ScriptBlock {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name 'StrongCertificateBindingEnforcement' -Value 2 -Type DWord
        Write-Host "[+] Set StrongCertificateBindingEnforcement=2 on $env:COMPUTERNAME"
    }
}
# No restart required
'@
            }
            @{
                Description = "Disable weak UPN mapping (remove 0x4 flag from CertificateMappingMethods)"
                Command = @'
# Remove UPN mapping (0x4) from Schannel certificate mapping
$DCs = Get-ADDomainController -Filter *
foreach ($DC in $DCs) {
    Invoke-Command -ComputerName $DC.HostName -ScriptBlock {
        $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel'
        $currentValue = (Get-ItemProperty -Path $regPath -Name 'CertificateMappingMethods' -ErrorAction SilentlyContinue).CertificateMappingMethods
        if ($currentValue) {
            # Remove 0x4 (UPN mapping)
            $newValue = $currentValue -band (-bnot 0x4)
            Set-ItemProperty -Path $regPath -Name 'CertificateMappingMethods' -Value $newValue -Type DWord
            Write-Host "[+] Removed weak UPN mapping on $env:COMPUTERNAME"
        }
    }
}
'@
            }
            @{
                Description = "Verify strong certificate binding configuration on DCs"
                Command = @'
# Check configuration on all DCs
$DCs = Get-ADDomainController -Filter *
foreach ($DC in $DCs) {
    Invoke-Command -ComputerName $DC.HostName -ScriptBlock {
        $kdcReg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name 'StrongCertificateBindingEnforcement' -ErrorAction SilentlyContinue
        $schannelReg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel' -Name 'CertificateMappingMethods' -ErrorAction SilentlyContinue

        Write-Host "`n$env:COMPUTERNAME Configuration:" -ForegroundColor Cyan
        Write-Host "  StrongCertificateBindingEnforcement: $($kdcReg.StrongCertificateBindingEnforcement) (Should be 2)"
        Write-Host "  CertificateMappingMethods: $($schannelReg.CertificateMappingMethods) (Should NOT include 0x4)"
    }
}
'@
            }
        )
        References = @(
            @{ Title = "KB5014754 - Certificate Mapping"; Url = "https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16" }
        )
        Tools = @("Certipy", "Certify")
        MITRE = "T1649"
        Triggers = @(
            @{ Attribute = 'StrongCertificateBindingEnforcement'; Severity = 'Finding' }
            @{ Attribute = 'CertificateMappingMethods'; Severity = 'Finding' }
        )
    }

    # ============================================================================
    # SCCM / MECM FINDINGS
    # ============================================================================

    'SCCM_CREDENTIAL_EXPOSURE' = @{
        Title = "SCCM/MECM Credential Exposure"
        Risk = "Finding"
        BaseScore = 40
        Description = "SCCM/MECM infrastructure may expose credentials through Network Access Accounts (NAA), task sequences, or collection variables. These credentials are often highly privileged."
        Impact = @(
            "Network Access Account credentials may be extractable"
            "Task sequences may contain plaintext passwords"
            "Collection variables can store sensitive data"
            "SCCM admin accounts often have broad domain access"
        )
        Attack = @(
            "1. Attacker compromises SCCM client or obtains WMI access"
            "2. Extracts NAA credentials from WMI or policy"
            "3. Decrypts credentials using DPAPI or master keys"
            "4. Uses credentials for lateral movement"
        )
        Remediation = @(
            "Use Enhanced HTTP instead of NAA where possible"
            "Store NAA credentials with minimal permissions"
            "Encrypt task sequence variables"
            "Audit SCCM for exposed credentials"
        )
        RemediationCommands = @(
            @{
                Description = "Check if Enhanced HTTP is enabled (eliminates need for Network Access Account)"
                Command = "Get-WmiObject -Namespace 'root\SMS\site_<SITECODE>' -Class SMS_SCI_SiteDefinition | Select-Object SiteName,@{Name='EnhancedHTTP';Expression={`$_.Props | Where-Object {`$_.PropertyName -eq 'EnhancedHTTP'} | Select-Object -ExpandProperty Value}} | Format-List"
            }
            @{
                Description = "Enable Enhanced HTTP via SCCM console (preferred over NAA)"
                Command = "# SCCM Console: Administration -> Site Configuration -> Sites -> Right-click site -> Properties -> Communication Security -> Check 'Use Configuration Manager-generated certificates for HTTP site systems' and 'Use PKI client certificate (client authentication capability) when available'"
            }
            @{
                Description = "List all Network Access Accounts configured in SCCM"
                Command = "Get-WmiObject -Namespace 'root\SMS\site_<SITECODE>' -Class SMS_SCI_Reserved | Where-Object {`$_.ItemName -eq 'Network Access Account'} | Select-Object SiteCode,ItemName,Value1,Value2 | Format-List"
            }
            @{
                Description = "Remove Network Access Account from SCCM (requires Enhanced HTTP to be enabled first)"
                Command = "# SCCM Console: Administration -> Site Configuration -> Sites -> Right-click site -> Configure Site Components -> Software Distribution -> Network Access Account tab -> Remove all accounts"
            }
            @{
                Description = "Audit task sequences for variables with potentially exposed credentials"
                Command = "Get-WmiObject -Namespace 'root\SMS\site_<SITECODE>' -Class SMS_TaskSequencePackage | Select-Object Name,PackageID,@{Name='Variables';Expression={(Get-WmiObject -Namespace 'root\SMS\site_<SITECODE>' -Query `"SELECT * FROM SMS_TaskSequence_Step WHERE PackageID='`$(`$_.PackageID)'`").TaskSequenceVariables}} | Where-Object {`$_.Variables -ne `$null} | Format-Table -AutoSize"
            }
            @{
                Description = "Set minimum permissions for SCCM service accounts (avoid Domain Admin)"
                Command = "# 1. Create dedicated SCCM service accounts with minimum required permissions`n# 2. Grant only necessary rights: Local Admin on SCCM servers, specific SQL permissions, no Domain Admin`n# 3. Document: https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/accounts"
            }
        )
        References = @(
            @{ Title = "SCCM Credential Recovery"; Url = "https://posts.specterops.io/sccm-hierarchy-takeover-with-high-availability-7dcbd3696b43" }
            @{ Title = "SCCM Attack Techniques"; Url = "https://posts.specterops.io/sccm-hierarchy-takeover-with-high-availability-7dcbd3696b43" }
            @{ Title = "Enhanced HTTP for MECM - Microsoft"; Url = "https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/enhanced-http" }
        )
        Tools = @("SharpSCCM", "sccmwtf", "MalSCCM")
        MITRE = "T1552.004"
    }

    'SCCM_ADMIN_HIERARCHY' = @{
        Title = "SCCM Hierarchy Takeover Risk"
        Risk = "Finding"
        BaseScore = 40
        Description = "The SCCM hierarchy configuration allows potential takeover attacks. SCCM admins can execute code on all managed systems, making SCCM a high-value target."
        Impact = @(
            "SCCM Full Administrators can execute code on all clients"
            "Hierarchy can be hijacked via various techniques"
            "Access to SCCM = Access to all managed endpoints"
            "Often includes Domain Controllers"
        )
        Attack = @(
            "1. Attacker compromises SCCM admin account"
            "2. Deploys malicious application or script to all systems"
            "3. Gains code execution on entire managed environment"
            "4. Including servers and Domain Controllers"
        )
        Remediation = @(
            "Implement SCCM role-based access control"
            "Limit Full Administrator role to minimal accounts"
            "Enable SCCM admin audit logging"
            "Separate SCCM infrastructure from domain admin access"
        )
        RemediationCommands = @(
            @{
                Description = "List all SCCM administrative users and their assigned security roles"
                Command = "Get-WmiObject -Namespace 'root\SMS\site_<SITECODE>' -Class SMS_Admin | Select-Object AdminSID,LogonName,SourceSite,@{Name='Roles';Expression={(Get-WmiObject -Namespace 'root\SMS\site_<SITECODE>' -Query `"SELECT * FROM SMS_ARole WHERE RoleID IN (SELECT RoleID FROM SMS_AdminRole WHERE AdminID='`$(`$_.AdminID)')`").RoleName}} | Format-Table -AutoSize"
            }
            @{
                Description = "View all security roles defined in SCCM"
                Command = "Get-WmiObject -Namespace 'root\SMS\site_<SITECODE>' -Class SMS_ARole | Select-Object RoleID,RoleName,RoleDescription,IsBuiltIn | Format-Table -AutoSize"
            }
            @{
                Description = "Create custom security role with limited permissions (via SCCM Console)"
                Command = "# In SCCM Console: Administration > Security > Security Roles > Create Security Role, then grant only required permissions instead of Full Administrator"
            }
            @{
                Description = "Enable audit logging for administrative actions (review SMS_StatusMessage for admin changes)"
                Command = "Get-WmiObject -Namespace 'root\SMS\site_<SITECODE>' -Query `"SELECT * FROM SMS_StatusMessage WHERE MessageType=768 AND MessageID>=30000 AND MessageID<=40000 AND Time > '`$((Get-Date).AddDays(-7).ToString('yyyyMMddHHmmss.000000+000'))' ORDER BY Time DESC`" | Select-Object MachineName,InsStrings,Time | Format-List"
            }
            @{
                Description = "Remove Full Administrator role from specific user (replace with more restrictive role)"
                Command = "# In SCCM Console: Administration > Security > Administrative Users > Select User > Properties > Security Roles tab > Remove Full Administrator > Add appropriate limited role instead"
            }
        )
        References = @(
            @{ Title = "SCCM Hierarchy Attacks"; Url = "https://posts.specterops.io/sccm-hierarchy-takeover-with-high-availability-7dcbd3696b43" }
            @{ Title = "MECM Role-Based Administration - Microsoft"; Url = "https://learn.microsoft.com/en-us/mem/configmgr/core/understand/fundamentals-of-role-based-administration" }
            @{ Title = "Configure role-based administration"; Url = "https://learn.microsoft.com/en-us/intune/configmgr/core/servers/deploy/configure/configure-role-based-administration" }
            @{ Title = "Enhanced Audit Status Message Queries"; Url = "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/enhanced-audit-status-message-queries/884897" }
        )
        Tools = @("SharpSCCM", "sccmhunter")
        MITRE = "T1072"
        Triggers = @(
            @{ Attribute = 'SCCMServer'; Severity = 'Finding' }
            @{ Attribute = 'sccmSiteServer'; Severity = 'Finding' }
        )
    }

    'SCCM_SITE_HIERARCHY' = @{
        Title = "SCCM Multi-Site Hierarchy Detected"
        Risk = "Hint"
        BaseScore = 30
        Description = "A Central Administration Site (CAS) was identified, indicating a multi-site SCCM hierarchy. CAS servers control the entire SCCM hierarchy and are Tier 0 assets."
        Impact = @(
            "CAS controls all Primary and Secondary sites in the hierarchy"
            "Compromise of CAS enables code execution across ALL sites"
            "CAS is the single point of control for the entire SCCM infrastructure"
        )
        Attack = @(
            "1. Identify CAS server via mSSMSManagementPoint site hierarchy analysis"
            "2. Target CAS admin accounts or CAS server directly"
            "3. Deploy malicious applications to all sites from CAS"
            "4. Full control of managed endpoints across entire organization"
        )
        Remediation = @(
            "Treat CAS as Tier 0 infrastructure"
            "Restrict CAS admin access to dedicated admin accounts"
            "Enable SCCM audit logging on CAS"
            "Implement network segmentation for SCCM infrastructure"
        )
        References = @(
            @{ Title = "Misconfiguration Manager"; Url = "https://github.com/subat0mik/Misconfiguration-Manager" }
            @{ Title = "SCCM Hierarchy Attacks (SpecterOps)"; Url = "https://posts.specterops.io/sccm-hierarchy-takeover-with-high-availability-7dcbd3696b43" }
            @{ Title = "MECM Site Hierarchy - Microsoft"; Url = "https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/design-a-hierarchy-of-sites" }
        )
        Tools = @("SharpSCCM", "sccmhunter", "ConfigManBearPig")
        MITRE = "T1072"
    }

    'SCCM_PXE_EXPOSURE' = @{
        Title = "PXE Boot Server Detected"
        Risk = "Hint"
        BaseScore = 25
        Description = "PXE boot servers published in Active Directory may represent an attack surface. Tools like PXEThief can extract media variables containing Network Access Account (NAA) credentials or task sequence secrets from PXE responses if not properly secured."
        Impact = @(
            "NAA credentials or task sequence secrets can be extracted from PXE boot images"
            "Captured credentials often grant network-wide access to SCCM distribution points"
            "Rogue PXE responses via DHCP spoofing enable OS deployment manipulation"
            "Boot images may contain additional embedded credentials or domain join accounts"
        )
        Attack = @(
            "1. Identify PXE servers via AD connectionPoint or intellimirrorSCP objects"
            "2. Use PXEThief to request PXE boot media from the distribution point"
            "3. Extract media variables (NAA credentials, task sequence secrets)"
            "4. Use captured credentials for lateral movement or SCCM admin access"
        )
        Remediation = @(
            "Enable PXE password protection on all distribution points"
            "Use Enhanced HTTP or HTTPS instead of NAA for client communication"
            "Implement DHCP snooping and IP Source Guard to prevent PXE spoofing"
            "Restrict PXE boot to dedicated VLANs with network access control"
            "Migrate from NAA to Enhanced HTTP (removes credential exposure entirely)"
        )
        References = @(
            @{ Title = "PXEThief - Extracting Credentials from PXE Boot"; Url = "https://www.thehacker.recipes/ad/movement/sccm-mecm/" }
            @{ Title = "Misconfiguration Manager - CRED-4 PXE Abuse"; Url = "https://github.com/subat0mik/Misconfiguration-Manager" }
            @{ Title = "PXE Boot Security for MECM - Microsoft"; Url = "https://learn.microsoft.com/en-us/mem/configmgr/osd/plan-design/security-and-privacy-for-operating-system-deployment" }
        )
        Tools = @("PXEThief", "PXEThiefy", "sccmhunter")
        MITRE = "T1557"
    }

    'SCCM_SERVICE_ACCOUNT' = @{
        Title = "SCCM Service Account with SPN"
        Risk = "Hint"
        BaseScore = 25
        Description = "User accounts with SCCM-related Service Principal Names (SMS*) were found. These accounts typically have elevated privileges in the SCCM hierarchy. Kerberoast risk is covered separately by the Kerberoasting check."
        Impact = @(
            "Service account is kerberoastable - ticket can be requested and cracked offline"
            "SCCM service accounts often have local admin rights on SCCM servers"
            "Compromised service account may enable SCCM admin access and software deployment to all clients"
            "Account may have elevated AD permissions (adminCount, delegation rights)"
        )
        Attack = @(
            "1. Request Kerberos TGS ticket for the SMS* SPN (Kerberoasting)"
            "2. Crack the ticket offline to recover the plaintext password"
            "3. Authenticate as the service account to access SCCM infrastructure"
            "4. Use SCCM admin access for domain-wide code execution via software deployment"
        )
        Remediation = @(
            "Use Group Managed Service Accounts (gMSA) instead of regular user accounts"
            "Enforce long, complex passwords (25+ characters) on service accounts"
            "Add SCCM service accounts to the Protected Users group (prevents RC4)"
            "Enable AES-only Kerberos encryption for the service account"
            "Monitor for Kerberoasting activity (Event ID 4769 with RC4 encryption)"
        )
        References = @(
            @{ Title = "Kerberoasting SCCM Service Accounts"; Url = "https://www.thehacker.recipes/ad/movement/kerberos/kerberoast" }
            @{ Title = "SCCM Attack Techniques"; Url = "https://github.com/subat0mik/Misconfiguration-Manager" }
            @{ Title = "MECM Accounts and Permissions - Microsoft"; Url = "https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/accounts" }
        )
        Tools = @("Rubeus", "Impacket", "sccmhunter")
        MITRE = "T1558.003"
    }

    # ============================================================================
    # AZURE AD / HYBRID FINDINGS
    # ============================================================================

    'AZURE_AD_CONNECT_EXPOSED' = @{
        Title = "Azure AD Connect Server Exposure"
        Risk = "Finding"
        BaseScore = 50
        Description = "The Azure AD Connect server is a Tier 0 asset that synchronizes identities between on-premises AD and Azure AD. Compromise of this server enables cloud and on-premises domain compromise."
        Impact = @(
            "Azure AD Connect service account has DCSync rights"
            "Server stores Azure AD credentials in encrypted form"
            "Compromise enables Silver Ticket to Azure AD"
            "Can extract cloud credentials and NTLM hashes"
        )
        Attack = @(
            "1. Attacker compromises Azure AD Connect server"
            "2. Extracts MSOL account credentials"
            "3. Uses DCSync rights to dump all domain hashes"
            "4. Or forges tokens for Azure AD access"
        )
        Remediation = @(
            "Treat Azure AD Connect as Tier 0 infrastructure"
            "Limit access to dedicated admin accounts"
            "Enable PTA (Pass-through Auth) instead of password sync"
            "Monitor for suspicious AAD Connect activity"
        )
        RemediationCommands = @(
            @{
                Description = "View current AD DS Connector account permissions (MSOL account)"
                Command = "Import-Module ADSync; Get-ADSyncConnectorAccount -Connector 'Contoso.com' | Select-Object UserName,PasswordNeverExpires,PasswordLastSet"
            }
            @{
                Description = "Review MSOL account DCSync permissions on domain root"
                Command = "(Get-Acl 'AD:\\DC=contoso,DC=com').Access | Where-Object {`$_.IdentityReference -like '*MSOL*' -and (`$_.ActiveDirectoryRights -match 'GenericAll|Replicating Directory Changes')} | Format-Table IdentityReference,ActiveDirectoryRights,AccessControlType -AutoSize"
            }
            @{
                Description = "Enable Entra Connect audit logging (requires 250MB-500MB log size)"
                Command = "# On Entra Connect server: wevtutil sl 'Microsoft-Windows-ADSync/Admin' /ms:524288000; # Then monitor event log: Get-WinEvent -LogName 'Microsoft-Windows-ADSync/Admin' -MaxEvents 50"
            }
            @{
                Description = "Monitor for interactive sign-ins by MSOL account (should only be non-interactive)"
                Command = "Get-ADUser -Filter {SamAccountName -like 'MSOL_*'} -Properties LastLogonDate,whenCreated | Select-Object Name,SamAccountName,LastLogonDate,whenCreated | Format-Table -AutoSize"
            }
            @{
                Description = "Audit Office 365 Unified Audit Logs for suspicious MSOL account activity"
                Command = "# In Microsoft 365 Compliance Center: Search Unified Audit Log for UserIds starting with MSOL_ with interactive logon events"
            }
            @{
                Description = "Restrict RDP and interactive access to Entra Connect server"
                Command = "# Use GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > User Rights Assignment > 'Allow log on through Remote Desktop Services' = Only specific admin accounts"
            }
        )
        References = @(
            @{ Title = "Azure AD Connect Security"; Url = "https://docs.microsoft.com/en-us/azure/active-directory/hybrid/whatis-azure-ad-connect" }
            @{ Title = "AAD Connect Attacks"; Url = "https://blog.xpnsec.com/azuread-connect-for-redteam/" }
            @{ Title = "Microsoft Entra Connect: Accounts and permissions"; Url = "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions" }
            @{ Title = "Securing Microsoft Azure AD Connect"; Url = "https://www.hub.trimarcsecurity.com/post/securing-microsoft-azure-ad-connect" }
            @{ Title = "Targeting MSOL Accounts"; Url = "https://www.tevora.com/threat-blog/targeting-msol-accounts-to-compromise-internal-networks/" }
        )
        Tools = @("AADInternals", "ROADtools", "Mimikatz")
        MITRE = "T1003.006"
        Triggers = @(
            @{ Attribute = 'entraConnectServer'; Severity = 'Finding' }
            @{ Attribute = 'entraM365Tenant'; Severity = 'Finding' }
        )
    }

    'SEAMLESS_SSO_ENABLED' = @{
        Title = "Azure AD Seamless SSO Enabled"
        Risk = "Finding"
        BaseScore = 35
        Description = "Azure AD Seamless SSO is enabled, which uses a computer account (AZUREADSSOACC) with a static Kerberos key. If this key is compromised, attackers can forge cloud authentication tickets."
        Impact = @(
            "AZUREADSSOACC computer account key enables Silver Tickets"
            "Forged tickets grant access to Azure AD resources"
            "Key remains valid until manually rotated"
            "Enables persistence across on-prem and cloud"
        )
        Attack = @(
            "1. Attacker extracts AZUREADSSOACC password hash"
            "2. Forges Kerberos ticket for Azure AD authentication"
            "3. Accesses Azure AD resources as any user"
            "4. Can maintain access even after password changes"
        )
        Remediation = @(
            "Rotate AZUREADSSOACC key every 30 days"
            "Use automated key rotation scripts"
            "Monitor AZUREADSSOACC for suspicious access"
            "Consider PHS or PTA as alternatives"
        )
        RemediationCommands = @(
            @{
                Description = "Manually rotate AZUREADSSOACC Kerberos decryption key (run on Entra Connect server)"
                Command = "Import-Module 'C:\Program Files\Microsoft Azure Active Directory Connect\AzureADSSO.psd1'; `$creds = Get-Credential; Update-AzureADSSOForest -OnPremCredentials `$creds"
            }
            @{
                Description = "View current AZUREADSSOACC account properties"
                Command = "Get-ADComputer -Filter {Name -like 'AZUREADSSOACC*'} -Properties PasswordLastSet,whenCreated,ServicePrincipalName | Select-Object Name,PasswordLastSet,whenCreated,@{Name='DaysSincePasswordChange';Expression={(New-TimeSpan -Start `$_.PasswordLastSet -End (Get-Date)).Days}},ServicePrincipalName"
            }
            @{
                Description = "Check last password change for AZUREADSSOACC (should be within 30 days)"
                Command = "Get-ADComputer 'AZUREADSSOACC$' -Properties PasswordLastSet | Select-Object Name,PasswordLastSet,@{Name='DaysOld';Expression={(New-TimeSpan -Start `$_.PasswordLastSet -End (Get-Date)).Days}}"
            }
            @{
                Description = "Monitor AZUREADSSOACC for suspicious authentication activity"
                Command = "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4768,4769; StartTime=(Get-Date).AddDays(-7)} | Where-Object {`$_.Message -match 'AZUREADSSOACC'} | Select-Object TimeCreated,Id,Message | Format-List"
            }
            @{
                Description = "Automate AZUREADSSOACC key rotation using scheduled task (create task)"
                Command = "# Create scheduled task on Entra Connect server: schtasks /create /tn 'Rotate AZUREADSSOACC Key' /tr 'powershell.exe -File C:\Scripts\Rotate-AzureADSSOKey.ps1' /sc monthly /mo 1 /ru SYSTEM"
            }
        )
        References = @(
            @{ Title = "Seamless SSO Security"; Url = "https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-sso-faq#what-are-the-security-implications-of-seamless-sso" }
            @{ Title = "Silver Ticket to Azure AD"; Url = "https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/" }
            @{ Title = "Rotate the Azure AD Seamless SSO Kerberos Key"; Url = "https://www.insentragroup.com/us/insights/geek-speak/cloud-and-modern-data-center/rotating-the-azure-ad-seamless-sso-kerberos-key-manually-part-1-of-2/" }
            @{ Title = "Roll Over Kerberos Decryption Key"; Url = "https://www.cloudcoffee.ch/microsoft-azure/azure-ad-roll-over-kerberos-decryption-key/" }
        )
        Tools = @("Impacket", "Mimikatz", "AADInternals")
        MITRE = "T1558.002"
        Triggers = @(
            @{ Attribute = 'AZUREADSSOACC'; Severity = 'Finding' }
            @{ Attribute = 'seamlessSSOEnabled'; Severity = 'Finding' }
        )
    }

    # ============================================================================
    # COMPUTER OWNERSHIP FINDINGS
    # ============================================================================

    'NON_DEFAULT_COMPUTER_OWNERS' = @{
        Title = "Computer with Non-Default Owner"
        Risk = "Hint"
        BaseScore = 40
        Description = "This computer object has a non-default owner. The owner of an AD object has implicit full control, including the ability to modify permissions. Non-default owners may indicate privilege escalation paths."
        Impact = @(
            "Object owner has implicit WriteDACL permission"
            "Owner can grant themselves any permission on the object"
            "May enable RBCD attacks if attacker owns the computer"
            "Non-standard ownership can indicate misconfiguration or compromise"
        )
        Attack = @(
            "1. Attacker identifies computer where they are owner"
            "2. Uses owner rights to grant themselves GenericAll"
            "3. Configures RBCD to impersonate any user"
            "4. Gains local admin access on target computer"
        )
        Remediation = @(
            "Review computer object owners across the domain"
            "Reset ownership to Domain Admins for critical systems"
            "Implement process to set correct owner during provisioning"
            "Monitor for ownership changes on computer objects"
        )
        References = @(
            @{ Title = "AD Object Ownership"; Url = "https://adsecurity.org/?p=1906" }
            @{ Title = "BloodHound Owns Edge"; Url = "https://bloodhound.specterops.io/resources/edges/owns" }
            @{ Title = "AD DS Object Permissions - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory" }
        )
        Tools = @("BloodHound", "PowerView", "ADACLScanner")
        MITRE = "T1222.001"
        Triggers = @(
            @{ Attribute = 'Owner'; Context = 'NonDefaultOwner'; Severity = 'Hint' }
        )
    }

    'NON_DEFAULT_USER_OWNERS' = @{
        Title = "User with Non-Default Owner"
        Risk = "Hint"
        BaseScore = 40
        Description = "This user object has a non-default owner. The owner of an AD object has implicit full control, including the ability to reset passwords and modify attributes. Non-default owners may indicate privilege escalation paths."
        Impact = @(
            "Object owner has implicit WriteDACL permission"
            "Owner can grant themselves any permission on the object"
            "Owner can reset the user's password without knowing the current one"
            "May enable privilege escalation if attacker owns a privileged user"
        )
        Attack = @(
            "1. Attacker identifies user where they are owner"
            "2. Uses owner rights to grant themselves GenericAll"
            "3. Resets target user's password"
            "4. Authenticates as target user to gain their privileges"
        )
        Remediation = @(
            "Review user object owners across the domain"
            "Reset ownership to Domain Admins for privileged accounts"
            "Implement process to set correct owner during provisioning"
            "Monitor for ownership changes on user objects"
        )
        References = @(
            @{ Title = "AD Object Ownership"; Url = "https://adsecurity.org/?p=1906" }
            @{ Title = "BloodHound Owns Edge"; Url = "https://bloodhound.specterops.io/resources/edges/owns" }
            @{ Title = "AD DS Object Permissions - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory" }
        )
        Tools = @("BloodHound", "PowerView", "ADACLScanner")
        MITRE = "T1222.001"
        Triggers = @(
            @{ Attribute = 'Owner'; Context = 'NonDefaultUserOwner'; Severity = 'Hint' }
        )
    }

    # ============================================================================
    # UNIX PASSWORD ATTRIBUTE FINDINGS
    # ============================================================================

    'READABLE_UNIX_PASSWORD_ATTRIBUTES' = @{
        Title = "Unix Password Attributes Readable"
        Risk = "Finding"
        BaseScore = 30
        Description = "This account has Unix password attributes (userPassword, unixUserPassword, sambaNTPassword, etc.) that are readable. These attributes may contain password hashes or even cleartext passwords."
        Impact = @(
            "Password hashes readable by any authenticated user"
            "May contain NTLM hashes in LM/NT format"
            "Legacy Unix integration often stores weak hashes"
            "Cleartext passwords possible in some configurations"
        )
        Attack = @(
            "1. Attacker queries AD for Unix password attributes"
            "2. Extracts password hashes from readable attributes"
            "3. Cracks hashes offline or uses Pass-the-Hash"
            "4. Gains access to accounts with populated attributes"
        )
        Remediation = @(
            "Remove unused Unix password attributes"
            "Restrict read access to these attributes via ACLs"
            "Migrate to modern authentication (Kerberos) for Unix systems"
            "Clear legacy password data from AD"
        )
        RemediationCommands = @(
            @{
                Description = "Find all users with Unix password attributes populated"
                Command = "Get-ADUser -Filter * -Properties unixUserPassword,userPassword,msSFU30Password,sambaNTPassword,sambaLMPassword | Where-Object {`$_.unixUserPassword -or `$_.userPassword -or `$_.msSFU30Password -or `$_.sambaNTPassword -or `$_.sambaLMPassword} | Select-Object Name,SamAccountName,@{Name='HasUnixPassword';Expression={[bool]`$_.unixUserPassword}},@{Name='HasUserPassword';Expression={[bool]`$_.userPassword}},@{Name='HasSFU30Password';Expression={[bool]`$_.msSFU30Password}}"
            }
            @{
                Description = "Clear Unix password attributes from a specific user"
                Command = "Set-ADUser -Identity 'USERNAME' -Clear unixUserPassword,userPassword,msSFU30Password,sambaNTPassword,sambaLMPassword"
            }
            @{
                Description = "Clear Unix password attributes from all affected users (bulk operation)"
                Command = "Get-ADUser -Filter * -Properties unixUserPassword,userPassword,msSFU30Password,sambaNTPassword,sambaLMPassword | Where-Object {`$_.unixUserPassword -or `$_.userPassword -or `$_.msSFU30Password -or `$_.sambaNTPassword -or `$_.sambaLMPassword} | ForEach-Object { Set-ADUser -Identity `$_.SamAccountName -Clear unixUserPassword,userPassword,msSFU30Password,sambaNTPassword,sambaLMPassword; Write-Host `"Cleared Unix password attributes from `$(`$_.SamAccountName)`" }"
            }
            @{
                Description = "Check ACL on confidential attributes to restrict read access (requires dsacls.exe)"
                Command = "# Use dsacls to deny read access: dsacls 'CN=Schema,CN=Configuration,DC=domain,DC=com' /D 'NT AUTHORITY\Authenticated Users:RP;userPassword'"
            }
        )
        References = @(
            @{ Title = "UNIX Attributes in AD"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory" }
            @{ Title = "Set-ADUser - Microsoft Learn"; Url = "https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-aduser" }
        )
        Tools = @("PowerView", "ldapsearch", "ADExplorer")
        MITRE = "T1552.006"
        Triggers = @(
            @{ Attribute = 'unixUserPassword'; Severity = 'Finding' }
            @{ Attribute = 'userPassword'; Severity = 'Finding' }
            @{ Attribute = 'unicodePwd'; Severity = 'Finding' }
            @{ Attribute = 'msSFU30Password'; Severity = 'Finding' }
            @{ Attribute = 'sambaNTPassword'; Severity = 'Finding' }
            @{ Attribute = 'sambaLMPassword'; Severity = 'Finding' }
        )
    }

    # ============================================================================
    # MANAGED SERVICE ACCOUNT FINDINGS
    # ============================================================================

    'STANDALONE_MSA_LEGACY' = @{
        Title = "Standalone Managed Service Account (Legacy)"
        Risk = "Hint"
        BaseScore = 20
        Description = "This domain uses standalone Managed Service Accounts (sMSA) which are less secure than Group Managed Service Accounts (gMSA). sMSAs can only be used on a single computer and have less robust password management."
        Impact = @(
            "Password management less robust than gMSA"
            "Tied to single computer - no failover capability"
            "Legacy technology with fewer security controls"
            "Should be migrated to gMSA where possible"
        )
        Attack = @(
            "1. sMSA passwords can potentially be extracted from the host"
            "2. No distributed password management like gMSA"
            "3. Compromise of host compromises sMSA"
        )
        Remediation = @(
            "Migrate sMSAs to Group Managed Service Accounts (gMSA)"
            "Implement gMSA for all new service accounts"
            "Review if sMSAs are still necessary"
            "Ensure proper ACLs on sMSA objects"
        )
        RemediationCommands = @(
            @{
                Description = "Find all standalone Managed Service Accounts (sMSA) in the domain"
                Command = "Get-ADServiceAccount -Filter {ObjectClass -eq 'msDS-ManagedServiceAccount'} -Properties ObjectClass | Where-Object {`$_.ObjectClass -notcontains 'msDS-GroupManagedServiceAccount'} | Select-Object Name,SamAccountName,DistinguishedName,Enabled"
            }
            @{
                Description = "Create KDS Root Key (required for gMSA, one-time setup per forest)"
                Command = "# For production (10 hour wait): Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)); # For testing (immediate): Add-KdsRootKey -EffectiveImmediately"
            }
            @{
                Description = "Create security group for gMSA password retrieval authorization"
                Command = "New-ADGroup -Name 'gMSA-ServiceServers' -GroupScope Global -GroupCategory Security -Path 'OU=Groups,DC=domain,DC=com' -Description 'Servers authorized to retrieve gMSA passwords'"
            }
            @{
                Description = "Create new Group Managed Service Account (gMSA)"
                Command = "New-ADServiceAccount -Name 'gMSA_ServiceName' -DNSHostName 'gMSA_ServiceName.domain.com' -PrincipalsAllowedToRetrieveManagedPassword 'gMSA-ServiceServers' -ManagedPasswordIntervalInDays 30"
            }
            @{
                Description = "Verify gMSA creation and test password retrieval on target server"
                Command = "# On Domain Controller: Get-ADServiceAccount -Identity 'gMSA_ServiceName' -Properties *; # On target server: Test-ADServiceAccount -Identity 'gMSA_ServiceName'"
            }
        )
        References = @(
            @{ Title = "Group Managed Service Accounts Overview"; Url = "https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview" }
            @{ Title = "Manage Group Managed Service Accounts - Microsoft Learn"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/manage-group-managed-service-accounts" }
        )
        Tools = @("PowerShell AD Module", "PowerView")
        MITRE = "T1078.002"
        Triggers = @(
            @{ Attribute = 'objectClass'; Pattern = 'msDS-ManagedServiceAccount'; ExcludePattern = 'msDS-GroupManagedServiceAccount'; Severity = 'Hint' }
        )
    }

    # ============================================================================
    # GPO SCHEDULED TASK FINDINGS
    # ============================================================================

    'GPO_TASK_SYSTEM_UNC_PATH' = @{
        Title = "GPO Scheduled Task Runs as SYSTEM from UNC Path"
        Risk = "Finding"
        BaseScore = 45
        Description = "A GPO-deployed scheduled task runs as SYSTEM and executes from a UNC network path. If the UNC path is writable, attackers can replace the executable to gain SYSTEM access on all affected computers."
        Impact = @(
            "Task runs with SYSTEM privileges"
            "Executable loaded from network share"
            "Writable share = code execution as SYSTEM"
            "Affects all computers where GPO is applied"
        )
        Attack = @(
            "1. Attacker identifies writable UNC path in task"
            "2. Replaces executable with malicious payload"
            "3. Task executes payload as SYSTEM on all affected hosts"
            "4. Gains SYSTEM access on multiple computers"
        )
        Remediation = @(
            "Use local paths for SYSTEM-context tasks"
            "Ensure UNC paths are only writable by admins"
            "Implement code signing for scheduled task executables"
            "Review all GPO scheduled tasks for security"
        )
        RemediationCommands = @(
            @{
                Description = "Review all scheduled tasks in GPO to identify UNC paths"
                Command = "Get-GPO -All | ForEach-Object { `$gpo = `$_; [xml]`$report = Get-GPOReport -Guid `$gpo.Id -ReportType Xml; `$tasks = `$report.GPO.Computer.ExtensionData | Where-Object {`$_.Name -eq 'Scheduled Tasks'}; if (`$tasks) { Write-Host `"GPO: `$(`$gpo.DisplayName)`"; `$tasks.Extension.ScheduledTasks.Task | Where-Object {`$_.Properties.Command -match '^\\\\\\\\' -or `$_.Properties.Arguments -match '^\\\\\\\\'}  | Select-Object @{Name='TaskName';Expression={`$_.Name}},@{Name='Command';Expression={`$_.Properties.Command}},@{Name='Arguments';Expression={`$_.Properties.Arguments}} } }"
            }
            @{
                Description = "Check NTFS permissions on UNC path to verify only admins have write access"
                Command = "Get-Acl '\\\\server\\share\\path' | Select-Object -ExpandProperty Access | Where-Object {`$_.FileSystemRights -match 'Write|Modify|FullControl' -and `$_.IdentityReference -notmatch 'BUILTIN\\\\Administrators|NT AUTHORITY\\\\SYSTEM'} | Format-Table IdentityReference,FileSystemRights,AccessControlType -AutoSize"
            }
            @{
                Description = "Restrict write access on UNC share to Administrators only"
                Command = "`$acl = Get-Acl '\\\\server\\share\\path'; `$rule = New-Object System.Security.AccessControl.FileSystemAccessRule('Domain Users','Write','Deny'); `$acl.SetAccessRule(`$rule); Set-Acl -Path '\\\\server\\share\\path' -AclObject `$acl"
            }
            @{
                Description = "Modify GPO scheduled task to use local path instead of UNC (requires Group Policy Editor or XML editing)"
                Command = "# Edit GPO via Group Policy Management Console: Computer Configuration > Preferences > Control Panel Settings > Scheduled Tasks > [Task] > Edit Actions > Change path from UNC to local (e.g., C:\Scripts\script.ps1)"
            }
        )
        References = @(
            @{ Title = "GPO Abuse"; Url = "https://wald0.com/?p=179" }
            @{ Title = "Scheduled Tasks via Group Policy - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page" }
            @{ Title = "Get-GPPermission - Microsoft Learn"; Url = "https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gppermission" }
        )
        Tools = @("SharpGPOAbuse", "PowerView", "GPO analysis")
        MITRE = "T1053.005"
        Triggers = @(
            @{ Attribute = 'scheduledTasks'; Severity = 'Finding' }
            @{ Attribute = 'taskPath'; Severity = 'Finding' }
        )
    }

    'GPO_TASK_UNQUOTED_PATH' = @{
        Title = "GPO Scheduled Task with Unquoted Path"
        Risk = "Finding"
        BaseScore = 40
        Description = "A GPO-deployed scheduled task has an unquoted executable path containing spaces. This can be exploited for privilege escalation via path injection."
        Impact = @(
            "Unquoted path with spaces enables injection"
            "Attacker can place executable in parent directory"
            "Task will execute attacker's binary instead"
            "Leads to privilege escalation"
        )
        Attack = @(
            "1. Task path: C:\\Program Files\\App Folder\\task.exe"
            "2. Attacker places C:\\Program.exe"
            "3. Windows executes C:\\Program.exe instead"
            "4. Attacker code runs with task privileges"
        )
        Remediation = @(
            "Quote all paths with spaces in scheduled tasks"
            "Audit GPO scheduled tasks for unquoted paths"
            "Restrict write access to root of drives"
        )
        RemediationCommands = @(
            @{
                Description = "Find all GPO scheduled tasks with paths containing spaces (check manually for missing quotes)"
                Command = "Get-GPO -All | ForEach-Object { `$gpo = `$_; [xml]`$report = Get-GPOReport -Guid `$gpo.Id -ReportType Xml; `$tasks = `$report.GPO.Computer.ExtensionData | Where-Object {`$_.Name -eq 'Scheduled Tasks'}; if (`$tasks) { `$tasks.Extension.ScheduledTasks.Task | Where-Object {`$_.Properties.Command -match ' '} | Select-Object @{Name='GPO';Expression={`$gpo.DisplayName}},@{Name='TaskName';Expression={`$_.Name}},@{Name='Path';Expression={`$_.Properties.Command}} } }"
            }
            @{
                Description = "Check write permissions on C:\\ drive root to prevent C:\\Program.exe injection"
                Command = "Get-Acl 'C:\\' | Select-Object -ExpandProperty Access | Where-Object {`$_.FileSystemRights -match 'Write|Modify|FullControl' -and `$_.IdentityReference -notmatch 'BUILTIN\\\\Administrators|NT AUTHORITY\\\\SYSTEM'} | Format-Table IdentityReference,FileSystemRights,AccessControlType -AutoSize"
            }
            @{
                Description = "Check write permissions on Program Files directory"
                Command = "Get-Acl 'C:\\Program Files' | Select-Object -ExpandProperty Access | Where-Object {`$_.FileSystemRights -match 'Write|Modify|FullControl' -and `$_.IdentityReference -notmatch 'BUILTIN\\\\Administrators|NT AUTHORITY\\\\SYSTEM|TrustedInstaller'} | Format-Table IdentityReference,FileSystemRights,AccessControlType -AutoSize"
            }
            @{
                Description = "Modify GPO scheduled task to add quotes around path (requires Group Policy Editor)"
                Command = "# Edit GPO via Group Policy Management Console: Computer Configuration > Preferences > Control Panel Settings > Scheduled Tasks > [Task] > Edit Actions > Wrap executable path in double quotes to prevent path injection"
            }
        )
        References = @(
            @{ Title = "Unquoted Service Paths"; Url = "https://attack.mitre.org/techniques/T1574/009/" }
            @{ Title = "CreateProcess and Path Handling - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw" }
        )
        Tools = @("PowerSploit", "SharpUp", "GPO analysis")
        MITRE = "T1574.009"
    }

    # ============================================================================
    # GPO LOCAL GROUP MEMBERSHIP FINDINGS
    # ============================================================================

    'GPO_RESTRICTED_GROUPS_DANGEROUS' = @{
        Title = "Restricted Groups GPO Modifies Local Admins"
        Risk = "Finding"
        BaseScore = 45
        Description = "A GPO uses Restricted Groups to modify local Administrators or other privileged local groups. While this can be legitimate, misconfigurations can lead to privilege escalation."
        Impact = @(
            "Defines who is in local Administrators group"
            "Applies to all computers where GPO is linked"
            "Incorrect configuration grants admin access"
            "May add unintended principals to admin groups"
        )
        Attack = @(
            "1. Attacker identifies GPO managing Restricted Groups"
            "2. If GPO is writable, modifies group membership"
            "3. Adds attacker-controlled account to Administrators"
            "4. Gains local admin on all affected computers"
        )
        Remediation = @(
            "Audit Restricted Groups GPO configurations"
            "Ensure only intended accounts are granted admin"
            "Protect GPOs with proper ACLs"
            "Monitor for GPO modifications"
        )
        RemediationCommands = @(
            @{
                Description = "Find all GPOs with Restricted Groups configured"
                Command = "Get-GPO -All | ForEach-Object { `$gpo = `$_; [xml]`$report = Get-GPOReport -Guid `$gpo.Id -ReportType Xml; `$restricted = `$report.GPO.Computer.ExtensionData.Extension.RestrictedGroups; if (`$restricted) { [PSCustomObject]@{ GPOName = `$gpo.DisplayName; RestrictedGroups = (`$restricted.RestrictedGroup.GroupName.Name.'#text' -join ', '); Members = (`$restricted.RestrictedGroup.Member.Name.'#text' -join ', ') } } }"
            }
            @{
                Description = "Review specific GPO Restricted Groups configuration in detail"
                Command = "[xml]`$report = Get-GPOReport -Name 'GPO_NAME' -ReportType Xml; `$report.GPO.Computer.ExtensionData.Extension.RestrictedGroups.RestrictedGroup | Select-Object @{Name='GroupName';Expression={`$_.GroupName.Name.'#text'}},@{Name='Members';Expression={(`$_.Member.Name.'#text' -join '; ')}}"
            }
            @{
                Description = "Check GPO permissions to ensure only authorized admins can modify it"
                Command = "Get-GPPermission -Name 'GPO_NAME' -All | Where-Object {`$_.Permission -match 'GpoEdit|GpoEditDeleteModifySecurity'} | Select-Object Trustee,Permission,Inherited | Format-Table -AutoSize"
            }
            @{
                Description = "Set GPO permissions to deny GpoEdit for unauthorized users"
                Command = "Set-GPPermission -Name 'GPO_NAME' -TargetName 'DOMAIN\\UnauthorizedUser' -TargetType User -PermissionLevel None"
            }
            @{
                Description = "Enable auditing for GPO modifications (Event ID 5136 in Security log)"
                Command = "# Configure via Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy > DS Access > Audit Directory Service Changes = Success, Failure"
            }
        )
        References = @(
            @{ Title = "Restricted Groups"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-f--securing-domain-admins-groups-in-active-directory" }
            @{ Title = "Get-GPOReport - Microsoft Learn"; Url = "https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gporeport" }
        )
        Tools = @("GPO analysis", "PowerView", "BloodHound")
        MITRE = "T1484.001"
        Triggers = @(
            @{ Attribute = 'restrictedGroups'; Severity = 'Finding' }
        )
    }

    # ============================================================================
    # ESC15 - NEW ADCS VARIANT
    # ============================================================================

    'ESC15_SCHEMA_V1_ENROLLEE_SUBJECT' = @{
        Title = "ESC15 - Schema v1 Template with Enrollee-Supplied Subject"
        Risk = "Hint"
        BaseScore = 30
        Description = "This certificate template uses Schema Version 1 and allows the enrollee to supply the subject name. Schema v1 templates lack the szOID_NTDS_CA_SECURITY_EXT extension, so issued certificates are not bound to the requestor's SID. Microsoft patched this as CVE-2024-49019 in November 2024 - on unpatched CAs, this remains exploitable for domain privilege escalation. Even on patched systems, Schema v1 templates are a certificate hygiene concern and should be replaced with v2+ templates."
        Impact = @(
            "Unpatched CA: Enrollee can inject arbitrary Application Policies (EKUwu attack)"
            "Schema v1 templates lack szOID_NTDS_CA_SECURITY_EXT (no SID binding)"
            "Certificate not bound to requestor - usable by anyone who obtains it"
            "Patched CA: Direct exploitation blocked, but v1 templates remain less controllable than v2+"
        )
        Attack = @(
            "1. Attacker enrolls using vulnerable v1 template on unpatched CA"
            "2. Injects Client Authentication EKU via Application Policies"
            "3. Specifies Domain Admin UPN in Subject Alternative Name"
            "4. Obtains certificate without SID binding"
            "5. Authenticates as Domain Admin via PKINIT"
        )
        Remediation = @(
            "Apply CVE-2024-49019 patch (November 2024 Patch Tuesday)"
            "Replace Schema v1 templates with v2+ duplicates"
            "Unpublish default v1 templates that are no longer needed"
            "Remove ENROLLEE_SUPPLIES_SUBJECT if not required"
            "Require CA Manager approval for subject requests"
            "Disable Application Policies extension: certutil -setreg policy\DisableExtensionList +1.3.6.1.4.1.311.21.10"
        )
        RemediationCommands = @(
            @{
                Description = "Duplicate Schema v1 template to v2+ (GUI method - run on CA or admin workstation)"
                Command = @'
# 1. Open Certificate Templates MMC (certtmpl.msc)
# 2. Right-click the vulnerable v1 template and select "Duplicate Template"
# 3. In the "Compatibility" tab, ensure Windows Server 2008 R2 or later (creates v2+)
# 4. In the "Subject Name" tab, select "Build from this Active Directory information"
# 5. Configure other settings as needed
# 6. Save the new template
# 7. Publish the new template on the CA
# 8. Unpublish the old v1 template

Write-Host "[!] This is a manual process requiring the Certificate Templates MMC" -ForegroundColor Yellow
'@
            }
            @{
                Description = "Unpublish vulnerable v1 template from CA"
                Command = @'
# Run on CA server
$templateName = "VulnerableV1Template"
certutil -deltemplate "$templateName"

# Or via PowerShell (requires RSAT-ADCS-Mgmt)
$caName = "$env:COMPUTERNAME\$((certutil -dump | Select-String 'Config:' | ForEach-Object { ($_ -split '\\')[-1].Trim() }))"
Remove-CATemplate -Name "$templateName" -Force
'@
            }
            @{
                Description = "Disable Application Policies extension on CA (prevents EKUwu attack)"
                Command = @'
# Run on CA server to block arbitrary Application Policy injection
certutil -setreg policy\DisableExtensionList +1.3.6.1.4.1.311.21.10

# Restart Certificate Services
net stop certsvc && net start certsvc

# Verify setting
certutil -getreg policy\DisableExtensionList
'@
            }
        )
        References = @(
            @{ Title = "TrustedSec - EKUwu (ESC15)"; Url = "https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc" }
            @{ Title = "CVE-2024-49019 - Microsoft"; Url = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49019" }
            @{ Title = "Microsoft Defender for Identity - ESC15"; Url = "https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates" }
        )
        Tools = @("Certipy", "Certify", "PSPKI")
        MITRE = "T1649"
        Triggers = @(
            @{ Attribute = 'Vulnerabilities'; Pattern = 'ESC15'; Severity = 'Hint' }
            @{ Attribute = 'SchemaVersion'; Pattern = '^1$'; Severity = 'Hint' }
        )
    }

    # ============================================================================
    # ESC13 - ISSUANCE POLICY GROUP LINK
    # ============================================================================

    'ESC13_ISSUANCE_POLICY_GROUP_LINK' = @{
        Title = "ESC13 - Issuance Policy Linked to AD Group"
        Risk = "Finding"
        BaseScore = 70
        Description = "A certificate template references an issuance policy OID that is linked to an AD group via the msDS-OIDToGroupLink attribute. When a user enrolls in this template, the resulting certificate grants automatic membership in the linked group. This can be abused for privilege escalation if non-privileged users can enroll."
        Impact = @(
            "Attacker enrolls in the template and gains membership in the linked AD group"
            "If the linked group is privileged, this directly escalates privileges"
            "Certificate-based group membership bypasses traditional group management controls"
            "The group membership is granted automatically upon certificate issuance"
        )
        Remediation = @(
            "Remove the msDS-OIDToGroupLink attribute from the issuance policy OID object"
            "Remove the issuance policy from the template's msPKI-Certificate-Policy attribute"
            "Restrict enrollment permissions to privileged users only"
            "Review which groups are linked to issuance policies and assess the security impact"
        )
        RemediationCommands = @(
            @{
                Description = "Remove msDS-OIDToGroupLink attribute from issuance policy OID"
                Command = @'
# Find OID objects with group links
$configNC = (Get-ADRootDSE).configurationNamingContext
$oidContainer = "CN=OID,CN=Public Key Services,CN=Services,$configNC"
$linkedOIDs = Get-ADObject -SearchBase $oidContainer -Filter {msDS-OIDToGroupLink -like "*"} -Properties msDS-OIDToGroupLink,displayName

foreach ($oid in $linkedOIDs) {
    Write-Host "[!] OID: $($oid.displayName) linked to: $($oid.'msDS-OIDToGroupLink')" -ForegroundColor Yellow
    # Remove the link
    Set-ADObject -Identity $oid.DistinguishedName -Clear msDS-OIDToGroupLink
    Write-Host "[+] Removed group link from OID: $($oid.displayName)" -ForegroundColor Green
}
'@
            }
            @{
                Description = "Remove issuance policy from vulnerable certificate template"
                Command = @'
$templateName = "VulnerableTemplate"
$configNC = (Get-ADRootDSE).configurationNamingContext
$templateDN = "CN=$templateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

# Get current policies
$template = Get-ADObject -Identity $templateDN -Properties msPKI-Certificate-Policy
Write-Host "[!] Current policies: $($template.'msPKI-Certificate-Policy')" -ForegroundColor Yellow

# Remove all policies (or selectively remove specific OID)
Set-ADObject -Identity $templateDN -Clear msPKI-Certificate-Policy
Write-Host "[+] Removed issuance policies from template" -ForegroundColor Green
'@
            }
            @{
                Description = "List all OID-to-Group links in the environment"
                Command = @'
# Audit all OID-to-Group links
$configNC = (Get-ADRootDSE).configurationNamingContext
$oidContainer = "CN=OID,CN=Public Key Services,CN=Services,$configNC"
$linkedOIDs = Get-ADObject -SearchBase $oidContainer -Filter {msDS-OIDToGroupLink -like "*"} -Properties msDS-OIDToGroupLink,displayName,msPKI-Cert-Template-OID

foreach ($oid in $linkedOIDs) {
    $groupDN = $oid.'msDS-OIDToGroupLink'
    $group = Get-ADGroup -Identity $groupDN -Properties Name,Description
    Write-Host "`nOID: $($oid.displayName)" -ForegroundColor Cyan
    Write-Host "  OID Value: $($oid.'msPKI-Cert-Template-OID')"
    Write-Host "  Linked Group: $($group.Name)"
    Write-Host "  Group DN: $groupDN"
}
'@
            }
        )
        References = @(
            @{ Title = "ESC13 - ADCS Abuse Technique"; Url = "https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53" }
            @{ Title = "Certified Pre-Owned - SpecterOps"; Url = "https://posts.specterops.io/certified-pre-owned-d95910965cd2" }
            @{ Title = "Issuance Policies and OID Group Links - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts" }
        )
        Tools = @("Certipy", "Certify", "BloodHound")
        MITRE = "T1649"
        Triggers = @(
            @{ Attribute = 'Vulnerabilities'; Pattern = 'ESC13'; Severity = 'Finding' }
            @{ Attribute = 'IssuancePolicyGroupLinks'; Pattern = '.'; Severity = 'Finding' }
        )
    }

    # ============================================================================
    # CA CERTIFICATE SECURITY FINDINGS
    # ============================================================================

    'ADCS_CA_WEAK_SIGNATURE' = @{
        Title = "CA Certificate Uses Weak Signature Algorithm"
        Risk = "Finding"
        BaseScore = 50
        Description = "The Certificate Authority's signing certificate uses a weak or deprecated signature algorithm (SHA-1, MD5, or MD2). Certificates signed with weak algorithms are vulnerable to collision attacks, potentially allowing attackers to forge certificates."
        Impact = @(
            "Weak hash algorithms are susceptible to collision attacks"
            "Forged certificates could be created that appear valid"
            "Modern security policies and browsers reject SHA-1 signed certificates"
        )
        Remediation = @(
            "Renew the CA certificate with SHA-256 or stronger signature algorithm"
            "Plan CA migration if the current CA does not support modern algorithms"
            "Verify all issued certificates also use strong signature algorithms"
        )
        RemediationCommands = @(
            @{
                Description = "Configure CA to use SHA-256 hash algorithm"
                Command = "certutil -setreg ca\csp\CNGHashAlgorithm SHA256"
            }
            @{
                Description = "Restart Certificate Services to apply changes"
                Command = "Restart-Service -Name CertSvc"
            }
            @{
                Description = "Verify current hash algorithm configuration"
                Command = "certutil -getreg ca\csp\CNGHashAlgorithm"
            }
        )
        References = @(
            @{ Title = "SHA-1 Deprecation - Microsoft"; Url = "https://techcommunity.microsoft.com/t5/windows-it-pro-blog/sha-1-windows-content-signing-is-ending/ba-p/3608963" }
            @{ Title = "Change SHA1 to SHA256 in Certification Authority - Evotec"; Url = "https://evotec.xyz/windows-server-how-to-change-sha1-to-sha256-sha384-or-sha512-options-in-certification-authority/" }
            @{ Title = "Migrate ADCS to SHA-2 - 4sysops"; Url = "https://4sysops.com/archives/how-to-migrate-active-directory-certificate-services-to-sha-2-and-key-storage-provider/" }
        )
        Tools = @("Certipy", "Certify", "certutil")
        MITRE = "T1649"
        Triggers = @(
            @{ Attribute = 'CACertWeakSignature'; Pattern = '.'; Severity = 'Finding' }
            @{ Attribute = 'CACertSignatureAlgorithm'; Pattern = '(?i)sha1|md5|md2'; Severity = 'Finding' }
        )
    }

    'ADCS_CA_SHORT_KEY' = @{
        Title = "CA Certificate Uses Insufficient Key Length"
        Risk = "Finding"
        BaseScore = 50
        Description = "The Certificate Authority's signing certificate uses a public key shorter than 2048 bits. Short keys are vulnerable to factoring attacks and do not meet current security standards."
        Impact = @(
            "Keys shorter than 2048 bits can potentially be factored"
            "All certificates issued by this CA inherit the weak security"
            "Non-compliant with NIST SP 800-57 and industry standards"
        )
        Remediation = @(
            "Renew the CA certificate with at least 2048-bit RSA key (4096-bit recommended)"
            "For ECC keys, use P-256 or stronger curves"
            "Plan CA migration if the current key cannot be upgraded"
        )
        RemediationCommands = @(
            @{
                Description = "Renew CA certificate with 4096-bit key (generates new key)"
                Command = "certutil -renewCert"
            }
            @{
                Description = "Check current CA certificate key length"
                Command = "certutil -cainfo cert | findstr `"Public Key Length`""
            }
            @{
                Description = "Configure default key length for new CA certificates"
                Command = "# Renew CA cert via GUI (certsrv.msc) - specify 4096-bit key during renewal wizard"
            }
        )
        References = @(
            @{ Title = "NIST SP 800-57 Key Management"; Url = "https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final" }
            @{ Title = "Key Length Requirements for AD CS - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts" }
            @{ Title = "Renew Windows Root CA Certificate - 4sysops"; Url = "https://4sysops.com/archives/renew-windows-root-ca-certificate/" }
        )
        Tools = @("Certipy", "Certify", "certutil")
        MITRE = "T1649"
        Triggers = @(
            @{ Attribute = 'CACertShortKey'; Pattern = '.'; Severity = 'Finding' }
            @{ Attribute = 'CACertKeySize'; Pattern = '^(512|768|1024) bit$'; Severity = 'Finding' }
        )
    }

    'ADCS_CA_CERT_EXPIRED' = @{
        Title = "CA Certificate Has Expired"
        Risk = "Finding"
        BaseScore = 60
        Description = "The Certificate Authority's signing certificate has expired. An expired CA certificate means the CA can no longer issue valid certificates, and existing certificates may fail validation."
        Impact = @(
            "CA cannot issue new valid certificates"
            "Existing certificates signed by this CA may fail chain validation"
            "Certificate-based authentication (PKINIT, smart card) may stop working"
            "Services relying on auto-enrollment will fail"
        )
        Remediation = @(
            "Renew the CA certificate immediately"
            "If the CA is no longer needed, decommission it properly"
            "Verify all dependent services after certificate renewal"
        )
        RemediationCommands = @(
            @{
                Description = "Renew CA certificate with new key"
                Command = "certutil -renewCert"
            }
            @{
                Description = "Renew CA certificate keeping existing key"
                Command = "certutil -renewCert ReuseKeys"
            }
            @{
                Description = "Install renewed subordinate CA certificate"
                Command = "certutil -installCert <CACertFileName>"
            }
        )
        References = @(
            @{ Title = "Renewing CA Certificate - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts" }
            @{ Title = "Renew Certificate Authority Certificates - Microsoft"; Url = "https://techcommunity.microsoft.com/blog/askds/renew-certificate-authority-certificates-on-windows-server-core-no-problem/4006988" }
        )
        Tools = @("certutil", "Certipy")
        MITRE = "T1649"
        Triggers = @(
            @{ Attribute = 'CACertExpired'; Pattern = '.'; Severity = 'Finding' }
            @{ Attribute = 'CACertValidity'; Pattern = 'EXPIRED'; Severity = 'Finding' }
        )
    }

    'ADCS_CA_CROSS_DOMAIN' = @{
        Title = "CA Server in Different Domain"
        Risk = "Info"
        BaseScore = 0
        Description = "The CA server's computer object is in a different domain partition than the current query target. CA configuration data is shown from the forest-wide Configuration Partition."
        Triggers = @(
            @{ Attribute = 'caNote'; Severity = 'Hint'; SeverityOnly = $true }
        )
    }

    # ============================================================================
    # PKI INFRASTRUCTURE CERTIFICATE FINDINGS (Root CAs, NTAuth, AIA)
    # ============================================================================

    'PKI_WEAK_SIGNATURE_ALGORITHM' = @{
        Title = "PKI Certificate Uses Weak Signature Algorithm"
        Risk = "Finding"
        BaseScore = 50
        Description = "A trusted PKI certificate (Root CA, NTAuth, or AIA) uses a weak or deprecated signature algorithm such as SHA-1, MD5, or MD2. Certificates signed with weak algorithms are vulnerable to collision attacks, potentially allowing attackers to forge certificates that chain to the trusted root."
        Impact = @(
            "Weak hash algorithms are susceptible to collision attacks"
            "Forged certificates could be created that appear to chain to the trusted root"
            "Modern security policies and browsers reject SHA-1 signed certificates"
            "All certificates in the chain inherit the weakness of the root signature"
        )
        Remediation = @(
            "Renew the CA certificate with SHA-256 or stronger signature algorithm"
            "Plan CA migration if the current CA does not support modern algorithms"
            "Update all dependent certificates in the chain"
        )
        RemediationCommands = @(
            @{
                Description = "Configure CA to use SHA-256 hash algorithm"
                Command = "certutil -setreg ca\csp\CNGHashAlgorithm SHA256"
            }
            @{
                Description = "Restart Certificate Services to apply changes"
                Command = "Restart-Service -Name CertSvc"
            }
            @{
                Description = "Disable weak algorithms in certificate validation (registry)"
                Command = "New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config' -Name 'WeakSignatureHashAlgorithm' -Value 'SHA1;MD5;MD2'"
            }
        )
        References = @(
            @{ Title = "SHA-1 Deprecation - Microsoft"; Url = "https://techcommunity.microsoft.com/t5/windows-it-pro-blog/sha-1-windows-content-signing-is-ending/ba-p/3608963" }
            @{ Title = "Disable Weak Cryptographic Algorithms - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/disable-weak-cryptographic-algorithms" }
            @{ Title = "Migrate ADCS to SHA-2 - 4sysops"; Url = "https://4sysops.com/archives/how-to-migrate-active-directory-certificate-services-to-sha-2-and-key-storage-provider/" }
        )
        Tools = @("certutil", "Certipy")
        MITRE = "T1649"
        Triggers = @(
            @{ Attribute = 'SignatureAlgorithm'; Pattern = '(?i)sha1|md5|md2'; Severity = 'Finding' }
        )
    }

    'PKI_SHORT_KEY_LENGTH' = @{
        Title = "PKI Certificate Uses Insufficient Key Length"
        Risk = "Finding"
        BaseScore = 50
        Description = "A trusted PKI certificate (Root CA, NTAuth, or AIA) uses a public key shorter than 2048 bits. Short keys are vulnerable to factoring attacks and do not meet current security standards. All certificates issued under this CA inherit the weak security posture."
        Impact = @(
            "Keys shorter than 2048 bits can potentially be factored"
            "All certificates in the trust chain are affected"
            "Non-compliant with NIST SP 800-57 and industry standards"
        )
        Remediation = @(
            "Renew the CA certificate with at least 2048-bit RSA key (4096-bit recommended)"
            "For ECC keys, use P-256 or stronger curves"
            "Plan CA migration if the current key cannot be upgraded"
        )
        RemediationCommands = @(
            @{
                Description = "Identify templates with short key sizes"
                Command = "certutil -dstemplate | findstr `"[ msPKI-Minimal-Key-Size`" | findstr /v `"1024 2048 4096`""
            }
            @{
                Description = "Update certificate template minimum key size to 2048 (via GUI: Certificate Templates Console - Cryptography tab)"
                Command = "# Use Certificate Templates Console (certtmpl.msc) to modify template properties - set Minimum key size to 2048 or 4096"
            }
            @{
                Description = "Force reenrollment with new key size"
                Command = "# Use Certificate Templates Console - Right-click template - Reenroll All Certificate Holders"
            }
        )
        References = @(
            @{ Title = "NIST SP 800-57 Key Management"; Url = "https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final" }
            @{ Title = "Key Length Requirements for AD CS - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts" }
            @{ Title = "Update for Minimum Certificate Key Length - Microsoft KB"; Url = "https://mskb.pkisolutions.com/kb/2661254" }
        )
        Tools = @("certutil", "Certipy")
        MITRE = "T1649"
        Triggers = @(
            @{ Attribute = 'KeySize'; Pattern = '^(512|768|1024) bit$'; Severity = 'Finding' }
        )
    }

    'PKI_CERTIFICATE_EXPIRED' = @{
        Title = "PKI Certificate Has Expired"
        Risk = "Finding"
        BaseScore = 60
        Description = "A trusted PKI certificate (Root CA, NTAuth, or AIA) has expired. An expired certificate in the trust chain can cause widespread authentication failures and certificate validation errors."
        Impact = @(
            "Certificates chaining to an expired root will fail validation"
            "Certificate-based authentication (PKINIT, smart card) may stop working"
            "New certificate enrollment may be affected"
            "Trust relationships depending on this certificate break"
        )
        Remediation = @(
            "Renew the expired CA certificate"
            "If the CA is no longer needed, remove it from the trust store"
            "Verify all dependent services after certificate renewal"
        )
        RemediationCommands = @(
            @{
                Description = "Renew CA certificate with new key"
                Command = "certutil -renewCert"
            }
            @{
                Description = "Renew CA certificate keeping existing key"
                Command = "certutil -renewCert ReuseKeys"
            }
            @{
                Description = "Publish renewed certificate to Active Directory (Standalone CA)"
                Command = "certutil -f -dspublish <RootCACertificate-File> RootCA"
            }
        )
        References = @(
            @{ Title = "Renewing CA Certificate - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts" }
            @{ Title = "Renew Certificate Authority Certificates - Microsoft"; Url = "https://techcommunity.microsoft.com/blog/askds/renew-certificate-authority-certificates-on-windows-server-core-no-problem/4006988" }
        )
        Tools = @("certutil", "Certipy")
        MITRE = "T1649"
        Triggers = @(
            @{ Attribute = 'Status'; Pattern = 'EXPIRED'; Severity = 'Finding' }
        )
    }

    # ============================================================================
    # CA OBJECT PERMISSION FINDINGS
    # ============================================================================

    'CA_DANGEROUS_AD_PERMISSIONS' = @{
        Title = "CA Object with Dangerous AD Permissions"
        Risk = "Finding"
        BaseScore = 60
        Description = "The Certification Authority AD object has dangerous permissions (GenericAll, WriteDACL, WriteOwner) granted to non-administrative principals. This can enable complete CA compromise."
        Impact = @(
            "Attacker can modify CA object in AD"
            "Can change CA enrollment permissions"
            "Can modify published certificate templates"
            "Complete PKI compromise possible"
        )
        Attack = @(
            "1. Attacker identifies dangerous CA object permissions"
            "2. Modifies CA to publish vulnerable templates"
            "3. Enables templates that allow arbitrary SANs"
            "4. Issues certificate for Domain Admin"
        )
        Remediation = @(
            "Audit CA object ACLs in AD"
            "Remove dangerous permissions from non-admin principals"
            "Only Enterprise Admins/CA Admins should manage CA objects"
            "Monitor for CA object permission changes"
        )
        RemediationCommands = @(
            @{
                Description = "List all Certification Authorities in the forest"
                Command = "Get-ADObject -LDAPFilter '(objectClass=pKIEnrollmentService)' -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -Properties cn,dNSHostName,distinguishedName | Select-Object cn,dNSHostName,distinguishedName | Format-Table -AutoSize"
            }
            @{
                Description = "View CA object ACL for a specific CA"
                Command = "`$caPath = 'AD:CN=CA-Name,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com'; Get-Acl -Path `$caPath | Select-Object -ExpandProperty Access | Where-Object {`$_.IdentityReference -notmatch 'SYSTEM|Administrators|Enterprise Admins|Cert Publishers'} | Select-Object IdentityReference,ActiveDirectoryRights,AccessControlType | Format-Table -AutoSize"
            }
            @{
                Description = "Remove GenericAll permission from specific principal on CA object"
                Command = "`$caPath = 'AD:CN=CA-Name,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com'; `$acl = Get-Acl -Path `$caPath; `$ace = `$acl.Access | Where-Object {`$_.IdentityReference -eq 'DOMAIN\\User' -and `$_.ActiveDirectoryRights -eq 'GenericAll'}; `$ace | ForEach-Object {`$acl.RemoveAccessRule(`$_)}; Set-Acl -Path `$caPath -AclObject `$acl"
            }
            @{
                Description = "Remove WriteDACL permission from specific principal on CA object"
                Command = "`$caPath = 'AD:CN=CA-Name,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com'; `$acl = Get-Acl -Path `$caPath; `$ace = `$acl.Access | Where-Object {`$_.IdentityReference -eq 'DOMAIN\\User' -and `$_.ActiveDirectoryRights -match 'WriteDacl'}; `$ace | ForEach-Object {`$acl.RemoveAccessRule(`$_)}; Set-Acl -Path `$caPath -AclObject `$acl"
            }
            @{
                Description = "Remove WriteOwner permission from specific principal on CA object"
                Command = "`$caPath = 'AD:CN=CA-Name,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com'; `$acl = Get-Acl -Path `$caPath; `$ace = `$acl.Access | Where-Object {`$_.IdentityReference -eq 'DOMAIN\\User' -and `$_.ActiveDirectoryRights -match 'WriteOwner'}; `$ace | ForEach-Object {`$acl.RemoveAccessRule(`$_)}; Set-Acl -Path `$caPath -AclObject `$acl"
            }
            @{
                Description = "Audit all CA object permissions in the forest for non-standard access"
                Command = "Get-ADObject -LDAPFilter '(objectClass=pKIEnrollmentService)' -SearchBase (Get-ADRootDSE).ConfigurationNamingContext | ForEach-Object { Write-Host `"CA: `$(`$_.Name)`" -ForegroundColor Cyan; Get-Acl -Path `"AD:`$(`$_.DistinguishedName)`" | Select-Object -ExpandProperty Access | Where-Object {`$_.IdentityReference -notmatch 'SYSTEM|Administrators|Enterprise Admins|Domain Admins|Cert Publishers' -and `$_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner'} | Format-Table IdentityReference,ActiveDirectoryRights,AccessControlType -AutoSize }"
            }
        )
        References = @(
            @{ Title = "Certified Pre-Owned"; Url = "https://posts.specterops.io/certified-pre-owned-d95910965cd2" }
            @{ Title = "CA Security Best Practices - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts" }
        )
        Tools = @("Certify", "ADACLScanner", "BloodHound")
        MITRE = "T1649"
        Triggers = @(
            @{ Attribute = 'CAPermissions'; Severity = 'Finding' }
            @{ Attribute = 'DangerousACEs'; Severity = 'Finding' }
        )
    }

    # ============================================================================
    # COMPUTER ACCOUNT CREATION FINDINGS
    # ============================================================================

    'COMPUTER_CONTAINER_CREATE_PERMISSIONS' = @{
        Title = "Non-Default Create Computer Permissions"
        Risk = "Finding"
        BaseScore = 35
        Description = "The Computers container or specific OUs have explicit permissions allowing non-privileged users to create computer objects. This extends beyond the ms-DS-MachineAccountQuota and may enable additional attacks."
        Impact = @(
            "Users can create computer accounts beyond quota"
            "Created accounts can be used in RBCD attacks"
            "Enables relay attacks requiring machine accounts"
            "May bypass quota restrictions entirely"
        )
        Attack = @(
            "1. Attacker identifies create permissions on container"
            "2. Creates machine account using explicit permission"
            "3. Uses account for RBCD or relay attacks"
            "4. Achieves privilege escalation"
        )
        Remediation = @(
            "Audit ACLs on Computers container and OUs"
            "Remove explicit Create Computer permissions"
            "Use dedicated provisioning accounts only"
            "Implement computer account pre-staging"
        )
        RemediationCommands = @(
            @{
                Description = "View ACL on Computers container (check for Create Computer Object rights)"
                Command = "(Get-Acl 'AD:\CN=Computers,DC=domain,DC=com').Access | Where-Object {`$_.ActiveDirectoryRights -match 'CreateChild' -and `$_.ObjectType -eq 'bf967a86-0de6-11d0-a285-00aa003049e2'} | Format-Table IdentityReference,ActiveDirectoryRights,AccessControlType -AutoSize"
            }
            @{
                Description = "Remove Create Computer permission from Computers container"
                Command = "`$dn = 'AD:\CN=Computers,DC=domain,DC=com'; `$acl = Get-Acl `$dn; `$ace = `$acl.Access | Where-Object {`$_.IdentityReference -eq 'DOMAIN\User' -and `$_.ActiveDirectoryRights -match 'CreateChild'}; `$acl.RemoveAccessRule(`$ace); Set-Acl -AclObject `$acl -Path `$dn"
            }
            @{
                Description = "Set ms-DS-MachineAccountQuota to 0 (disable regular users from creating computers)"
                Command = "Set-ADDomain -Identity (Get-ADDomain).DistinguishedName -Replace @{'ms-DS-MachineAccountQuota'='0'}"
            }
            @{
                Description = "Find all OUs where specific principal can create computer objects"
                Command = "Get-ADOrganizationalUnit -Filter * | ForEach-Object { `$acl = Get-Acl `$_.DistinguishedName; `$createPerms = `$acl.Access | Where-Object {`$_.IdentityReference -like '*USERNAME*' -and `$_.ActiveDirectoryRights -match 'CreateChild' -and `$_.ObjectType -eq 'bf967a86-0de6-11d0-a285-00aa003049e2'}; if (`$createPerms) { [PSCustomObject]@{OU=`$_.Name; DN=`$_.DistinguishedName} } }"
            }
        )
        References = @(
            @{ Title = "Machine Account Attacks"; Url = "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution" }
            @{ Title = "MachineAccountQuota Attribute - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota" }
        )
        Tools = @("PowerMad", "ADACLScanner", "BloodHound")
        MITRE = "T1136.002"
    }

    'GPO_SEMACHINEACCOUNTPRIVILEGE_BROAD' = @{
        Title = "SeMachineAccountPrivilege Assigned via GPO"
        Risk = "Hint"
        BaseScore = 20
        Description = "The 'Add workstations to domain' user right (SeMachineAccountPrivilege) is configured via GPO. This setting controls who can join computers to the domain beyond the ms-DS-MachineAccountQuota."
        Impact = @(
            "Listed accounts can add computers to domain"
            "Works in addition to ms-DS-MachineAccountQuota"
            "May allow broader access than intended"
        )
        Attack = @(
            "1. Attacker identifies SeMachineAccountPrivilege assignment"
            "2. Joins attacker-controlled system to domain"
            "3. Uses machine account for further attacks"
            "4. RBCD, relay, or coercion attacks"
        )
        Remediation = @(
            "Restrict SeMachineAccountPrivilege to specific admin groups"
            "Avoid assigning to Authenticated Users or Everyone"
            "Implement controlled computer provisioning"
            "Monitor for unexpected computer account creation"
        )
        References = @(
            @{ Title = "User Rights Assignment"; Url = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/add-workstations-to-domain" }
        )
        Tools = @("GPO analysis", "secedit", "PowerView")
        MITRE = "T1136.002"
        Triggers = @(
            @{ Attribute = 'accounts'; Severity = 'Hint' }
        )
    }

    # ============================================================================
    # BLOODHOUND COLLECTOR
    # ============================================================================

    'BLOODHOUND_COLLECTION_COMPLETE' = @{
        Title = "BloodHound Data Collection"
        Risk = "Note"
        BaseScore = 10
        Description = "adPEAS includes a native BloodHound-compatible data collector. This collector operates in DCOnly mode, retrieving all data via LDAP queries without requiring local admin access or session enumeration."
        Impact = @(
            "Enables graph-based attack path analysis in BloodHound CE"
            "Identifies privilege escalation paths across the domain"
            "Visualizes ACL-based attack chains"
            "Maps group membership hierarchies and nested delegations"
        )
        Attack = @(
            "BloodHound is a defensive tool for identifying attack paths"
            "Attackers also use BloodHound for reconnaissance"
            "Understanding your attack surface helps prioritize remediation"
        )
        Remediation = @(
            "Import the ZIP file into BloodHound CE for analysis"
            "Focus on 'Shortest Paths to Domain Admin' queries"
            "Identify and remediate high-risk ACL configurations"
            "Review delegation paths and Kerberoastable accounts"
        )
        RemediationCommands = @(
            @{
                Description = "Start BloodHound CE with Docker"
                Command = "docker-compose -f docker-compose.yml up -d"
            }
            @{
                Description = "Import data via BloodHound API"
                Command = "curl -X POST -F 'file=@bloodhound_data.zip' http://localhost:8080/api/v2/file-upload"
            }
        )
        References = @(
            @{ Title = "BloodHound CE"; Url = "https://github.com/SpecterOps/BloodHound" }
            @{ Title = "BloodHound Documentation"; Url = "https://bloodhound.specterops.io/" }
            @{ Title = "BloodHound CE Docker Setup"; Url = "https://github.com/SpecterOps/BloodHound/blob/main/examples/docker-compose/docker-compose.yml" }
            @{ Title = "Cypher Query Reference"; Url = "https://bloodhound.specterops.io/analyze-data/overview" }
            @{ Title = "Securing Privileged Access - Microsoft"; Url = "https://learn.microsoft.com/en-us/security/privileged-access-workstations/security-rapid-modernization-plan" }
        )
        Tools = @("BloodHound", "Neo4j", "ADRecon")
        MITRE = "T1087"
    }

    # ============================================================================
    # SECURE CONFIGURATION FINDINGS
    # ============================================================================
    # These definitions describe secure/hardened configurations when attributes
    # have security-positive values (Severity = "Secure")

    'LDAP_SIGNING_REQUIRED' = @{
        Title = "LDAP Signing Required"
        Risk = "Secure"
        BaseScore = 0
        Description = "LDAP signing is configured as required on this Domain Controller. This security setting ensures that all LDAP communications are digitally signed, preventing man-in-the-middle attacks and NTLM relay to LDAP services."
        Impact = @(
            "LDAP traffic is protected against interception and modification"
            "NTLM relay attacks targeting LDAP services are blocked"
            "Credentials and data are protected during LDAP communications"
            "Compliant with security best practices and CIS benchmarks"
        )
        Attack = @(
            "With LDAP signing required, attackers cannot:"
            "- Relay NTLM authentication to LDAP for privilege escalation"
            "- Intercept or modify LDAP traffic in transit"
            "- Perform RBCD attacks via LDAP relay"
            "- Add users to groups via unsigned LDAP operations"
        )
        Remediation = @(
            "This is a secure configuration - no remediation needed"
            "Ensure this setting is consistently applied across all Domain Controllers"
            "Document this security control in your hardening baseline"
            "Monitor for any attempts to weaken this setting"
        )
        References = @(
            @{ Title = "LDAP Signing Requirements - Microsoft"; Url = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-controller-ldap-server-signing-requirements" }
            @{ Title = "CIS Benchmark - LDAP Signing"; Url = "https://www.cisecurity.org/benchmark/microsoft_windows_server" }
        )
        Tools = @()
        MITRE = "M1041"
        Triggers = @(
            @{ Attribute = 'LDAPSigning'; Pattern = '^Required$'; Severity = 'Secure' }
        )
    }

    'LDAP_CHANNEL_BINDING_ALWAYS' = @{
        Title = "LDAP Channel Binding Always Required"
        Risk = "Secure"
        BaseScore = 0
        Description = "LDAP channel binding is configured as 'Always' required. This provides cryptographic binding between the TLS channel and the LDAP authentication, preventing relay attacks even over encrypted connections."
        Impact = @(
            "LDAPS connections are protected against relay attacks"
            "TLS channel is cryptographically bound to authentication"
            "Enhanced protection beyond just LDAP signing"
            "Compliant with Microsoft's 2020 LDAP security recommendations"
        )
        Attack = @(
            "With channel binding enforced, attackers cannot:"
            "- Relay LDAP authentication over TLS"
            "- Bypass LDAP signing via LDAPS relay"
            "- Perform man-in-the-middle on encrypted LDAP"
        )
        Remediation = @(
            "This is a secure configuration - no remediation needed"
            "Ensure this is consistently configured via GPO across all DCs"
            "Verify application compatibility has been tested"
            "Document in security hardening baseline"
        )
        References = @(
            @{ Title = "LDAP Channel Binding - Microsoft"; Url = "https://support.microsoft.com/en-us/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows-ef185fb8-00f7-167d-744c-f299a66fc00a" }
        )
        Tools = @()
        MITRE = "M1041"
        Triggers = @(
            @{ Attribute = 'ChannelBinding'; Pattern = '^Always$'; Severity = 'Secure' }
        )
    }

    'LDAP_ANONYMOUS_BINDING_RESTRICTED' = @{
        Title = "Anonymous LDAP Binding Restricted"
        Risk = "Secure"
        BaseScore = 0
        Description = "Anonymous LDAP binding is explicitly restricted. Unauthenticated users cannot enumerate Active Directory objects, reducing the attack surface for reconnaissance and information gathering."
        Impact = @(
            "Unauthenticated LDAP enumeration is blocked"
            "Attackers cannot gather AD information without credentials"
            "Reduces exposure of usernames, groups, and organizational structure"
            "Compliant with security hardening best practices"
        )
        Attack = @(
            "With anonymous binding restricted, attackers cannot:"
            "- Enumerate users and groups without authentication"
            "- Discover organizational structure anonymously"
            "- Identify high-value targets without valid credentials"
            "- Perform pre-authentication reconnaissance via LDAP"
        )
        Remediation = @(
            "This is a secure configuration - no remediation needed"
            "Verify the setting is applied via GPO for consistency"
            "Audit any exceptions that may require anonymous access"
            "Monitor for failed anonymous bind attempts"
        )
        References = @(
            @{ Title = "Anonymous LDAP Operations - Microsoft"; Url = "https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/anonymous-ldap-operations-active-directory-disabled" }
        )
        Tools = @()
        MITRE = "M1035"
        Triggers = @(
            @{ Attribute = 'anonymousLDAPAccess'; Pattern = '^Restricted$'; Severity = 'Secure' }
            @{ Attribute = 'AnonymousBinding'; Pattern = '^Restricted$'; Severity = 'Secure' }
        )
    }

    'SMB_SIGNING_REQUIRED' = @{
        Title = "SMB Signing Required"
        Risk = "Secure"
        BaseScore = 0
        Description = "SMB signing is configured as required. This security setting ensures all SMB communications are digitally signed, preventing man-in-the-middle attacks and NTLM relay to SMB services."
        Impact = @(
            "SMB traffic is protected against interception and relay"
            "NTLM relay attacks targeting SMB are blocked"
            "Remote code execution via relay is prevented"
            "Lateral movement via unsigned SMB is blocked"
        )
        Attack = @(
            "With SMB signing required, attackers cannot:"
            "- Relay NTLM authentication to SMB for code execution"
            "- Intercept or modify SMB traffic in transit"
            "- Perform PsExec/WMI attacks via relayed credentials"
            "- Use coercion attacks (PetitPotam, PrinterBug) for SMB relay"
        )
        Remediation = @(
            "This is a secure configuration - no remediation needed"
            "Ensure SMB signing is required on both server and client sides"
            "Document this control in your security hardening baseline"
            "Monitor for any attempts to disable SMB signing"
        )
        References = @(
            @{ Title = "SMB Signing Overview - Microsoft"; Url = "https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing" }
            @{ Title = "CIS Benchmark - SMB Signing"; Url = "https://www.cisecurity.org/benchmark/microsoft_windows_server" }
        )
        Tools = @()
        MITRE = "M1041"
        Triggers = @(
            @{ Attribute = 'ServerSigning'; Pattern = '^Required$'; Severity = 'Secure' }
            @{ Attribute = 'ClientSigning'; Pattern = '^Required$'; Severity = 'Secure' }
        )
    }

    'MANAGER_APPROVAL_REQUIRED' = @{
        Title = "CA Manager Approval Required"
        Risk = "Secure"
        BaseScore = 0
        Description = "This certificate template requires CA Manager approval before certificates are issued. This control prevents automatic certificate issuance and adds a manual verification step, significantly reducing the risk of certificate-based attacks."
        Impact = @(
            "Certificate requests require manual CA Manager approval"
            "Automatic exploitation of vulnerable templates is prevented"
            "Human review catches suspicious or unauthorized requests"
            "ESC1/ESC2/ESC3 attacks are significantly harder to execute"
        )
        Attack = @(
            "With manager approval required, attackers cannot:"
            "- Automatically request certificates for arbitrary users"
            "- Exploit ESC1/ESC2/ESC3 vulnerabilities without detection"
            "- Obtain certificates without human verification"
            "- Rapidly escalate privileges via ADCS"
        )
        Remediation = @(
            "This is a secure configuration - no remediation needed"
            "Ensure CA Managers are trained to verify certificate requests"
            "Implement approval workflows with proper documentation"
            "Monitor and audit all certificate approvals"
        )
        References = @(
            @{ Title = "Certificate Template Security - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts" }
            @{ Title = "ADCS Security Best Practices"; Url = "https://posts.specterops.io/certified-pre-owned-d95910965cd2" }
        )
        Tools = @()
        MITRE = "M1026"
    }

    'ENROLLMENT_REQUIRES_APPROVAL' = @{
        Title = "Certificate Enrollment Requires Approval"
        Risk = "Secure"
        BaseScore = 0
        Description = "The CT_FLAG_PEND_ALL_REQUESTS flag is set on this certificate template, meaning all certificate requests are placed in a pending state for manual approval. This is a strong security control that prevents automatic certificate issuance."
        Impact = @(
            "All certificate requests require explicit approval"
            "No certificates are automatically issued"
            "Provides complete control over certificate issuance"
            "Significantly reduces ADCS attack surface"
        )
        Attack = @(
            "With PEND_ALL_REQUESTS enabled, attackers cannot:"
            "- Automatically obtain certificates"
            "- Exploit enrollment-based vulnerabilities silently"
            "- Request certificates without administrator awareness"
        )
        Remediation = @(
            "This is a secure configuration - no remediation needed"
            "Document the approval process and responsible personnel"
            "Ensure timely processing of legitimate requests"
            "Audit approval actions for compliance"
        )
        References = @(
            @{ Title = "msPKI-Enrollment-Flag - Microsoft"; Url = "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1" }
        )
        Tools = @()
        MITRE = "M1026"
    }

    'ACCOUNT_DISABLED' = @{
        Title = "Account Disabled"
        Risk = "Secure"
        BaseScore = 0
        Description = "This account has the ACCOUNTDISABLE flag set in userAccountControl. Disabled accounts cannot authenticate to the domain, effectively preventing any unauthorized access through this account."
        Impact = @(
            "Account cannot be used for authentication"
            "Prevents misuse of inactive or compromised accounts"
            "Reduces attack surface by removing unused credentials"
            "Good security hygiene for terminated employees"
        )
        Attack = @(
            "With the account disabled, attackers cannot:"
            "- Authenticate using this account's credentials"
            "- Use the account for lateral movement"
            "- Leverage any delegated permissions of the account"
        )
        Remediation = @(
            "This is a secure configuration for inactive accounts"
            "Consider deleting accounts that will never be re-enabled"
            "Document the reason for keeping disabled accounts"
            "Review disabled accounts periodically for potential deletion"
        )
        References = @(
            @{ Title = "userAccountControl Attribute - Microsoft"; Url = "https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties" }
        )
        Tools = @()
        MITRE = "M1026"
        Triggers = @(
            @{ Attribute = 'userAccountControl'; Pattern = 'ACCOUNTDISABLE'; Severity = 'Secure' }
        )
    }

    'SMARTCARD_REQUIRED' = @{
        Title = "Smart Card Required for Interactive Logon"
        Risk = "Secure"
        BaseScore = 0
        Description = "This account has the SMARTCARD_REQUIRED flag set, requiring a smart card for interactive logon. This provides strong multi-factor authentication and makes password-based attacks ineffective."
        Impact = @(
            "Password-based attacks are ineffective"
            "Phishing for passwords becomes useless"
            "Strong cryptographic authentication required"
            "Significantly increases account security"
        )
        Attack = @(
            "With smartcard required, attackers cannot:"
            "- Use password spraying or brute force attacks"
            "- Leverage credentials from phishing attacks"
            "- Use stolen password hashes for authentication"
            "- Perform Kerberoasting (password hash is random)"
        )
        Remediation = @(
            "This is a secure configuration - no remediation needed"
            "Ensure smart card infrastructure is properly maintained"
            "Document smart card enrollment and revocation procedures"
            "Consider extending smart card requirement to more privileged accounts"
        )
        References = @(
            @{ Title = "Smart Card Sign-in - Microsoft"; Url = "https://docs.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-how-smart-card-sign-in-works-in-windows" }
            @{ Title = "Privileged Access - Smart Cards"; Url = "https://docs.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-devices" }
        )
        Tools = @()
        MITRE = "M1032"
        Triggers = @(
            @{ Attribute = 'userAccountControl'; Pattern = 'SMARTCARD_REQUIRED'; Severity = 'Secure' }
        )
    }

    'ACCOUNT_NOT_DELEGATED' = @{
        Title = "Account Is Sensitive and Cannot Be Delegated"
        Risk = "Secure"
        BaseScore = 0
        Description = "This account has the NOT_DELEGATED flag set, meaning it cannot be impersonated through Kerberos delegation. This protects the account from delegation-based attacks including unconstrained, constrained, and resource-based constrained delegation."
        Impact = @(
            "Account is protected from all Kerberos delegation attacks"
            "Cannot be impersonated via unconstrained delegation"
            "Protected from constrained delegation abuse"
            "RBCD attacks cannot target this account"
        )
        Attack = @(
            "With NOT_DELEGATED set, attackers cannot:"
            "- Impersonate this account via delegation servers"
            "- Use captured TGTs for S4U2Self/S4U2Proxy attacks"
            "- Leverage RBCD to access resources as this account"
            "- Abuse unconstrained delegation to steal this account's TGT"
        )
        Remediation = @(
            "This is a secure configuration - no remediation needed"
            "Consider adding all privileged accounts to Protected Users group"
            "Document which accounts have this protection"
            "Regularly audit that this flag remains set on sensitive accounts"
        )
        References = @(
            @{ Title = "Protected Accounts - Microsoft"; Url = "https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group" }
            @{ Title = "Delegation Protection"; Url = "https://adsecurity.org/?p=1667" }
        )
        Tools = @()
        MITRE = "M1026"
        Triggers = @(
            @{ Attribute = 'userAccountControl'; Pattern = 'NOT_DELEGATED'; Severity = 'Secure' }
        )
    }

    'WEB_ENDPOINT_EPA_ENABLED' = @{
        Title = "Extended Protection for Authentication Enabled"
        Risk = "Secure"
        BaseScore = 0
        Description = "This web endpoint has Extended Protection for Authentication (EPA) enabled with NTLM authentication. EPA binds the authentication to the TLS channel, preventing NTLM relay attacks even when NTLM is used over HTTPS."
        Impact = @(
            "NTLM relay attacks over HTTPS are blocked"
            "Authentication is cryptographically bound to TLS channel"
            "Provides defense in depth for legacy NTLM authentication"
            "Significantly reduces attack surface for web services"
        )
        Attack = @(
            "With EPA enabled, attackers cannot:"
            "- Relay NTLM authentication to this endpoint"
            "- Exploit coercion attacks (PetitPotam, etc.) via relay"
            "- Perform ESC8 attacks against ADCS web enrollment"
            "- Use NTLM relay for privilege escalation"
        )
        Remediation = @(
            "This is a secure configuration - no remediation needed"
            "Ensure EPA is consistently enabled across all web services"
            "Consider migrating to Kerberos or certificate authentication"
            "Document EPA configuration in security baseline"
        )
        References = @(
            @{ Title = "Extended Protection for Authentication - Microsoft"; Url = "https://docs.microsoft.com/en-us/dotnet/framework/wcf/feature-details/extended-protection-for-authentication-overview" }
            @{ Title = "ADCS ESC8 Mitigation"; Url = "https://posts.specterops.io/certified-pre-owned-d95910965cd2" }
        )
        Tools = @()
        MITRE = "M1041"
        Triggers = @(
            @{ Attribute = 'WebEnrollmentEndpoints'; Pattern = '\[EPA:\s*Enabled\]'; Severity = 'Secure' }
        )
    }

    # --- PKI / CA Certificate Secure Configurations ---

    'PKI_STRONG_SIGNATURE_ALGORITHM' = @{
        Title = "PKI Certificate Uses Strong Signature Algorithm"
        Risk = "Secure"
        BaseScore = 0
        Description = "The PKI certificate uses a signature algorithm stronger than the current baseline (SHA-384 or SHA-512). These algorithms provide an extra security margin beyond the SHA-256 standard, offering increased collision resistance for long-lived CA certificates."
        Impact = @(
            "Certificate signatures provide extra security margin beyond baseline"
            "Stronger collision resistance than SHA-256"
            "Future-proof against potential advances in hash attacks"
            "Exceeds current industry baseline requirements"
        )
        Attack = @(
            "With strong signature algorithms, attackers cannot:"
            "- Forge certificates using hash collision attacks"
            "- Create fraudulent certificates that chain to the trusted root"
            "- Exploit weaknesses in deprecated hash algorithms"
        )
        Remediation = @(
            "This is a secure configuration - no remediation needed"
            "Continue using SHA-384 or SHA-512 for CA certificate operations"
            "Monitor for algorithm deprecation announcements"
        )
        RemediationCommands = @(
            @{
                Description = "Verify strong signature algorithm configuration"
                Command = "certutil -getreg ca\csp\CNGHashAlgorithm"
            }
        )
        References = @(
            @{ Title = "NIST SP 800-57 Key Management"; Url = "https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final" }
        )
        Tools = @()
        MITRE = "M1041"
        Triggers = @(
            @{ Attribute = 'SignatureAlgorithm'; Pattern = '(?i)sha384|sha512'; Severity = 'Secure' }
            @{ Attribute = 'CACertSignatureAlgorithm'; Pattern = '(?i)sha384|sha512'; Severity = 'Secure' }
        )
    }

    'PKI_STRONG_KEY_LENGTH' = @{
        Title = "PKI Certificate Uses Strong Key Length"
        Risk = "Secure"
        BaseScore = 0
        Description = "The PKI certificate uses a strong public key length of 4096 bits or more. This exceeds the current minimum recommendation of 2048 bits and provides additional security margin for long-lived CA certificates."
        Impact = @(
            "Key is computationally infeasible to factor with current technology"
            "Exceeds NIST minimum requirements for RSA keys"
            "Provides long-term security appropriate for CA certificates"
            "Future-proof against advances in computing power"
        )
        Attack = @(
            "With strong key lengths, attackers cannot:"
            "- Factor the private key using known mathematical methods"
            "- Compromise the CA through key recovery attacks"
            "- Forge certificates by deriving the private key"
        )
        Remediation = @(
            "This is a secure configuration - no remediation needed"
            "Continue using 4096-bit or stronger keys for CA certificates"
            "Consider ECC P-384 or P-521 as a modern alternative"
        )
        RemediationCommands = @(
            @{
                Description = "Verify strong key length configuration"
                Command = "certutil -cainfo cert | findstr `"Public Key Length`""
            }
        )
        References = @(
            @{ Title = "NIST SP 800-57 Key Management"; Url = "https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final" }
        )
        Tools = @()
        MITRE = "M1041"
        Triggers = @(
            @{ Attribute = 'KeySize'; Pattern = '^(4096|8192) bit$'; Severity = 'Secure' }
            @{ Attribute = 'CACertKeySize'; Pattern = '^(4096|8192) bit$'; Severity = 'Secure' }
        )
    }

    'PASSWORD_COMPLEXITY_ENABLED' = @{
        Title = "Password Complexity Requirements Enabled"
        Risk = "Secure"
        BaseScore = 0
        Description = "Password complexity requirements are enabled, forcing passwords to contain characters from at least three of the following categories: uppercase letters, lowercase letters, digits, and special characters. This increases the keyspace and makes brute force attacks significantly harder."
        Impact = @(
            "Passwords must meet minimum complexity standards"
            "Brute force attacks require significantly more time"
            "Simple dictionary passwords are prevented"
        )
        Attack = @(
            "With complexity enabled, attackers cannot:"
            "- Use simple dictionary words as passwords"
            "- Rely on common password patterns (e.g., 'password123')"
        )
        Remediation = @(
            "This is a secure configuration - no remediation needed"
            "Consider supplementing with Azure AD Password Protection for banned passwords"
        )
        References = @(
            @{ Title = "Password Complexity Requirements"; Url = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements" }
        )
        Tools = @()
        MITRE = "M1027"
        Triggers = @(
            @{ Attribute = 'passwordComplexity'; Pattern = 'Enabled'; Severity = 'Secure' }
        )
    }

    'LOCKOUT_DURATION_FOREVER' = @{
        Title = "Account Lockout Duration - Manual Unlock Required"
        Risk = "Secure"
        BaseScore = 0
        Description = "The account lockout duration is set to 'Forever', meaning locked accounts require manual intervention by an administrator to unlock. This prevents attackers from simply waiting for accounts to auto-unlock after a lockout."
        Impact = @(
            "Brute force attacks are severely limited"
            "Locked accounts remain locked until admin intervention"
            "Provides opportunity to investigate lockout causes"
            "Strong deterrent against password guessing attacks"
        )
        Attack = @(
            "With permanent lockout enabled, attackers cannot:"
            "- Wait for accounts to auto-unlock and continue attacks"
            "- Perform slow-rate password spraying undetected"
            "- Bypass lockout by timing attacks across lockout windows"
        )
        Remediation = @(
            "This is a secure configuration - no remediation needed"
            "Ensure help desk processes exist for legitimate unlock requests"
            "Implement self-service unlock with strong verification"
            "Monitor lockout events for attack detection"
        )
        References = @(
            @{ Title = "Account Lockout Policy - Microsoft"; Url = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-duration" }
            @{ Title = "CIS Benchmark - Lockout Settings"; Url = "https://www.cisecurity.org/benchmark/microsoft_windows_server" }
        )
        Tools = @()
        MITRE = "M1036"
        Triggers = @(
            @{ Attribute = 'lockoutDuration'; Pattern = 'Forever|Permanent|Infinite'; Severity = 'Secure' }
        )
    }

    # ============================================================================
    # OPERATOR GROUP FINDINGS (from Get-ProtectedUsersStatus)
    # ============================================================================

    'OPERATOR_GROUP_MEMBERS' = @{
        Title = "Operator Group Has Active Members"
        Risk = "Hint"
        BaseScore = 25
        Description = "This operator-level group (such as Account Operators, Backup Operators, Print Operators, or Server Operators) has active members. While less privileged than Tier 0 groups like Domain Admins, these groups still have elevated capabilities that can be abused for privilege escalation."
        Impact = @(
            "Account Operators can create and modify non-admin accounts"
            "Backup Operators can back up and restore files on DCs including NTDS.dit"
            "Print Operators can load drivers on DCs (kernel-mode code execution)"
            "Server Operators can log on to DCs and manage services"
        )
        Remediation = @(
            "Review if members actually need membership in this operator group"
            "Follow least-privilege principle for group assignments"
            "Monitor membership changes in these groups"
            "Consider using delegated permissions instead of broad group membership"
        )
        References = @(
            @{ Title = "AD Built-In Groups"; Url = "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory" }
            @{ Title = "Abusing Backup Operators"; Url = "https://www.bordergate.co.uk/backup-operator-privilege-escalation/" }
        )
        Tools = @("BloodHound", "PowerView")
        MITRE = "T1078.002"
        Triggers = @(
            @{ Attribute = 'OperatorGroup'; Severity = 'Hint' }
            @{ Attribute = 'MemberCount'; Custom = 'gt_0'; Severity = 'Hint' }
            @{ Attribute = 'ProtectedCount'; Pattern = '^0$'; Severity = 'Finding' }
        )
    }

    # ============================================================================
    # ACTIVITY STATUS FINDINGS
    # ============================================================================

    'INACTIVE_ACCOUNT' = @{
        Title = "Inactive Account Detected"
        Risk = "Hint"
        BaseScore = 20
        Description = "This account shows signs of inactivity based on last logon timestamps. Inactive accounts are potential security risks because they may have stale, unrotated passwords and are unlikely to be monitored for misuse."
        Impact = @(
            "Inactive accounts with old passwords are prime targets for credential stuffing"
            "Compromise of inactive accounts may go unnoticed for extended periods"
            "Accounts inactive for over 365 days likely represent orphaned or unnecessary accounts"
        )
        Remediation = @(
            "Disable or delete accounts that are no longer in use"
            "Implement an automated account lifecycle management process"
            "Regularly audit inactive accounts and require justification for active status"
            "Monitor for logon events from previously inactive accounts"
        )
        References = @(
            @{ Title = "Stale Accounts"; Url = "https://learn.microsoft.com/en-us/defender-for-identity/cas-isp-dormant-entities" }
        )
        MITRE = "T1078"
        Triggers = @(
            @{ Attribute = 'activityStatus'; Severity = 'Hint' }
            @{ Attribute = 'lastLogonTimestamp'; Pattern = 'INACTIVE'; Severity = 'Hint' }
        )
    }

    # ============================================================================
    # DOMAIN FUNCTIONAL LEVEL
    # ============================================================================

    'OLD_FUNCTIONAL_LEVEL' = @{
        Title = "Outdated Domain/Forest Functional Level"
        Risk = "Hint"
        BaseScore = 15
        Description = "The domain or forest functional level is set to an outdated version (Windows 2000, 2003, or 2008). This prevents the use of modern security features like Protected Users group, Authentication Policies, and LDAP improvements available in newer functional levels."
        Impact = @(
            "Cannot use Protected Users group (requires 2012 R2+)"
            "Cannot use Authentication Policies/Silos (requires 2012 R2+)"
            "Missing modern Kerberos improvements"
            "May indicate presence of legacy Domain Controllers"
        )
        Remediation = @(
            "Plan upgrade of all Domain Controllers to current OS version"
            "Raise domain/forest functional level after all DCs are upgraded"
            "Remove any remaining legacy Domain Controllers"
            "Test application compatibility before raising functional level"
        )
        References = @(
            @{ Title = "Forest and Domain Functional Levels"; Url = "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels" }
        )
        MITRE = "T1078"
        Triggers = @(
            @{ Attribute = 'domainFunctionalLevel'; Pattern = 'Windows (2000|2003|2008)'; Severity = 'Hint' }
            @{ Attribute = 'forestFunctionalLevel'; Pattern = 'Windows (2000|2003|2008)'; Severity = 'Hint' }
        )
    }

    # ============================================================================
    # ANONYMOUS LDAP READABLE ATTRIBUTES
    # ============================================================================

    'ANON_LDAP_READABLE_ATTRS' = @{
        Title = "Anonymous LDAP Readable Attributes"
        Risk = "Hint"
        BaseScore = 20
        Description = "Specific attributes are readable via anonymous LDAP binding. While the Domain Controller allows anonymous access, these are the attributes that can be enumerated without authentication."
        Impact = @(
            "Unauthenticated enumeration of specific directory attributes"
            "Information gathering for targeted attacks"
        )
        Remediation = @(
            "Disable anonymous LDAP access entirely"
            "Restrict dsHeuristics to remove ANONYMOUS LOGON access"
        )
        References = @(
            @{ Title = "Anonymous LDAP Operations"; Url = "https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/anonymous-ldap-operations-active-directory-disabled" }
        )
        MITRE = "T1087"
        Triggers = @(
            @{ Attribute = 'anonymousReadableAttributes'; Severity = 'Hint' }
        )
    }

    # ============================================================================
    # LAPS UNPROTECTED COMPUTERS
    # ============================================================================

    'LAPS_UNPROTECTED_COMPUTERS' = @{
        Title = "Computers Without LAPS Protection"
        Risk = "Finding"
        BaseScore = 35
        Description = "These computers in the OU do not have LAPS deployed, meaning their local administrator passwords are not managed. Without LAPS, local admin passwords may be identical across systems, enabling lateral movement."
        Impact = @(
            "Local admin passwords may be identical across systems"
            "Compromising one system enables lateral movement via Pass-the-Hash"
            "No automatic password rotation for local accounts"
        )
        Remediation = @(
            "Deploy Windows LAPS to all computers in the OU"
            "Configure LAPS via GPO for password complexity and rotation"
        )
        References = @(
            @{ Title = "Windows LAPS Overview"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview" }
        )
        Tools = @("LAPSToolkit")
        MITRE = "T1078.003"
        Triggers = @(
            @{ Attribute = 'lapsUnprotectedComputers'; Severity = 'Finding' }
        )
    }

    # ============================================================================
    # GPO AFFECTED COMPUTER COUNT
    # ============================================================================

    'GPO_WIDE_IMPACT' = @{
        Title = "GPO Affects Many Computers"
        Risk = "Finding"
        BaseScore = 30
        Description = "This GPO finding affects a large number of computers. The wider the impact scope, the more critical the finding becomes, as exploitation would compromise more systems simultaneously."
        Impact = @(
            "GPO settings apply to all affected computers"
            "Malicious modifications impact multiple systems simultaneously"
            "Larger scope amplifies any security vulnerability"
        )
        Remediation = @(
            "Review GPO permissions and ensure strict access control"
            "Consider reducing GPO scope using security filtering or WMI filters"
        )
        References = @(
            @{ Title = "Group Policy Security"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview" }
        )
        MITRE = "T1484.001"
        Triggers = @(
            @{ Attribute = 'affectedComputerCount'; Custom = 'affected_computers_gt_10'; Severity = 'Finding' }
            @{ Attribute = 'affectedComputerCount'; Custom = 'affected_computers_gt_0'; Severity = 'Hint' }
        )
    }

    # ============================================================================
    # META / STATUS ATTRIBUTES
    # ============================================================================

    'LAPS_AUTHORIZATION' = @{
        Title = "LAPS Password Read Authorization"
        Risk = "Hint"
        BaseScore = 20
        Description = "This shows which principals are authorized to read LAPS passwords for computers in this scope. LAPS password read access should be limited to designated administrators following the tiered administration model."
        Impact = @(
            "Authorized principals can retrieve local admin passwords"
            "If overly broad, enables lateral movement for compromised accounts"
        )
        Remediation = @(
            "Review LAPS read permissions following tiered administration"
            "Only Tier 0/1 admins should read DC/server LAPS passwords"
        )
        References = @(
            @{ Title = "Windows LAPS"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview" }
        )
        Tools = @("LAPSToolkit")
        MITRE = "T1552.006"
        Triggers = @(
            @{ Attribute = 'msLAPS-AuthorizedGroup'; Severity = 'Hint' }
            @{ Attribute = 'msLAPS-AuthorizedSID'; Severity = 'Hint' }
        )
    }

    'GMSA_MEMBERSHIP_INFO' = @{
        Title = "gMSA Membership Information"
        Risk = "Hint"
        BaseScore = 15
        Description = "This shows the membership/principal configuration for a Group Managed Service Account (gMSA). The listed principals can retrieve the managed password for this service account."
        Impact = @(
            "Listed principals can obtain the gMSA password"
            "If broad groups are included, the gMSA password is widely accessible"
        )
        Remediation = @(
            "Ensure only required principals are in the gMSA membership"
            "Remove broad groups like Authenticated Users from gMSA access"
        )
        References = @(
            @{ Title = "gMSA Overview"; Url = "https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview" }
        )
        MITRE = "T1078"
        Triggers = @(
            @{ Attribute = 'msds-groupmsamembership'; Severity = 'Hint' }
            # Catch-all for PrincipalsAllowedToRetrievePassword: non-broad groups = Hint
            @{ Attribute = 'PrincipalsAllowedToRetrievePassword'; Severity = 'Hint'; SeverityOnly = $true }
        )
    }

    'ACL_INHERITED_FROM' = @{
        Title = "ACL Inheritance Source"
        Risk = "Note"
        BaseScore = 5
        Description = "This shows the source of inherited permissions. Understanding the inheritance chain helps identify where dangerous permissions originate from, which is essential for effective remediation."
        Impact = @(
            "Informational - shows permission inheritance path"
            "Helps trace the source of potentially dangerous permissions"
        )
        Remediation = @(
            "Review the source OU/container for overly broad permissions"
            "Consider breaking inheritance on sensitive OUs if appropriate"
        )
        References = @(
            @{ Title = "AD Delegation"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/delegating-administration-by-using-ou-objects" }
        )
        MITRE = "T1222.001"
        Triggers = @(
            @{ Attribute = 'inheritedFrom'; Severity = 'Note' }
        )
    }

    'ADMIN_COUNT_INDICATOR' = @{
        Title = "AdminCount Attribute Set"
        Risk = "Hint"
        BaseScore = 10
        Description = "This account has adminCount=1 set, indicating it is or was a member of a protected group managed by SDProp. If the account is no longer in any admin group, this may indicate an orphaned admin account."
        Impact = @(
            "Account is/was protected by SDProp"
            "Custom ACLs are reset by SDProp every 60 minutes"
            "May indicate orphaned admin account"
        )
        Remediation = @(
            "If no longer in admin groups, clear adminCount and reset ACLs"
        )
        References = @(
            @{ Title = "AdminSDHolder and SDProp"; Url = "https://adsecurity.org/?p=1906" }
        )
        MITRE = "T1078.002"
        Triggers = @(
            @{ Attribute = 'adminCount'; Pattern = '^1$'; Severity = 'Hint' }
        )
    }

    'LAPS_ACCOUNT_INFO' = @{
        Title = "LAPS Managed Account"
        Risk = "Finding"
        BaseScore = 40
        Description = "The LAPS managed account name is exposed. This shows which local account is being managed by LAPS on this computer."
        Impact = @(
            "Reveals the local admin account name managed by LAPS"
            "If the LAPS password is also readable, provides full local admin access"
        )
        Remediation = @(
            "Restrict LAPS attribute read permissions"
        )
        References = @(
            @{ Title = "Windows LAPS"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview" }
        )
        MITRE = "T1552.006"
        Triggers = @(
            @{ Attribute = 'msLAPS-Account'; Severity = 'Finding' }
        )
    }

    # Dangerous Rights severity indicator (Exchange groups, privileged users)
    'DANGEROUS_RIGHTS_SEVERITY' = @{
        Title = "Permission Classification"
        Risk = "Finding"
        BaseScore = 10
        Description = "This indicates the severity classification of the dangerous permissions found on this object. Expected/Attention means the permissions belong to privileged groups (like Exchange) and are by-design."
        Impact = @(
            "Expected/Attention: Permissions are by-design for privileged groups"
            "Finding: Permissions are unexpected and potentially dangerous"
        )
        Remediation = @(
            "Review unexpected permissions and remove if not required"
        )
        MITRE = "T1222.001"
        Triggers = @(
            @{ Attribute = 'dangerousRightsSeverity'; Pattern = '^(Expected|Attention|Hint)$'; Severity = 'Hint' }
            @{ Attribute = 'dangerousRightsSeverity'; Pattern = '^Finding$'; Severity = 'Finding'; SeverityOnly = $true }
        )
    }

    # Affected OUs by dangerous rights
    'DANGEROUS_RIGHTS_AFFECTED_OUS' = @{
        Title = "OUs Affected by Dangerous Permissions"
        Risk = "Hint"
        BaseScore = 20
        Description = "These OUs are affected by the dangerous permissions found. All objects within these OUs are subject to the identified ACL abuse paths."
        Impact = @(
            "All objects in listed OUs are affected"
            "Scope of impact depends on OU contents"
        )
        Remediation = @(
            "Review and restrict permissions on affected OUs"
        )
        MITRE = "T1222.001"
        Triggers = @(
            @{ Attribute = 'affectedOUs'; Severity = 'Hint' }
            @{ Attribute = 'right'; Severity = 'Finding' }
        )
    }

    # ADCS Template - Client Authentication EKU (severity trigger)
    'ADCS_CLIENT_AUTH_SEVERITY' = @{
        Title = "Client Authentication Enabled"
        Risk = "Hint"
        BaseScore = 15
        Description = "This certificate template includes the Client Authentication EKU, allowing PKINIT authentication."
        Impact = @(
            "Certificates can authenticate as the enrolled user"
        )
        Remediation = @(
            "Only enable Client Authentication EKU where required"
        )
        RemediationCommands = @(
            @{
                Description = "Remove Client Authentication EKU from template (if not required)"
                Command = "# Use certtmpl.msc - Extensions tab - Application Policies - Remove 'Client Authentication'"
            }
        )
        MITRE = "T1649"
        Triggers = @(
            @{ Attribute = 'ClientAuthentication'; Pattern = '^(True|Yes)$'; Severity = 'Hint'; SeverityOnly = $true }
        )
    }

    # ADCS Template - Manager Approval
    'ADCS_MANAGER_APPROVAL' = @{
        Title = "Manager Approval Status"
        Risk = "Hint"
        BaseScore = 10
        Description = "This shows whether CA manager approval is required for certificate requests from this template."
        Impact = @(
            "If not required: Certificates are issued automatically upon request"
            "If required: Provides manual review step preventing immediate exploitation"
        )
        Remediation = @(
            "Enable Manager Approval for sensitive templates"
        )
        RemediationCommands = @(
            @{
                Description = "Enable CA manager approval requirement"
                Command = "# Use certtmpl.msc - Issuance Requirements tab - check 'CA certificate manager approval'"
            }
        )
        MITRE = "T1649"
        Triggers = @(
            @{ Attribute = 'ManagerApprovalRequired'; Pattern = '^(True|Required)$'; Severity = 'Secure' }
            @{ Attribute = 'ManagerApprovalRequired'; Pattern = '^(False|Not Required)$'; Severity = 'Hint' }
            @{ Attribute = 'ManagerApproval'; Pattern = '^(True|Required)$'; Severity = 'Secure' }
            @{ Attribute = 'ManagerApproval'; Pattern = '^(False|Not Required)$'; Severity = 'Hint' }
        )
    }

    # Certificate Name/Enrollment Flags (severity-only triggers for flags)
    'CERT_FLAG_SEVERITY' = @{
        Title = "Certificate Template Flags"
        Risk = "Finding"
        BaseScore = 30
        Description = "Certificate template flag classifications for severity display."
        Impact = @(
            "Security-relevant certificate template flags affect enrollment behavior"
        )
        Remediation = @(
            "Review and secure certificate template flag configuration"
        )
        RemediationCommands = @(
            @{
                Description = "Disable ENROLLEE_SUPPLIES_SUBJECT flag via Certificate Templates Console"
                Command = "# Use certtmpl.msc - Subject Name tab - uncheck 'Supply in the request'"
            }
            @{
                Description = "Enable PEND_ALL_REQUESTS flag (require CA manager approval)"
                Command = "# Use certtmpl.msc - Issuance Requirements tab - check 'CA certificate manager approval'"
            }
            @{
                Description = "View template flags via certutil"
                Command = "certutil -dstemplate <TemplateName> | findstr `"msPKI-Certificate-Name-Flag msPKI-Enrollment-Flag`""
            }
        )
        MITRE = "T1649"
        Triggers = @(
            @{ Attribute = 'CertificateNameFlag'; Pattern = 'ENROLLEE_SUPPLIES_SUBJECT'; Severity = 'Finding'; SeverityOnly = $true }
            @{ Attribute = 'EnrollmentFlag'; Pattern = 'NO_SECURITY_EXTENSION'; Severity = 'Finding'; SeverityOnly = $true }
            @{ Attribute = 'EnrollmentFlag'; Pattern = 'PEND_ALL_REQUESTS'; Severity = 'Secure'; SeverityOnly = $true }
            @{ Attribute = 'EnrollmentFlagDisplay'; Pattern = 'NO_SECURITY_EXTENSION'; Severity = 'Finding'; SeverityOnly = $true }
            @{ Attribute = 'EnrollmentFlagDisplay'; Pattern = 'PEND_ALL_REQUESTS'; Severity = 'Secure'; SeverityOnly = $true }
        )
    }

    # Exchange Endpoints (WebEndpoints for Exchange, separate from ADCS WebEnrollmentEndpoints)
    'EXCHANGE_WEB_ENDPOINTS' = @{
        Title = "Exchange Web Endpoints Security"
        Risk = "Finding"
        BaseScore = 40
        Description = "Exchange web endpoints expose authentication interfaces. Endpoints using NTLM authentication are vulnerable to relay attacks unless Extended Protection for Authentication (EPA) is enabled. EPA binds authentication to the TLS channel, preventing relay."
        Impact = @(
            "HTTP + NTLM endpoints are vulnerable to NTLM relay"
            "HTTPS + NTLM without EPA is also vulnerable"
            "Relay attacks can compromise Exchange mailboxes"
        )
        Remediation = @(
            "Enable EPA on all Exchange endpoints"
            "Disable HTTP access and require HTTPS"
        )
        References = @(
            @{ Title = "Exchange Security Best Practices"; Url = "https://docs.microsoft.com/en-us/exchange/plan-and-deploy/post-installation-tasks/security-best-practices" }
        )
        MITRE = "T1187"
        Triggers = @(
            @{ Attribute = 'WebEndpoints'; Pattern = 'NTLM'; Severity = 'Finding' }
        )
    }

    # AllowedToActOnBehalfOfOtherIdentity alias
    'RBCD_ENABLED' = @{
        Title = "Resource-Based Constrained Delegation Configured"
        Risk = "Finding"
        BaseScore = 55
        Description = "Resource-Based Constrained Delegation (RBCD) is configured on this object. Principals in the RBCD list can impersonate any user to this resource."
        Impact = @(
            "Listed principals can impersonate any user to this computer"
            "Enables lateral movement through S4U2Proxy abuse"
        )
        Remediation = @(
            "Audit RBCD configurations and remove unnecessary entries"
        )
        References = @(
            @{ Title = "RBCD Attack"; Url = "https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd" }
        )
        Tools = @("Rubeus", "Impacket")
        MITRE = "T1550.003"
        Triggers = @(
            @{ Attribute = 'AllowedToActOnBehalfOfOtherIdentity'; Severity = 'Finding' }
        )
    }

    # Constrained Delegation (regular, non-protocol transition)
    'CONSTRAINED_DELEGATION' = @{
        Title = "Constrained Delegation Configured"
        Risk = "Finding"
        BaseScore = 40
        Description = "This account has constrained delegation configured. It can impersonate users to the specified services when they authenticate to this account."
        Impact = @(
            "Can impersonate authenticating users to configured target services"
            "If target includes LDAP/CIFS on DCs, privilege escalation possible"
        )
        Remediation = @(
            "Review if constrained delegation is still required"
            "Limit target services to minimum necessary"
        )
        RemediationCommands = @(
            @{
                Description = "Remove constrained delegation target SPNs"
                Command = "Set-ADUser -Identity 'ACCOUNT_NAME' -Clear msDS-AllowedToDelegateTo"
            }
            @{
                Description = "List all target SPNs for constrained delegation"
                Command = "Get-ADUser -Identity 'ACCOUNT_NAME' -Properties msDS-AllowedToDelegateTo | Select-Object -ExpandProperty msDS-AllowedToDelegateTo"
            }
            @{
                Description = "Find all accounts with constrained delegation"
                Command = "Get-ADObject -LDAPFilter '(msDS-AllowedToDelegateTo=*)' -Properties msDS-AllowedToDelegateTo,userAccountControl"
            }
        )
        References = @(
            @{ Title = "Constrained Delegation"; Url = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview" }
        )
        Tools = @("Rubeus", "Impacket")
        MITRE = "T1550.003"
    }

    # ============================================================================
    # LAPS INSTALLATION STATUS
    # ============================================================================

    'LAPS_INSTALLED' = @{
        Title = "Windows LAPS Installed"
        Risk = "Secure"
        BaseScore = 0
        Description = "Windows LAPS (Local Administrator Password Solution) is properly deployed. This provides automatic rotation of unique local administrator passwords for each computer."
        Impact = @(
            "Local admin passwords are unique per computer and automatically rotated"
            "Pass-the-Hash lateral movement with local admin is prevented"
        )
        Remediation = @()
        References = @(
            @{ Title = "Windows LAPS Overview"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview" }
        )
        MITRE = "M1026"
        Triggers = @(
            @{ Attribute = 'LapsInstalled'; Pattern = '^Windows LAPS'; Severity = 'Secure' }
        )
    }

    'LAPS_LEGACY' = @{
        Title = "Legacy LAPS Deployed"
        Risk = "Hint"
        BaseScore = 15
        Description = "Legacy Microsoft LAPS is deployed. While functional, consider upgrading to Windows LAPS which offers password encryption, improved auditing, and better integration with Azure AD."
        Impact = @(
            "Local admin passwords are managed but stored unencrypted in AD"
            "Any principal with read access to the LAPS attribute can see passwords"
        )
        Remediation = @(
            "Plan migration to Windows LAPS for enhanced security features"
        )
        References = @(
            @{ Title = "Windows LAPS vs Legacy LAPS"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview" }
        )
        MITRE = "M1026"
        Triggers = @(
            @{ Attribute = 'LapsInstalled'; Pattern = '^Legacy LAPS'; Severity = 'Hint' }
        )
    }

    'LAPS_LEGACY_ONLY' = @{
        Title = "Only Legacy LAPS Available"
        Risk = "Finding"
        BaseScore = 30
        Description = "Only legacy LAPS is available and Windows LAPS is not installed. Legacy LAPS stores passwords unencrypted in Active Directory."
        Impact = @(
            "Passwords stored in plaintext in AD attributes"
            "No password encryption or enhanced auditing available"
        )
        Remediation = @(
            "Deploy Windows LAPS alongside or replacing legacy LAPS"
        )
        References = @(
            @{ Title = "Windows LAPS"; Url = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview" }
        )
        MITRE = "T1552.006"
        Triggers = @(
            @{ Attribute = 'LapsInstalled'; Pattern = '^Not installed$'; Severity = 'Finding' }
        )
    }

    # ============================================================================
    # META-ATTRIBUTE SEVERITY DEFINITIONS (Pass-Through / Status Indicators)
    # ============================================================================

    # severity attribute: Pass-through - the value IS the severity
    'META_SEVERITY_PASSTHROUGH' = @{
        Title = "Severity Indicator"
        Risk = "Finding"
        BaseScore = 0
        Description = "Pass-through severity attribute. The attribute value directly indicates the severity level."
        Triggers = @(
            @{ Attribute = 'severity'; Pattern = '^Finding$'; Severity = 'Finding'; SeverityOnly = $true }
            @{ Attribute = 'severity'; Pattern = '^Hint$'; Severity = 'Hint'; SeverityOnly = $true }
            @{ Attribute = 'severity'; Pattern = '^Note$'; Severity = 'Note'; SeverityOnly = $true }
            @{ Attribute = 'severity'; Pattern = '^Secure$'; Severity = 'Secure'; SeverityOnly = $true }
        )
    }

    # status attribute: Handles both adPEAS severity values and PKI certificate status
    'META_STATUS_INDICATOR' = @{
        Title = "Status Indicator"
        Risk = "Finding"
        BaseScore = 0
        Description = "Status attribute handling both severity values and PKI certificate status."
        Triggers = @(
            @{ Attribute = 'status'; Pattern = '^Finding$'; Severity = 'Finding'; SeverityOnly = $true }
            @{ Attribute = 'status'; Pattern = '^Hint$'; Severity = 'Hint'; SeverityOnly = $true }
            @{ Attribute = 'status'; Pattern = '^Note$'; Severity = 'Note'; SeverityOnly = $true }
            @{ Attribute = 'status'; Pattern = '^Secure$'; Severity = 'Secure'; SeverityOnly = $true }
            @{ Attribute = 'status'; Pattern = '(?i)^EXPIRED$'; Severity = 'Finding'; SeverityOnly = $true }
            @{ Attribute = 'status'; Pattern = '(?i)not yet valid'; Severity = 'Hint'; SeverityOnly = $true }
        )
    }

    # isSecure attribute: Boolean -> Secure/Finding
    'META_SECURE_INDICATOR' = @{
        Title = "Secure Configuration Indicator"
        Risk = "Finding"
        BaseScore = 0
        Description = "Boolean attribute indicating whether a configuration is secure."
        Triggers = @(
            @{ Attribute = 'isSecure'; Pattern = '^True$'; Severity = 'Secure'; SeverityOnly = $true }
            @{ Attribute = 'isSecure'; Pattern = '^False$'; Severity = 'Finding'; SeverityOnly = $true }
            # Catch-all: any non-True value = Finding
            @{ Attribute = 'isSecure'; Severity = 'Finding'; SeverityOnly = $true }
        )
    }

    # isDefault attribute: True = using defaults = Hint
    'META_DEFAULT_INDICATOR' = @{
        Title = "Default Configuration Indicator"
        Risk = "Hint"
        BaseScore = 0
        Description = "Boolean attribute indicating whether a default configuration value is in use."
        Triggers = @(
            @{ Attribute = 'isDefault'; Pattern = '^True$'; Severity = 'Hint'; SeverityOnly = $true }
        )
    }

    # userName in credential context: Always Finding (exposed credentials)
    'CREDENTIAL_USERNAME_EXPOSED' = @{
        Title = "Username in Credential Exposure"
        Risk = "Finding"
        BaseScore = 0
        Description = "A username was found in a credential exposure context."
        Triggers = @(
            @{ Attribute = 'userName'; Severity = 'Finding'; SeverityOnly = $true }
        )
    }

    # password in credential context: Always Finding (exposed credentials)
    'CREDENTIAL_PASSWORD_EXPOSED' = @{
        Title = "Password in Credential Exposure"
        Risk = "Finding"
        BaseScore = 0
        Description = "A password was found in a credential exposure context."
        Triggers = @(
            @{ Attribute = 'password'; Severity = 'Finding'; SeverityOnly = $true }
        )
    }

    # matchedLine with credential context override
    'CREDENTIAL_MATCHED_LINE' = @{
        Title = "Credential Matched Line"
        Risk = "Finding"
        BaseScore = 0
        Description = "A line matching credential patterns was found."
        Triggers = @(
            # Tier2 patterns (needs review) = Hint, determined by Custom trigger
            @{ Attribute = 'matchedLine'; Custom = 'credential_needs_review'; Severity = 'Hint'; SeverityOnly = $true }
            # Default: any matchedLine = Finding
            @{ Attribute = 'matchedLine'; Severity = 'Finding'; SeverityOnly = $true }
        )
    }

    # credentialType with context override
    'CREDENTIAL_TYPE_INFO' = @{
        Title = "Credential Type Information"
        Risk = "Hint"
        BaseScore = 0
        Description = "Information about the type of credential exposure found."
        Triggers = @(
            # Tier2 patterns (needs review) = Hint
            @{ Attribute = 'credentialType'; Custom = 'credential_needs_review'; Severity = 'Hint'; SeverityOnly = $true }
            # Default: any credentialType = Hint
            @{ Attribute = 'credentialType'; Severity = 'Hint'; SeverityOnly = $true }
        )
    }

    # msLAPS-EncryptedPassword: Hint (still sensitive but encrypted)
    'LAPS_ENCRYPTED_PASSWORD' = @{
        Title = "LAPS Encrypted Password Accessible"
        Risk = "Hint"
        BaseScore = 20
        Description = "The encrypted LAPS password is accessible. While encrypted, this still indicates password retrieval capability."
        Triggers = @(
            @{ Attribute = 'msLAPS-EncryptedPassword'; Severity = 'Hint'; SeverityOnly = $true }
        )
    }

    # Owner with non-default owner check
    'NON_DEFAULT_OWNER' = @{
        Title = "Non-Default Object Owner"
        Risk = "Hint"
        BaseScore = 15
        Description = "This object has a non-default owner. Non-default owners have implicit full control over the object."
        Triggers = @(
            @{ Attribute = 'Owner'; Custom = 'is_not_default_owner'; Severity = 'Hint'; SeverityOnly = $true }
        )
    }

    # servicePrincipalName on user accounts (Kerberoastable)
    'KERBEROASTABLE_USER_SPN' = @{
        Title = "User Account with SPN (Kerberoastable)"
        Risk = "Finding"
        BaseScore = 0
        Description = "User account has Service Principal Names, making it vulnerable to Kerberoasting."
        Triggers = @(
            @{ Attribute = 'servicePrincipalName'; Custom = 'is_not_computer'; Severity = 'Finding'; SeverityOnly = $true }
        )
    }

    # dangerousRights with context-override
    'DANGEROUS_RIGHTS_CONTEXT' = @{
        Title = "Dangerous Rights (Context-Aware)"
        Risk = "Finding"
        BaseScore = 0
        Description = "Dangerous AD permissions (GenericAll, WriteDACL, WriteOwner, ForceChangePassword, etc.) allow privilege escalation and unauthorized access. These ACL misconfigurations enable attackers to compromise additional accounts, modify permissions, and escalate to domain admin."
        Impact = @(
            "Privilege escalation to high-value accounts possible"
            "Unauthorized modification of group memberships (adding users to Domain Admins)"
            "Password resets on privileged accounts"
            "ACL manipulation enabling persistent backdoors"
            "Ownership changes leading to complete object control"
        )
        Attack = @(
            "1. Attacker compromises low-privileged user with GenericAll on Domain Admins group"
            "2. Uses Add-DomainGroupMember to add attacker account to Domain Admins"
            "3. Alternatively, WriteDACL allows adding new ACE granting attacker Full Control"
            "4. WriteOwner enables taking ownership of sensitive objects (AdminSDHolder, GPOs)"
            "5. ForceChangePassword allows resetting passwords of privileged accounts"
        )
        Remediation = @(
            "Audit all ACLs using BloodHound, PingCastle, or Defender for Identity"
            "Remove unnecessary GenericAll, WriteDACL, WriteOwner permissions"
            "Ensure only appropriate groups have dangerous permissions on high-value objects"
            "Monitor AdminSDHolder ACL for unauthorized modifications"
            "Implement Protected Users security group for sensitive accounts"
            "Enable advanced auditing for ACL changes (Event ID 4670, 5136)"
            "Review and remediate attack paths identified by BloodHound"
        )
        References = @(
            @{ Title = "Total Identity Compromise - Active Directory ACL Abuse"; Url = "https://techcommunity.microsoft.com/blog/microsoftsecurityexperts/total-identity-compromise-microsoft-incident-response-lessons-on-securing-active/3753391" }
            @{ Title = "Active Directory Access Control List - Attacks and Defense"; Url = "https://techcommunity.microsoft.com/t5/security-compliance-and-identity/active-directory-access-control-list-8211-attacks-and-defense/ba-p/250315" }
            @{ Title = "Abusing Active Directory ACLs/ACEs"; Url = "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces" }
            @{ Title = "DACL Abuse - The Hacker Recipes"; Url = "https://www.thehacker.recipes/ad/movement/dacl/" }
        )
        Tools = @("BloodHound", "PowerView", "Impacket dacledit.py", "Defender for Identity")
        MITRE = "T1078.002"
        Triggers = @(
            # Expected/Attention permissions (Exchange groups, privileged users) = Hint
            @{ Attribute = 'dangerousRights'; Custom = 'dangerous_rights_expected'; Severity = 'Hint'; SeverityOnly = $true }
            @{ Attribute = 'DangerousPermissions'; Custom = 'dangerous_rights_expected'; Severity = 'Hint'; SeverityOnly = $true }
            @{ Attribute = 'DangerousSettings'; Custom = 'dangerous_rights_expected'; Severity = 'Hint'; SeverityOnly = $true }
            @{ Attribute = 'right'; Custom = 'dangerous_rights_expected'; Severity = 'Hint'; SeverityOnly = $true }
            @{ Attribute = 'affectedOUs'; Custom = 'dangerous_rights_expected'; Severity = 'Hint'; SeverityOnly = $true }
            # Default: non-expected permissions = Finding
            @{ Attribute = 'dangerousRights'; Severity = 'Finding'; SeverityOnly = $true }
            @{ Attribute = 'DangerousPermissions'; Severity = 'Finding'; SeverityOnly = $true }
            @{ Attribute = 'DangerousSettings'; Severity = 'Finding'; SeverityOnly = $true }
        )
    }

    # Scope attribute (GPO scope) - only color when GPO has actual findings
    'GPO_SCOPE_SEVERITY' = @{
        Title = "GPO Scope Classification"
        Risk = "Finding"
        BaseScore = 0
        Description = "GPO scope classification based on link target."
        Triggers = @(
            @{ Attribute = 'Scope'; Pattern = 'Domain-wide'; Custom = 'is_gpo_finding_object'; Severity = 'Finding'; SeverityOnly = $true }
            @{ Attribute = 'Scope'; Pattern = 'NOT LINKED'; Severity = 'Hint'; SeverityOnly = $true }
        )
    }

    # LinkedOUs (GPO linked to domain root) - only color when GPO has actual findings
    'GPO_LINKED_OUS_SEVERITY' = @{
        Title = "GPO Linked to Domain Root"
        Risk = "Finding"
        BaseScore = 0
        Description = "GPO linkage classification - domain root linkage affects the entire domain."
        Triggers = @(
            @{ Attribute = 'LinkedOUs'; Pattern = '^DC=[^,]+,DC='; Custom = 'is_gpo_finding_object'; Severity = 'Finding'; SeverityOnly = $true }
        )
    }

    # WebEndpoints/WebEnrollmentEndpoints with NTLM/HTTP/EPA checks
    'WEB_ENDPOINT_SECURITY' = @{
        Title = "Web Endpoint Security Classification"
        Risk = "Finding"
        BaseScore = 0
        Description = "Web endpoint security classification based on protocol, authentication and EPA status."
        Triggers = @(
            # HTTP + NTLM = Critical (relay possible)
            @{ Attribute = 'WebEndpoints'; Pattern = 'via HTTP[^S]|via HTTP$'; Severity = 'Finding'; SeverityOnly = $true }
            @{ Attribute = 'WebEnrollmentEndpoints'; Pattern = 'via HTTP[^S]|via HTTP$'; Severity = 'Finding'; SeverityOnly = $true }
            # EPA Enabled = Secure
            @{ Attribute = 'WebEndpoints'; Pattern = '\[EPA:\s*Enabled\]'; Severity = 'Secure'; SeverityOnly = $true }
            @{ Attribute = 'WebEnrollmentEndpoints'; Pattern = '\[EPA:\s*Enabled\]'; Severity = 'Secure'; SeverityOnly = $true }
            # NTLM + EPA Disabled = Finding
            @{ Attribute = 'WebEndpoints'; Pattern = '\[EPA:\s*Disabled\]'; Severity = 'Finding'; SeverityOnly = $true }
            @{ Attribute = 'WebEnrollmentEndpoints'; Pattern = '\[EPA:\s*Disabled\]'; Severity = 'Finding'; SeverityOnly = $true }
        )
    }

    # Hardcoded scriptPath (UNC or absolute local path)
    'SCRIPTPATH_HARDCODED' = @{
        Title = "Hardcoded Logon Script Path"
        Risk = "Hint"
        BaseScore = 30
        Description = "This user account has a scriptPath attribute pointing to a UNC path (e.g., \\server\share\script.bat) or an absolute local path (e.g., C:\scripts\logon.bat) instead of a relative path resolved via NETLOGON. This is unusual and may indicate persistence, backdoor activity, or a misconfiguration that could be exploited for code execution."
        Impact = @(
            "UNC paths can point to attacker-controlled SMB servers, enabling code execution on user logon"
            "Absolute local paths bypass NETLOGON share protections and GPO-based script management"
            "Logon scripts execute with the user's privileges — privileged accounts amplify the risk"
            "An attacker who can modify scriptPath can achieve persistence without touching NETLOGON"
        )
        Attack = @(
            "1. Attacker modifies scriptPath to point to an attacker-controlled UNC share (\\evil\share\payload.bat)"
            "2. User logs on and Windows executes the script from the UNC path"
            "3. Attacker gains code execution in the user's security context"
            "4. If the user is privileged, the attacker escalates privileges"
        )
        Remediation = @(
            "Use only relative paths in scriptPath that resolve via the NETLOGON share"
            "Prefer Group Policy-based logon scripts over per-user scriptPath settings"
            "Monitor scriptPath changes, especially to UNC or absolute paths"
            "Audit who has WriteProperty permissions on scriptPath in affected OUs"
        )
        References = @(
            @{ Title = "Boot or Logon Initialization Scripts - MITRE ATT&CK"; Url = "https://attack.mitre.org/techniques/T1037/001/" }
            @{ Title = "scriptPath Attribute - Microsoft"; Url = "https://learn.microsoft.com/en-us/windows/win32/adschema/a-scriptpath" }
        )
        Tools = @("PowerView", "BloodHound", "ADExplorer")
        MITRE = "T1037.001"
        Triggers = @(
            @{ Attribute = 'scriptPath'; Custom = 'is_hardcoded_path'; Severity = 'Hint' }
        )
    }

    # UAC flags with DC context
    'UAC_SEVERITY_OVERRIDE' = @{
        Title = "User Account Control Severity Classification"
        Risk = "Finding"
        BaseScore = 0
        Description = "UAC flag severity classification with DC context awareness."
        Triggers = @(
            # DONT_REQ_PREAUTH and ENCRYPTED_TEXT always Finding
            @{ Attribute = 'userAccountControl'; Pattern = 'DONT_REQ_PREAUTH|ENCRYPTED_TEXT_PWD_ALLOWED'; Severity = 'Finding'; SeverityOnly = $true }
            # TRUSTED_FOR_DELEGATION on DC = Hint (expected)
            @{ Attribute = 'userAccountControl'; Pattern = 'TRUSTED_FOR_DELEGATION'; Custom = 'is_dc_uac'; Severity = 'Hint'; SeverityOnly = $true }
            # TRUSTED_FOR_DELEGATION on non-DC = Finding
            @{ Attribute = 'userAccountControl'; Pattern = 'TRUSTED_FOR_DELEGATION'; Severity = 'Finding'; SeverityOnly = $true }
            # Noteworthy flags = Hint
            @{ Attribute = 'userAccountControl'; Pattern = 'PASSWD_NOTREQD|DONT_EXPIRE_PASSWORD|INTERDOMAIN_TRUST_ACCOUNT'; Severity = 'Hint'; SeverityOnly = $true }
            # Secure flags
            @{ Attribute = 'userAccountControl'; Pattern = 'ACCOUNTDISABLE|SMARTCARD_REQUIRED|NOT_DELEGATED'; Severity = 'Secure'; SeverityOnly = $true }
        )
    }
}

<#
.SYNOPSIS
    Exports finding definitions as JSON for embedding in HTML.
.PARAMETER Minified
    If set, outputs minified JSON without indentation.
.RETURNS
    JSON string of all finding definitions.
#>
function Export-FindingDefinitionsJson {
    [CmdletBinding()]
    param(
        [switch]$Minified
    )

    # Convert hashtable to format suitable for JSON
    $jsonObject = @{}

    foreach ($key in $Script:FindingDefinitions.Keys) {
        $def = $Script:FindingDefinitions[$key]

        # Convert References array of hashtables to array of objects
        $refs = [System.Collections.Generic.List[object]]::new()
        if ($def.References) {
            foreach ($ref in $def.References) {
                $refs.Add(@{ title = $ref.Title; url = $ref.Url })
            }
        }

        # Convert Tools - support both old string format and new object format
        $tools = [System.Collections.Generic.List[object]]::new()
        if ($def.Tools) {
            foreach ($tool in $def.Tools) {
                if ($tool -is [hashtable] -or $tool -is [System.Collections.Specialized.OrderedDictionary]) {
                    $tools.Add(@{ name = $tool.Name; url = $tool.Url })
                } else {
                    # String format - resolve URL from central repository
                    $toolUrl = $Script:ToolUrls[$tool]
                    $tools.Add(@{ name = [string]$tool; url = $toolUrl })
                }
            }
        }

        # Convert RemediationCommands array of hashtables to array of objects
        $remediationCmds = [System.Collections.Generic.List[object]]::new()
        if ($def.RemediationCommands) {
            foreach ($cmd in $def.RemediationCommands) {
                $remediationCmds.Add(@{ description = $cmd.Description; command = $cmd.Command })
            }
        }

        $jsonObject[$key] = @{
            title = $def.Title
            risk = $def.Risk
            baseScore = $def.BaseScore
            description = $def.Description
            impact = $def.Impact
            attack = $def.Attack
            remediation = $def.Remediation
            remediationCommands = $remediationCmds.ToArray()
            references = $refs.ToArray()
            tools = $tools.ToArray()
            mitre = $def.MITRE
        }
    }

    if ($Minified) {
        return ($jsonObject | ConvertTo-Json -Depth 10 -Compress)
    } else {
        return ($jsonObject | ConvertTo-Json -Depth 10)
    }
}

# =============================================================================
# BUILD INVERTED INDEX for fast attribute → FindingId + Severity lookup
# =============================================================================
# Reads Triggers from each FindingDefinition and builds an inverted index.
# Used by Get-FindingIdForAttribute (tooltip lookup) and Get-SeverityFromTrigger (severity).
#
# Structure: $Script:FindingTriggerIndex['attributeName'] = @(
#   @{ FindingId = 'XXX'; Pattern = 'regex'; ExcludePattern = 'regex'; Context = 'ctx';
#      Custom = 'func'; Severity = 'Hint'; ParentRisk = 'Finding' }
# )
#
# Severity resolution order:
#   1. Trigger.Severity (explicit per-trigger override, e.g. "Hint" for Optional values)
#   2. FindingDefinition.Risk (parent definition risk level, e.g. "Finding")

$Script:FindingTriggerIndex = @{}
$triggerLists = @{}  # Temporary List<object> per attribute for O(1) append

foreach ($findingId in $Script:FindingDefinitions.Keys) {
    $definition = $Script:FindingDefinitions[$findingId]

    # Skip if no Triggers defined
    if (-not $definition.ContainsKey('Triggers') -or $null -eq $definition.Triggers) {
        continue
    }

    foreach ($trigger in $definition.Triggers) {
        if (-not $trigger.Attribute) { continue }

        $attrName = $trigger.Attribute.ToLower()

        if (-not $triggerLists.ContainsKey($attrName)) {
            $triggerLists[$attrName] = [System.Collections.Generic.List[object]]::new()
        }

        $triggerLists[$attrName].Add(@{
            FindingId      = $findingId
            Pattern        = $trigger.Pattern
            ExcludePattern = $trigger.ExcludePattern
            Context        = $trigger.Context
            Custom         = $trigger.Custom
            Severity       = $trigger.Severity      # Optional: per-trigger severity override
            SeverityOnly   = $trigger.SeverityOnly   # If $true, Get-FindingIdForAttribute skips this
            ParentRisk     = $definition.Risk        # Parent definition risk level
        })
    }
}

# Convert Lists to arrays for the final index (arrays are faster to iterate)
foreach ($key in $triggerLists.Keys) {
    $Script:FindingTriggerIndex[$key] = $triggerLists[$key].ToArray()
}
Remove-Variable -Name triggerLists -ErrorAction SilentlyContinue

<#
.SYNOPSIS
    Maps attribute names/values to finding definition IDs for tooltip display.
.DESCRIPTION
    Thin wrapper around Get-TriggerMatch that returns only the FindingId.
    Returns $null if no tooltip should be shown.
.PARAMETER Name
    The attribute name (e.g., 'servicePrincipalName', 'userAccountControl').
.PARAMETER Value
    The attribute value to check against patterns.
.PARAMETER Context
    Optional context string for context-specific triggers.
.RETURNS
    FindingId string or $null.
#>
function Get-FindingIdForAttribute {
    [CmdletBinding()]
    param(
        [string]$Name,
        $Value,
        [string]$Context = $null
    )

    $match = Get-TriggerMatch -Name $Name -Value $Value -Context $Context
    return $match.FindingId
}

<#
.SYNOPSIS
    Determines attribute severity from FindingDefinitions triggers.
.DESCRIPTION
    Thin wrapper around Get-TriggerMatch that returns only the Severity.
    Returns $null if no trigger matches (caller should use "Standard" as fallback).
.PARAMETER Name
    The attribute name (e.g., 'LDAPSigning', 'servicePrincipalName').
.PARAMETER Value
    The attribute value to check against patterns.
.PARAMETER IsComputer
    Set to $true if the source object is a computer account.
.PARAMETER SourceObject
    Optional. The source AD object for context-aware triggers.
.PARAMETER Context
    Optional context string for context-specific triggers.
.RETURNS
    Severity string ("Finding", "Hint", "Secure", "Note") or $null if no trigger matches.
#>
function Get-SeverityFromTrigger {
    [CmdletBinding()]
    param(
        [string]$Name,
        $Value,
        [bool]$IsComputer = $false,
        $SourceObject = $null,
        [string]$Context = $null
    )

    $match = Get-TriggerMatch -Name $Name -Value $Value -IsComputer $IsComputer `
        -SourceObject $SourceObject -Context $Context
    $severity = $match.Severity
    if ($severity -eq 'Standard') { return $null }
    return $severity
}

<#
.SYNOPSIS
    Combined severity and FindingId lookup in a single pass.
.DESCRIPTION
    Returns both severity and FindingId for an attribute value from FindingDefinitions.
    Eliminates the need for separate Get-AttributeSeverity + Get-FindingIdForAttribute calls.

    The function performs two lookups:
    1. Severity: Via two-pass evaluation (SeverityOnly triggers first, then normal triggers)
    2. FindingId: Via normal triggers only (SeverityOnly triggers are excluded)

    When both are found in the same trigger match, only one index lookup is needed.
.PARAMETER Name
    The attribute name.
.PARAMETER Value
    The attribute value.
.PARAMETER IsComputer
    Whether the source object is a computer account.
.PARAMETER SourceObject
    The source AD object for context-aware triggers.
.PARAMETER Context
    Optional context string for context-specific triggers.
.RETURNS
    PSCustomObject with Severity (string or "Standard") and FindingId (string or $null).
    Returns $null if attribute has no triggers at all.
#>
function Get-TriggerMatch {
    [CmdletBinding()]
    param(
        [string]$Name,
        $Value,
        [bool]$IsComputer = $false,
        $SourceObject = $null,
        [string]$Context = $null
    )

    # Default return object for no-match cases
    $noMatch = [PSCustomObject]@{ Severity = 'Standard'; FindingId = $null }

    if ([string]::IsNullOrEmpty($Name)) { return $noMatch }

    # Auto-detect IsComputer from SourceObject via central helper
    if (-not $IsComputer -and $SourceObject) {
        $IsComputer = Test-IsComputerObject -Object $SourceObject
    }

    $attrNameLower = $Name.ToLower()
    $strValue = [string]$Value

    if (-not $Script:FindingTriggerIndex.ContainsKey($attrNameLower)) {
        return $noMatch
    }

    $triggers = $Script:FindingTriggerIndex[$attrNameLower]
    $resultSeverity = $null
    $resultFindingId = $null

    # Pass 1: SeverityOnly triggers (priority for severity)
    # Pass 2: Normal triggers (provide both severity fallback and FindingId)
    foreach ($pass in @($true, $false)) {
        foreach ($trigger in $triggers) {
            $isSeverityOnly = [bool]$trigger.SeverityOnly
            if ($isSeverityOnly -ne $pass) { continue }

            # Check Context requirement
            if ($trigger.Context) {
                if (-not $Context -or $Context -notmatch $trigger.Context) { continue }
            }

            # Check ExcludePattern
            if ($trigger.ExcludePattern) {
                if ($strValue -match $trigger.ExcludePattern) { continue }
            }

            # Determine if trigger matches
            $matched = $false
            if ($trigger.Custom) {
                $customResult = Test-CustomTrigger -CustomType $trigger.Custom -Value $Value `
                    -IsComputer $IsComputer -SourceObject $SourceObject
                if (-not $customResult) { continue }
                if ($trigger.Pattern) {
                    if ($strValue -notmatch $trigger.Pattern) { continue }
                }
                $matched = $true
            } elseif ($trigger.Pattern) {
                if ($strValue -match $trigger.Pattern) { $matched = $true }
            } else {
                $matched = $true
            }

            if (-not $matched) { continue }

            # Extract severity from matched trigger
            if ($null -eq $resultSeverity) {
                $resultSeverity = if ($trigger.Severity) { $trigger.Severity } else { $trigger.ParentRisk }
            }

            # Extract FindingId from non-SeverityOnly triggers
            if ($null -eq $resultFindingId -and -not $isSeverityOnly) {
                $resultFindingId = $trigger.FindingId
            }

            # If we have both, we can stop early
            if ($null -ne $resultSeverity -and $null -ne $resultFindingId) {
                break
            }
        }

        # If we have both after pass 1, skip pass 2
        if ($null -ne $resultSeverity -and $null -ne $resultFindingId) {
            break
        }
    }

    if ($null -eq $resultSeverity -and $null -eq $resultFindingId) {
        return $noMatch
    }

    return [PSCustomObject]@{
        Severity  = if ($resultSeverity) { $resultSeverity } else { 'Standard' }
        FindingId = $resultFindingId
    }
}

<#
.SYNOPSIS
    Evaluates custom trigger conditions.
.DESCRIPTION
    Handles special cases that can't be expressed as simple regex patterns.
    Supports SourceObject for context-aware triggers (SID-based, computer detection).
#>
function Test-CustomTrigger {
    param(
        [string]$CustomType,
        $Value,
        [bool]$IsComputer = $false,
        $SourceObject = $null
    )

    switch ($CustomType) {
        # =====================================================================
        # Context-aware triggers (require SourceObject)
        # =====================================================================

        'is_not_computer' {
            # Returns true if the source object is NOT a computer account
            # Used for servicePrincipalName: SPNs on user accounts = Finding, on computers = expected
            if ($IsComputer) { return $false }
            if ($SourceObject -and (Test-IsComputerObject -Object $SourceObject)) {
                return $false
            }
            return $true
        }

        'is_privileged_sid' {
            # Returns true if the SID belongs to a privileged group/user
            $sid = if ($Value -is [string] -and $Value -match '^S-1-') { $Value }
                   elseif ($Value -is [PSCustomObject] -and $Value.PSObject.Properties['SID']) { $Value.SID }
                   else { $null }
            if (-not $sid) { return $false }
            $privResult = Test-IsPrivileged -Identity $sid
            return ($privResult.Category -eq 'Privileged')
        }

        'is_operator_sid' {
            # Returns true if the SID belongs to an operator group
            $sid = if ($Value -is [string] -and $Value -match '^S-1-') { $Value }
                   elseif ($Value -is [PSCustomObject] -and $Value.PSObject.Properties['SID']) { $Value.SID }
                   else { $null }
            if (-not $sid) { return $false }
            $privResult = Test-IsPrivileged -Identity $sid
            return ($privResult.Category -eq 'Operator')
        }

        'is_broad_group_sid' {
            # Returns true if the SID is a broad group (Everyone, Authenticated Users, Domain Users)
            $sid = if ($Value -is [string] -and $Value -match '^S-1-') { $Value }
                   elseif ($Value -is [PSCustomObject] -and $Value.PSObject.Properties['SID']) { $Value.SID }
                   else { [string]$Value }
            if (-not $sid) { return $false }
            if (Get-Command -Name 'Test-IsBroadGroupSID' -ErrorAction SilentlyContinue) {
                return (Test-IsBroadGroupSID -SID $sid)
            }
            # Fallback: check common broad group SID patterns
            $privResult = Test-IsPrivileged -Identity $sid
            return ($privResult.Category -eq 'BroadGroup')
        }

        'is_not_default_owner' {
            # Returns true if the Owner SID is NOT a default owner (DA, EA, Administrators, SYSTEM)
            if ($SourceObject -and $SourceObject.OwnerSID) {
                $isDefault = Test-IsDefaultOwner -SID $SourceObject.OwnerSID
                return (-not $isDefault)
            }
            return $false
        }

        'is_within_forest_trust' {
            # Returns true if the trust is a within-forest trust (for SID filtering context)
            if ($SourceObject -and $SourceObject.isWithinForest -eq $true) {
                return $true
            }
            return $false
        }

        'is_gpo_finding_object' {
            # Returns true if the GPO object has DangerousPermissions or DangerousSettings
            # Used to prevent Scope/LinkedOUs severity coloring on informational GPO displays
            # (e.g. LDAPConfigGPO, SMBSigningGPO) where domain-wide scope is just context, not a finding
            if (-not $SourceObject) { return $false }
            $hasDangerousPerms = $SourceObject.PSObject.Properties['DangerousPermissions'] -and $SourceObject.DangerousPermissions
            $hasDangerousSettings = $SourceObject.PSObject.Properties['DangerousSettings'] -and $SourceObject.DangerousSettings
            return ($hasDangerousPerms -or $hasDangerousSettings)
        }

        'is_hardcoded_path' {
            # Returns true if scriptPath is a UNC path (\\server\share) or absolute local path (C:\...)
            $strVal = [string]$Value
            if ([string]::IsNullOrWhiteSpace($strVal)) { return $false }
            return ($strVal -match '^\\\\[^\\]+\\' -or $strVal -match '^[A-Za-z]:[\\\/]')
        }

        'is_dc_uac' {
            # Returns true if userAccountControl flags contain SERVER_TRUST_ACCOUNT (Domain Controller)
            # SourceObject contains all UAC flags joined by space (from UAC transformer)
            $allFlags = if ($SourceObject) { [string]$SourceObject } else { [string]$Value }
            return ($allFlags -match 'SERVER_TRUST_ACCOUNT')
        }

        'is_exchange_eol' {
            # Returns true if the Exchange version/build is EOL (not Standard severity)
            # For ExchangeBuildNumber: check build directly
            # For ExchangeVersion: check via SourceObject for build number
            $strValue = [string]$Value
            $severity = 'Standard'
            if ($strValue -match '^\d+\.\d+\.\d+') {
                # Build number format (e.g., 15.2.2562.37)
                $severity = Get-ExchangeSeverity -BuildNumber $strValue
            } elseif ($SourceObject) {
                # ExchangeVersion attribute - check SourceObject for build number
                $buildNum = if ($SourceObject.PSObject.Properties['ExchangeBuildNumber']) { $SourceObject.ExchangeBuildNumber } else { $null }
                if ($buildNum) {
                    $severity = Get-ExchangeSeverity -BuildNumber $buildNum
                } else {
                    $severity = Get-ExchangeSeverity -ProductName $strValue
                }
            } else {
                $severity = Get-ExchangeSeverity -ProductName $strValue
            }
            return ($severity -ne 'Standard')
        }

        'credential_needs_review' {
            # Returns true if the source object has credentialType "(needs review)" (Tier2 pattern)
            if ($SourceObject -and $SourceObject.credentialType -and $SourceObject.credentialType -match '\(needs review\)') {
                return $true
            }
            return $false
        }

        'dangerous_rights_expected' {
            # Returns true if dangerousRightsSeverity indicates expected/privileged permissions
            if ($SourceObject -and $SourceObject.dangerousRightsSeverity) {
                return ($SourceObject.dangerousRightsSeverity -in @('Expected', 'Attention', 'Hint'))
            }
            return $false
        }

        'is_dnsadmins_sid' {
            # Returns true if the SID resolves to DnsAdmins (no fixed RID)
            $sid = if ($Value -is [string] -and $Value -match '^S-1-') { $Value }
                   elseif ($Value -is [PSCustomObject] -and $Value.PSObject.Properties['SID']) { $Value.SID }
                   else { $null }
            if (-not $sid) { return $false }
            $resolvedName = ConvertFrom-SID -SID $sid
            return ($resolvedName -match '\\DnsAdmins$')
        }

        'days_over_365' {
            # Integer value > 365 (for daysSinceLastLogon/krbtgtPasswordAge)
            $strValue = [string]$Value
            if ($strValue -match '^(\d+)') {
                return ([int]$Matches[1] -gt 365)
            }
            return $false
        }

        'days_91_to_365' {
            # Integer value in range 91-365 (> 90 and <= 365)
            $strValue = [string]$Value
            if ($strValue -match '^(\d+)') {
                $days = [int]$Matches[1]
                return ($days -gt 90 -and $days -le 365)
            }
            return $false
        }

        'days_181_to_365' {
            # Integer value in range 181-365 (> 180 and <= 365)
            $strValue = [string]$Value
            if ($strValue -match '^(\d+)') {
                $days = [int]$Matches[1]
                return ($days -gt 180 -and $days -le 365)
            }
            return $false
        }

        'lt_8' {
            # Integer value < 8 or "Disabled" (for minimum password length = Finding)
            $strValue = [string]$Value
            if ($strValue -match 'Disabled') { return $true }
            $intValue = 0
            if ([int]::TryParse($strValue, [ref]$intValue)) {
                return ($intValue -lt 8)
            }
            if ($strValue -match '^(\d+)') {
                if ([int]::TryParse($Matches[1], [ref]$intValue)) {
                    return ($intValue -lt 8)
                }
            }
            return $false
        }

        'affected_computers_gt_10' {
            # Integer value > 10
            $intValue = 0
            if ([int]::TryParse([string]$Value, [ref]$intValue)) {
                return ($intValue -gt 10)
            }
            return $false
        }

        'affected_computers_gt_0' {
            # Integer value > 0 but <= 10
            $intValue = 0
            if ([int]::TryParse([string]$Value, [ref]$intValue)) {
                return ($intValue -gt 0 -and $intValue -le 10)
            }
            return $false
        }

        # =====================================================================
        # Existing custom triggers (unchanged)
        # =====================================================================

        'pwdAge_gt_1825' {
            # Password age > 5 years (1825 days)
            $pwdDate = Get-DateFromValue -Value $Value
            if ($pwdDate) {
                $pwdAge = ((Get-Date) - $pwdDate).Days
                return ($pwdAge -gt 1825)
            }
            return $false
        }
        'pwdAge_365_1825' {
            # Password age between 1-5 years
            $pwdDate = Get-DateFromValue -Value $Value
            if ($pwdDate) {
                $pwdAge = ((Get-Date) - $pwdDate).Days
                return ($pwdAge -gt 365 -and $pwdAge -le 1825)
            }
            return $false
        }
        'gt_0' {
            # Integer value > 0
            $intValue = 0
            if ([int]::TryParse([string]$Value, [ref]$intValue)) {
                return ($intValue -gt 0)
            }
            return $false
        }
        'lt_12' {
            # Integer value < 12 (for password length)
            $strValue = [string]$Value
            $intValue = 0
            if ([int]::TryParse($strValue, [ref]$intValue)) {
                return ($intValue -lt 12)
            }
            if ($strValue -match '^(\d+)') {
                if ([int]::TryParse($Matches[1], [ref]$intValue)) {
                    return ($intValue -lt 12)
                }
            }
            return $false
        }
        'lt_10_minutes' {
            # Lockout duration < 10 minutes (extract number from "5 minutes")
            $strValue = [string]$Value
            # Skip "Forever" / "manual unlock" - those are secure
            if ($strValue -match 'Forever|Permanent|manual') {
                return $false
            }
            $intValue = 0
            if ([int]::TryParse($strValue, [ref]$intValue)) {
                return ($intValue -gt 0 -and $intValue -lt 10)
            }
            if ($strValue -match '^(\d+)') {
                if ([int]::TryParse($Matches[1], [ref]$intValue)) {
                    return ($intValue -gt 0 -and $intValue -lt 10)
                }
            }
            return $false
        }
        default {
            return $false
        }
    }
}

<#
.SYNOPSIS
    Converts various date value formats to DateTime.
.DESCRIPTION
    Handles pwdLastSet (FileTime), DateTime objects, and string representations.
#>
function Get-DateFromValue {
    param($Value)

    if ($null -eq $Value) { return $null }

    # Already a DateTime
    if ($Value -is [DateTime]) {
        return $Value
    }

    # FileTime (Int64)
    if ($Value -is [Int64] -or $Value -is [long]) {
        if ($Value -gt 0) {
            try {
                return [DateTime]::FromFileTime($Value)
            } catch {
                return $null
            }
        }
        return $null
    }

    # String representation
    $strValue = [string]$Value
    if ([string]::IsNullOrEmpty($strValue)) { return $null }

    # Try parsing as FileTime
    $longValue = 0
    if ([long]::TryParse($strValue, [ref]$longValue) -and $longValue -gt 0) {
        try {
            return [DateTime]::FromFileTime($longValue)
        } catch {
            # Fall through to DateTime parse
        }
    }

    # Try parsing as DateTime
    $dtValue = [DateTime]::MinValue
    if ([DateTime]::TryParse($strValue, [ref]$dtValue)) {
        return $dtValue
    }

    return $null
}

