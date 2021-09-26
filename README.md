# adPEAS

![](https://github.com/61106960/adPEAS/raw/main/images/adPEAS_large.jpg)

adPEAS is a Powershell tool to automate Active Directory enumeration.
In fact, adPEAS is like a wrapper for different other cool projects like
* PowerView
* Empire
* Bloodhound
* and some own written lines of code

As said, adPEAS is a wrapper for other tools. They are almost all written in pure Powershell but some of them are included as compressed binary blob or C# code.

adPEAS-Light is a version without Bloodhound and vulnerability checks and it is more likely that it will not blocked by an AV solution.

# How It Works

adPEAS can be run simply by starting the script via 'invoke-adPEAS' if it is started on a domain joined computer.
If the system you are running adPEAS from is not domain joined or you want to enumerate another domain, use a certain domain controller to connect to, use different credentials or just to enumerate for credential exposure only, you can do it by using defined parameters.

## adPEAS Modules

adPEAS consists of the following enumeration modules:
* Domain - Searching for basic Active Directory information, like Domain Controllers, Sites und Subnets, Trusts and DCSync rights
* CA - Searching for basic Enterprise Certificate Authority information, like CA Name, CA Server and Templates
* Creds - Searching for different kind of credential exposure, like ASREPRoast, Kerberoasting, GroupPolicies, Netlogon scripts, LAPS, gMSA, certain account attributes, e.g. UnixPassword, etc.
* Delegation - Searching for delegation issues, like 'Constrained Delegation', 'Unconstrained Delegation' and 'Resource Based Unconstrained Delegation', for computer and user accounts
* Accounts - Searching for high privileged user accounts in predefined groups, account issues like e.g. password not expire
* Computer - Enumerating Domain Controllers and Exchange server, with the switch -Vulns it checks the systems for EternalBlue, BlueKeep, ZeroLogon and critical Exchange vulnerabilities
* Bloodhound - Enumerating Active Directory with BloodHound

# Some How To Use Examples
## Simple usage with generic program parameters
First you have to load adPEAS in Powershell...
```
Import-Module .\adPEAS.ps1
```
or
```
. .\adPEAS.ps1
```
or
```
gc -raw .\adPEAS.ps1 | iex
```
or
```
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/61106960/adPEAS/main/adPEAS.ps1')
```

Start adPEAS with all enumeration modules and enumerate the domain the logged-on user and computer is connected to.
```
Invoke-adPEAS
```

Start adPEAS with all enumeration modules and enumerate the domain 'contoso.com'.
```
Invoke-adPEAS -Domain 'contoso.com'
```

Start adPEAS with all enumeration modules, enumerate the domain 'contoso.com' and use the domain controller 'dc1.contoso.com' for almost all enumeration requests.
```
Invoke-adPEAS -Domain 'contoso.com' -Server 'dc1.contoso.com'
```

Start adPEAS with all enumeration modules, enumerate the domain 'contoso.com' and use the passed PSCredential object during enumeration.
```
$SecPassword = ConvertTo-SecureString 'Passw0rd1!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('contoso\johndoe', $SecPassword)
Invoke-adPEAS -Domain 'contoso.com' -Cred $Cred
```

Start adPEAS with all enumeration modules, enumerate the domain 'contoso.com' and use the username 'contoso\johndoe' with password 'Passw0rd1!' during enumeration.
```
Invoke-adPEAS -Domain contoso.com -Username 'contoso\johndoe' -Password 'Passw0rd1!'
```

## Usage with a single enumeration module
### All modules below can be combined with all generic program parameters explained above.

Enumerates basic Active Directory information, like Domain Controllers, Password Policy, Sites and Subnets, Trusts, DCSync Rights.
```
Invoke-adPEAS -Module Domain
```

Enumerates basic Enterprise Certificate Authority information, like CA Name, CA Server and Templates.
```
Invoke-adPEAS -Module CA
```

Enumerates credential exposure issues, like ASREPRoast, Kerberoasting, Linux/Unix password attributes, gMSA, LAPS (if your account has the rights to read it), Group Policies, Netlogon scripts.
```
Invoke-adPEAS -Module Creds
```

Enumerates delegation issues, like 'Unconstrained Delegation', 'Constrained Delegation', 'Resource Based Constrained Delegation' for user and computer objects.
```
Invoke-adPEAS -Module Delegation
```

Enumerates users in high privileged groups which are NOT disabled, like Administrators, Domain Admins, Enterprise Admins, Group Policy Creators, DNS Admins, Account Operators, Server Operators, Printer Operators, Backup Operators, Hyper-V Admins, Remote Management Users und CERT Publishers.     Enumerates high privileged users (admincount=1), which are NOT disabled and where the password does not expire or which may not require a password.
```
Invoke-adPEAS -Module Accounts
```

Enumerates installed Domain Controllers and Exchange Server.
```
Invoke-adPEAS -Module Computer
```

Enumerates installed Domain Controllers and Exchange Server and checks them for common critical vulnerabilities, like CVE-2020-1472 (ZeroLogon), CVE-2020-0688 (Exchange), CVE-2019-0708 (BlueKeep), CVE-2018-8581 (Exchange), CVE-2017-0144 (aka MS17-010, EternalBlue)
```
Invoke-adPEAS -Module Computer -Vulns
```

Starts Bloodhound enumeration with the scope DCOnly. Output ZIP files is stored in the same directory adPEAS is started from.
```
Invoke-adPEAS -Module Bloodhound
```

Starts Bloodhound enumeration with the scope All. With this option Bloodhound will contact each member computer of the domain. Output ZIP files is stored in the same directory adPEAS is started from.
```
Invoke-adPEAS -Module Bloodhound -Scope All
```

## Example program output
```
PS > Invoke-adPEAS -Domain sub.pen.local

[*] +++++ Starting adPEAS Version 0.7.0 +++++
adPEAS version 0.7.0
[*] +++++ Starting Enumeration +++++
[*] +++++ Searching for Domain Information +++++
[*] +++++ Checking Domain +++++
Checking Domain - Details for Domain 'sub.pen.local':
Domain Name       : sub.pen.local
Domain SID        : S-1-5-21-575725702-4057784316-641645133
Forest Name       : pen.local
Root Domain Name  : pen.local
Root Domain SID   : S-1-5-21-2219892162-3422002451-1011183393
Forest Children   : No Subdomain[s] available
Domain Controller : PEN-SDC01.sub.pen.local

[*] +++++ Checking Password and Kerberos Policy +++++
Checking Password Policy - Details for Domain 'sub.pen.local':
[!] Password of accounts are stored with reversible encryption
[+] https://adsecurity.org/?p=2053
Minimum Password Age    : Disabled
Maximum Password Age    : Disabled
Minimum Password Length : 7 character
Password Complexity     : Disabled
Lockout Account         : Disabled
Reversible Encryption   : Enabled

Checking Kerberos Policy - Details for Domain 'sub.pen.local':
Maximum Age of TGT            : 10 hours
Maximum Age of TGS            : 600 minutes
Maximum Clock Time Difference : 5 minutes
Krbtgt Password Last Set      : 29.04.2019 10:05:59

[*] +++++ Checking Domain Controller, Sites and Subnets +++++
Checking Domain Controller - Details for Domain 'sub.pen.local':
DC Host Name  : PEN-SDC01.sub.pen.local
DC IP Address : 192.168.46.10
Site Name     : Germany
Domain        : sub.pen.local

Checking Sites and Subnets - Details for Domain 'sub.pen.local':
IP Subnet : 192.168.46.0/25
Site Name : Germany

[*] +++++ Checking Forest and Domain Trusts +++++
Checking Domain Trusts - Details for Domain 'sub.pen.local':
Target Domain Name : pen.local
Target Domain SID  : S-1-5-21-2219892162-3422002451-1011183393
Flags              : IN_FOREST, DIRECT_OUTBOUND, TREE_ROOT, DIRECT_INBOUND
TrustAttributes    : WITHIN_FOREST

[*] +++++ Checking DCSync Rights +++++
[*] https://book.hacktricks.xyz/windows/active-directory-methodology/dcsync
Checking DCSync Rights - Details for Domain 'sub.pen.local':
ActiveDirectoryRight : DS-Replication-Get-Changes
Identity             : BUILTIN\Administrators
distinguishedName    :
ObjectSID            : S-1-5-32-544

ActiveDirectoryRight : DS-Replication-Get-Changes-In-Filtered-Set
Identity             : BUILTIN\Administrators
distinguishedName    :
ObjectSID            : S-1-5-32-544

ActiveDirectoryRight : DS-Replication-Get-Changes-All
Identity             : BUILTIN\Administrators
distinguishedName    :
ObjectSID            : S-1-5-32-544

ActiveDirectoryRight : DS-Replication-Get-Changes
Identity             : Enterprise Domain Controllers
distinguishedName    :
ObjectSID            : S-1-5-9

ActiveDirectoryRight : DS-Replication-Get-Changes-In-Filtered-Set
Identity             : Enterprise Domain Controllers
distinguishedName    :
ObjectSID            : S-1-5-9

ActiveDirectoryRight : DS-Replication-Get-Changes
Identity             : PEN\Enterprise Read-only Domain Controllers
distinguishedName    : CN=Enterprise Read-only Domain Controllers,CN=Users,DC=pen,DC=local
ObjectSID            : S-1-5-21-2219892162-3422002451-1011183393-498

ActiveDirectoryRight : DS-Replication-Get-Changes-All
Identity             : SUB\Domain Controllers
distinguishedName    : CN=Domain Controllers,CN=Users,DC=sub,DC=pen,DC=local
ObjectSID            : S-1-5-21-575725702-4057784316-641645133-516

ActiveDirectoryRight : DS-Replication-Get-Changes-All
Identity             : SUB\superadmin
distinguishedName    : CN=Superadmin,CN=Users,DC=sub,DC=pen,DC=local
ObjectSID            : S-1-5-21-575725702-4057784316-641645133-3954

ActiveDirectoryRight : DS-Replication-Get-Changes
Identity             : SUB\superadmin
distinguishedName    : CN=Superadmin,CN=Users,DC=sub,DC=pen,DC=local
ObjectSID            : S-1-5-21-575725702-4057784316-641645133-3954

[*] +++++ Checking GenericAll Rights +++++
[*] https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces
Checking GenericAll Rights - Details for Domain 'sub.pen.local':
ActiveDirectoryRight : GenericAll
Identity             : Local System
distinguishedName    :
ObjectSID            : S-1-5-18

ActiveDirectoryRight : GenericAll
Identity             : SUB\Andend
distinguishedName    : CN=Alexander Baumgartner,OU=germany,OU=users,OU=corp,DC=sub,DC=pen,DC=local
ObjectSID            : S-1-5-21-575725702-4057784316-641645133-2273

ActiveDirectoryRight : GenericAll
Identity             : PEN\Enterprise Admins
distinguishedName    : CN=Enterprise Admins,CN=Users,DC=pen,DC=local
ObjectSID            : S-1-5-21-2219892162-3422002451-1011183393-519

ActiveDirectoryRight : GenericAll
Identity             : PEN\Exchange Trusted Subsystem
distinguishedName    : CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,DC=pen,DC=local
ObjectSID            : S-1-5-21-2219892162-3422002451-1011183393-1118

ActiveDirectoryRight : GenericAll
Identity             : PEN\Exchange Trusted Subsystem
distinguishedName    : CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,DC=pen,DC=local
ObjectSID            : S-1-5-21-2219892162-3422002451-1011183393-1118

ActiveDirectoryRight : GenericAll
Identity             : PEN\Organization Management
distinguishedName    : CN=Organization Management,OU=Microsoft Exchange Security Groups,DC=pen,DC=local
ObjectSID            : S-1-5-21-2219892162-3422002451-1011183393-1105

ActiveDirectoryRight : GenericAll
Identity             : PEN\Exchange Trusted Subsystem
distinguishedName    : CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,DC=pen,DC=local
ObjectSID            : S-1-5-21-2219892162-3422002451-1011183393-1118

[*] +++++ Searching for Certificate Authority Information +++++
[*] +++++ Searching for Enterprise CA +++++
[*] https://posts.specterops.io/certified-pre-owned-d95910965cd2
Searching for Certificate Authority - Details for 'PEN-IssuingCA01':
CA Name            : PEN-IssuingCA01
CA dnshostname     : PEN-SCA.sub.pen.local
CA IP Address      : 192.168.46.23
Date of Creation   : 29.07.2020 21:05:02
DistinguishedName  : CN=PEN-IssuingCA01,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=sub,DC=pen,DC=local
Templates          : Wildcard-Smartcard-User
                     Wildcard-User
                     Webserver
                     DirectoryEmailReplication
                     DomainControllerAuthentication
                     DomainController
                     Machine
                     Administrator
NTAuthCertificates : True

[*] +++++ Searching for Vulnerable Certificate Templates +++++
[+] adPEAS does basic enumeration only, consider using https://github.com/GhostPack/PSPKIAudit
[*] +++++ Checking Template 'Wildcard-Smartcard-User' +++++
[!] 'Authenticated Users' have 'GenericAll' permissions on Template 'Wildcard-Smartcard-User'
Checking Certificate Template - Details for Template 'Wildcard-Smartcard-User':
Template Name              : Wildcard-Smartcard-User
Template distinguishedname : CN=Wildcard-Smartcard-User,CN=Certificate Templates,CN=Public Key
                             Services,CN=Services,CN=Configuration,DC=sub,DC=pen,DC=local
Date of Creation           : 15.08.2020 14:15:13
CertificateNameFlag        : ENROLLEE_SUPPLIES_SUBJECT
                             OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME
                             ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME
                             SUBJECT_ALT_REQUIRE_DOMAIN_DNS
                             SUBJECT_ALT_REQUIRE_DIRECTORY_GUID
                             SUBJECT_ALT_REQUIRE_UPN
                             SUBJECT_ALT_REQUIRE_EMAIL
                             SUBJECT_ALT_REQUIRE_DNS
                             SUBJECT_REQUIRE_DNS_AS_CN
                             SUBJECT_REQUIRE_EMAIL
                             SUBJECT_REQUIRE_COMMON_NAME
                             SUBJECT_REQUIRE_DIRECTORY_PATH
EnrollmentFlag             : CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS
                             CT_FLAG_PUBLISH_TO_DS
                             CT_FLAG_AUTO_ENROLLMENT
                             CT_FLAG_USER_INTERACTION_REQUIRED
Private Key Exportable     : True
Authenticated Users        : GenericAll

[*] +++++ Checking Template 'Wildcard-User' +++++
[!] 'Authenticated Users' have 'ReadProperty, WriteProperty, GenericExecute, WriteDacl, WriteOwner' permissions on Template 'Wildcard-User'
Checking Certificate Template - Details for Template 'Wildcard-User':
Template Name              : Wildcard-User
Template distinguishedname : CN=Wildcard-User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=sub,DC=pen,DC=local
Date of Creation           : 15.08.2020 14:06:08
CertificateNameFlag        : ENROLLEE_SUPPLIES_SUBJECT
                             OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME
                             ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME
                             SUBJECT_ALT_REQUIRE_DOMAIN_DNS
                             SUBJECT_ALT_REQUIRE_DIRECTORY_GUID
                             SUBJECT_ALT_REQUIRE_UPN
                             SUBJECT_ALT_REQUIRE_EMAIL
                             SUBJECT_ALT_REQUIRE_DNS
                             SUBJECT_REQUIRE_DNS_AS_CN
                             SUBJECT_REQUIRE_EMAIL
                             SUBJECT_REQUIRE_COMMON_NAME
                             SUBJECT_REQUIRE_DIRECTORY_PATH
EnrollmentFlag             : CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS
                             CT_FLAG_AUTO_ENROLLMENT
                             CT_FLAG_USER_INTERACTION_REQUIRED
Private Key Exportable     : True
Authenticated Users        : ReadProperty, WriteProperty, GenericExecute, WriteDacl, WriteOwner

[*] +++++ Searching for Credentials Exposure +++++
[*] +++++ Searching for ASREPRoast Users +++++
[*] https://book.hacktricks.xyz/windows/active-directory-methodology/asreproast
[!] Account Boody1946 does not require kerberos preauthentication to get a TGT
[*] Hashcat usage: hashcat -m 18200
Searching for ASREPRoast Users - Details for User 'Boody1946':
sAMAccountName     : Boody1946
userPrincipalName  : Kevin.Ehrlichmann@sub.pen.local
distinguishedName  : CN=Kevin Ehrlichmann,OU=germany,OU=users,OU=corp,DC=sub,DC=pen,DC=local
description        :
objectSid          : S-1-5-21-575725702-4057784316-641645133-2289
userAccountControl : NORMAL_ACCOUNT, DONT_REQ_PREAUTH
memberOf           :
pwdLastSet         : 12.06.2019 13:18:36
lastLogonTimestamp : 13.11.2020 13:32:41

$krb5asrep$23$Boody1946@sub.pen.local:d38e4dcd90019ddda3ec04e535eb81b7$b3943db8194504c13e706358d9600a34c1269570c232f8dd
039f164ceed1bf15XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXaa084060f8b18db692b79749caf1e3149a
ad42059aeb56d39fc9862596a75f74ff414c476577a4b18f0b3a790ce642ac3f0096f6ab7e9b8ca20e1494a65d9e26b68e2952ed732a9eecea24c21
1b07314c69d0385ff42cd6180562a36035e9XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXff12ce17b66921
c91f35d66bdcf241f8fa821db4cf0db74247b508401fe17639c488f379d43043bfb3c99

[*] +++++ Searching for Kerberoastable Users +++++
[*] https://book.hacktricks.xyz/windows/active-directory-methodology/kerberoast#kerberoast
[!] Account svc_web has a SPN and is vulnerable to Kerberoasting
[*] Hashcat usage: hashcat -m 13100
Searching for Kerberoastable Users - Details for User 'svc_web':
sAMAccountName     : svc_web
userPrincipalName  : svc_web@sub.pen.local
distinguishedName  : CN=svc_web,OU=service accounts,OU=corp,DC=sub,DC=pen,DC=local
description        :
objectSid          : S-1-5-21-575725702-4057784316-641645133-3952
userAccountControl : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
memberOf           :
pwdLastSet         : 21.01.2020 17:40:15
lastLogonTimestamp :

$krb5tgs$23$*svc_web$sub.pen.local$http/web.server*$C2D4F2B64EC91A55A605229DBA5598FB$48B30F628AEE1917D1B401410937A633C2
4A586F186F6F8E5936EE2A375D21F226DF85AB2E29CE9866BBC985B2D12C57C3ADE298DC67293BDB5A258D092AAFC18415F60D925F69F4AC8832543
468D4371CB9464B18A1651A028D19273C7480421177ED589E0539265B63A833250964AB572451EE6589DD0041DBF06A3F5A63817594637D6CBA7A6D
D5B62281F6E29BD350F45F674F7C879A374284E95FB5344E100767F7BED97F609F6F2A2AFFE25135757F3119644B4ACFEC293E0709F4D7A139D322F
10910440302D6FA6XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX30E5C0587F4F1A9742B919ED1A9B2
41D812434FE9BAC01AA3688F885DC4EF58D6D1ADD664D4315636DD0537DDA058F68963DF413829C89A18265F0FF6966C55AFE14C642C46EA9BABFCB
E849F4ADE91E7E86F23E4DA78CC19AE93A676F42BAB1F3C9D34D3EED8CD35FCE43E69A3AF2996370249ACEFA92BB1DE6F3F2D00368FE03E2F39C32B
D8C49BF5B66065EDDFDF0A2436CD45F17557D68823909353F6AE75AA60DAB2752EC21497D79999A1C9FF47ECBE330A86924DCD4A7C97858D573244C
5D63863CA6D5AD4838CB4F0A1D78D579B063CAD8953FD56F002DC6CB5D2253CB7CAC0300D26ED5FF0379C8F1C409870FD53B3AFFE9FF7773229BC77
12E6A459F459828D334744AE1AE35A673C47A643FDD315B2414170FD4E9CA07B1C26F055AF42019FC36A68A8501FEB6B1C1424AA50415C2BBBA9E1E
647A4703096A2CF3563C404CE5E9F55D5A0A010C9140783B6956351ADD6C09B82F6D21B6810F3E08C67C68A547560F3589C18A5D44E26C76F078552
8EFEC05A13188058362F8800798BDDB21A67CFD79FA244740FEBB1A2736A24EC4C1E5FDEB5765C7E5E8905B4E8AB7B86FFD8A601EEAB0E9FD51E678
112B82BACCBA64C86XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXB133302F9E3A2D0070BA725E786852A9139ED12CC40B4
090DCD3579110C17DE189695B5F3D8EFDFC626A7E7713A073F3861CCA6929CFA1DB9CAA2063587870C733A52BE23DD92F048A9DC0049315FA116F73
A9112AE205F53251B1F1BAC51939951C2D96089E8022D3E780F46CB17B8B858CDBE3E8A292ED6E02F175171E10840623F0407ED1E5DB445DA7A6FCA
40F1BDFD0A310CA89328E98382C7FD1DC600897DDDEC71D65AA8C98AD70C0E223F0372740F36DC1CC1C66F2E61A9FBFCB3705478471DAE696BCE92F
91309ABAEEDB101B652CC7A8F2C28F5339765BA0E89C86611F5C17E45073AFED15ABF02F6E65DF2A7483BB8E0802E5891F30A9668BDC126F52ED9FA
169B3BE775BC87EA99521506AD48C93DB025XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXFB1BF977339341
AA40386C102807D5F33656BABEBAB8FE983CB9C2D1E56E28D9488671A56AE205686EF2324F9EBD9DACEFF9C7E8E3D10814444E00DEFB024C3DC856F
C326EC09C657BC09F6502A4058CA88258CCDAEB34E12A652D76C07C0D2547E52A8FFF50CA164E748B34CD6F8119DAB66A1B21043BBCD16C05F6

[*] +++++ Searching for Users with a set 'Linux/Unix Password' attribute +++++
[*] https://www.blackhillsinfosec.com/domain-goodness-learned-love-ad-explorer/
[!] User Tiledgets has a legacy cleartext Linux/Unix password set
Searching for Users with a set 'Linux/Unix Password' attribute - Details for User 'Tiledgets':
sAMAccountName     : Tiledgets
userPrincipalName  : Lucas.Maier@sub.pen.local
distinguishedName  : CN=Lucas Maier,OU=germany,OU=users,OU=corp,DC=sub,DC=pen,DC=local
description        :
objectSid          : S-1-5-21-575725702-4057784316-641645133-2115
userAccountControl : NORMAL_ACCOUNT
memberOf           :
pwdLastSet         : 12.06.2019 13:18:07
lastLogonTimestamp :
UnixUserPassword   : ABCD!efgh12345$67890

[*] +++++ Searching for Computers with enabled and readable LAPS attribute +++++
[*] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#antivirus-and-detectors
[!] Computer SRVCLOUD$ has enabled LAPS - Found password 'SecretPW0815!'
Searching for Computers with enabled LAPS - Details for Computer 'SRVCLOUD$':
sAMAccountName                                    : SRVCLOUD$
dNSHostName                                       : srvcloud.sub.pen.local
distinguishedName                                 : CN=SRVCLOUD,OU=corp,DC=sub,DC=pen,DC=local
IPv4Address                                       : 192.168.46.31
operatingSystem                                   : Windows Server 2019 Standard
description                                       : Ask the administrator for the password
objectSid                                         : S-1-5-21-575725702-4057784316-641645133-1715
userAccountControl                                : ACCOUNTDISABLE, WORKSTATION_TRUST_ACCOUNT
ms-Mcs-AdmPwd [Password]                          : SecretPW0815!
ms-mcs-AdmPwdExpirationTime [Password Expiration] : 01.12.2020 00:00:00

[*] +++++ Searching for Group Managed Service Accounts (gMSA) accounts +++++
[*] https://book.hacktricks.xyz/windows/active-directory-methodology/privileged-accounts-and-token-privileges
[+] Account gMSA-Service$ is a Group Managed Service Account
Searching for gMSA - Details for Account 'gMSA-Service$':
sAMAccountName                             : gMSA-Service$
distinguishedName                          : CN=gMSA-Service,CN=Managed Service Accounts,DC=sub,DC=pen,DC=local
description                                :
objectSid                                  : S-1-5-21-575725702-4057784316-641645133-36616
userAccountControl                         : WORKSTATION_TRUST_ACCOUNT
memberOf                                   : CN=Testgroup,OU=test,OU=corp,DC=sub,DC=pen,DC=local
pwdLastSet                                 : 26.09.2021 12:31:44
lastLogonTimestamp                         : 26.09.2021 12:38:07
PrincipalsAllowedToRetrieveManagedPassword : SUB\superadmin
                                             SUB\SRV-DB01$
                                             SUB\test

[*] +++++ Searching for Crypted Passwords in SYSVOL Group Policy Objects +++++
[*] https://www.andreafortuna.org/2019/02/13/abusing-group-policy-preference-files-for-password-discovery/
[!] Password 'P8ssw0rd#! for user local-admin-srv has been found
Searching for Crypted Passwords in SYSVOL Policies Directory - Details for File '\\sub.pen.local\SYSVOL\sub.pen.local\Policies\{6F6C332E-79D5-4C77-BF23-6FB5ED9381D4}\Machine\Preferences\Groups\Groups.xml':
Username : local-admin-srv
Password : 'P8ssw0rd#!

[*] +++++ Searching for Sensitive Information in NETLOGON Share +++++
[+] Possible sensitive information have been found
Searching for sensitive information in NETLOGON Share - Details for File '\\sub.pen.local\NETLOGON\login-script.cmd':
LineNumber  : 5
LineContent : rem password: SuperS3cr3t!

[+] Possible sensitive information have been found
Searching for sensitive information in NETLOGON Share - Details for File '\\sub.pen.local\NETLOGON\login-script_test.cmd':
LineNumber  : {5, 7}
LineContent : {rem password: TestPW0815!, net use l: \\srv-rfile.pen.local\Deparmentshare$ Passw0rd1!
              /user:sub\%username%}

[*] +++++ Searching for Delegation Issues +++++
[*] +++++ Searching for Computers with Unconstrained Delegation Rights +++++
[*] https://book.hacktricks.xyz/windows/active-directory-methodology/unconstrained-delegation
[!] Computer PEN-SEXCH$ has unconstrained delegation rights
Searching for Computers with Unconstrained Delegation Rights - Details for Computer 'PEN-SEXCH$':
sAMAccountName     : PEN-SEXCH$
dNSHostName        : PEN-SEXCH.sub.pen.local
distinguishedName  : CN=PEN-SEXCH,OU=servers,OU=corp,DC=sub,DC=pen,DC=local
IPv4Address        : 192.168.46.22
operatingSystem    : Windows Server 2016 Datacenter
description        :
objectSid          : S-1-5-21-575725702-4057784316-641645133-1106
userAccountControl : WORKSTATION_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION

[*] +++++ Searching for Computers with Constrained Delegation Rights +++++
[*] https://book.hacktricks.xyz/windows/active-directory-methodology/constrained-delegation
[!] Computer PEN-SCA$ has constrained delegation rights
Searching for Computers with Constrained Delegation Rights - Details for Computer 'PEN-SCA$':
sAMAccountName           : PEN-SCA$
dNSHostName              : PEN-SCA.sub.pen.local
distinguishedName        : CN=PEN-SCA,OU=servers,OU=corp,DC=sub,DC=pen,DC=local
IPv4Address              : 192.168.46.23
operatingSystem          : Windows Server 2016 Datacenter
description              :
objectSid                : S-1-5-21-575725702-4057784316-641645133-1104
userAccountControl       : WORKSTATION_TRUST_ACCOUNT, TRUSTED_TO_AUTH_FOR_DELEGATION
msDS-AllowedToDelegateTo : HOST/PEN-SDC01.sub.pen.local/sub.pen.local
                           HOST/PEN-SDC01.sub.pen.local
                           HOST/PEN-SDC01
                           HOST/PEN-SDC01.sub.pen.local/SUB
                           HOST/PEN-SDC01/SUB

[*] +++++ Searching for Computers with Resource-Based Constrained Delegation Rights +++++
[*] https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
[!] Computer SRVVM$ has resource-based constrained delegation rights
Searching for Computers with Resource-Based Constrained Delegation Rights - Details for Computer 'SRVVM$':
sAMAccountName                      : SRVVM$
dNSHostName                         : srvvm.sub.pen.local
distinguishedName                   : CN=SRVVM,OU=corp,DC=sub,DC=pen,DC=local
IPv4Address                         : 192.168.46.56
operatingSystem                     : Windows Server 2016 Datacenter
description                         : vCenter
objectSid                           : S-1-5-21-575725702-4057784316-641645133-1187
userAccountControl                  : ACCOUNTDISABLE, WORKSTATION_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION
AllowedToActOnBehalfOfOtherIdentity : SUB\SRV-TEST$

[*] +++++ Searching for Users with Constrained Delegation Rights +++++
[*] https://book.hacktricks.xyz/windows/active-directory-methodology/constrained-delegation
[!] User test has constrained delegation rights
[+] The account test is or was member of a high privileged protected group
[+] https://book.hacktricks.xyz/windows/active-directory-methodology/privileged-accounts-and-token-privileges#adminsdholder-group
Searching for Users with Constrained Delegation Rights - Details for User 'test':
sAMAccountName           : test
userPrincipalName        : test@sub.pen.local
distinguishedName        : CN=test,OU=test,OU=corp,DC=sub,DC=pen,DC=local
description              : 
objectSid                : S-1-5-21-575725702-4057784316-641645133-2613
userAccountControl       : PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_REQ_PREAUTH
memberOf                 : CN=Testgroup,OU=test,OU=corp,DC=sub,DC=pen,DC=local
pwdLastSet               : 20.10.2020 13:48:35
lastLogonTimestamp       : 19.11.2020 16:43:36
msDS-AllowedToDelegateTo : HOST/PEN-SDC01.sub.pen.local/sub.pen.local
                           HOST/PEN-SDC01.sub.pen.local
                           HOST/PEN-SDC01
                           HOST/PEN-SDC01.sub.pen.local/SUB
                           HOST/PEN-SDC01/SUB

[*] +++++ Searching for Users with Resource-Based Constrained Delegation Rights +++++
[*] https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
[!] User test1 has resource-based constrained delegation rights
Searching for Users with Resource-Based Constrained Delegation Rights - Details for User 'test1':
sAMAccountName                      : test1
userPrincipalName                   : test1@sub.pen.local
distinguishedName                   : CN=test1,OU=test,OU=corp,DC=sub,DC=pen,DC=local
description                         : 
objectSid                           : S-1-5-21-575725702-4057784316-641645133-5165
userAccountControl                  : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH
memberOf                            : 
pwdLastSet                          : 18.10.2020 17:45:20
lastLogonTimestamp                  : 02.12.2020 14:39:26
AllowedToActOnBehalfOfOtherIdentity : SUB\SRV-DB01$

[*] +++++ Starting Account Enumeration +++++
[*] +++++ Starting Domain User Enumeration +++++
[*] +++++ Searching for Users in High Privileged Groups +++++
[*] https://book.hacktricks.xyz/windows/active-directory-methodology/privileged-accounts-and-token-privileges
Searching for Users in High Privileged Groups - Members of Group 'BUILTIN\Administrators':
GroupName         : Domain Admins
distinguishedName : CN=Domain Admins,CN=Users,DC=sub,DC=pen,DC=local
description       :
objectSid         : S-1-5-21-575725702-4057784316-641645133-512
MemberDomain      : sub.pen.local

GroupName         : Enterprise Admins
distinguishedName : CN=Enterprise Admins,CN=Users,DC=pen,DC=local
description       :
objectSid         : S-1-5-21-2219892162-3422002451-1011183393-519
MemberDomain      : pen.local

sAMAccountName     : superadmin
userPrincipalName  : superadmin@sub.pen.local
distinguishedName  : CN=Superadmin,CN=Users,DC=sub,DC=pen,DC=local
description        :
objectSid          : S-1-5-21-575725702-4057784316-641645133-3954
MemberDomain       : sub.pen.local
pwdLastSet         : 16.04.2020 11:28:31
lastLogonTimestamp : 16.04.2020 11:29:54
UserAccountControl : NORMAL_ACCOUNT

sAMAccountName     : Andend
userPrincipalName  : Alexander.Baumgartner@sub.pen.local
distinguishedName  : CN=Alexander Baumgartner,OU=germany,OU=users,OU=corp,DC=sub,DC=pen,DC=local
description        :
objectSid          : S-1-5-21-575725702-4057784316-641645133-2273
MemberDomain       : sub.pen.local
pwdLastSet         : 12.06.2019 13:18:33
lastLogonTimestamp : 14.04.2020 15:12:20
UserAccountControl : NORMAL_ACCOUNT

sAMAccountName     : Administrator
userPrincipalName  : Administrator@sub.pen.local
distinguishedName  : CN=Administrator,CN=Users,DC=sub,DC=pen,DC=local
description        : Built-in account for administering the computer/domain
objectSid          : S-1-5-21-575725702-4057784316-641645133-500
MemberDomain       : sub.pen.local
pwdLastSet         : 28.10.2019 10:37:49
lastLogonTimestamp : 30.12.2020 14:10:15
UserAccountControl : NORMAL_ACCOUNT

Searching for Users in High Privileged Groups - Members of Group 'SUB\Domain Admins':
sAMAccountName     : superadmin
userPrincipalName  : superadmin@sub.pen.local
distinguishedName  : CN=Superadmin,CN=Users,DC=sub,DC=pen,DC=local
description        :
objectSid          : S-1-5-21-575725702-4057784316-641645133-3954
MemberDomain       : sub.pen.local
pwdLastSet         : 16.04.2020 11:28:31
lastLogonTimestamp : 16.04.2020 11:29:54
UserAccountControl : NORMAL_ACCOUNT

sAMAccountName     : Administrator
userPrincipalName  : Administrator@sub.pen.local
distinguishedName  : CN=Administrator,CN=Users,DC=sub,DC=pen,DC=local
description        : Built-in account for administering the computer/domain
objectSid          : S-1-5-21-575725702-4057784316-641645133-500
MemberDomain       : sub.pen.local
pwdLastSet         : 28.10.2019 10:37:49
lastLogonTimestamp : 30.12.2020 14:10:15
UserAccountControl : NORMAL_ACCOUNT

sAMAccountName     : Andend
userPrincipalName  : Alexander.Baumgartner@sub.pen.local
distinguishedName  : CN=Alexander Baumgartner,OU=germany,OU=users,OU=corp,DC=sub,DC=pen,DC=local
description        :
objectSid          : S-1-5-21-575725702-4057784316-641645133-2273
MemberDomain       : sub.pen.local
pwdLastSet         : 12.06.2019 13:18:33
lastLogonTimestamp : 14.04.2020 15:12:20
UserAccountControl : NORMAL_ACCOUNT

Searching for Users in High Privileged Groups - Members of Group 'PEN\Enterprise Admins':
GroupName         : Domain Admins
distinguishedName : CN=Domain Admins,CN=Users,DC=sub,DC=pen,DC=local
description       :
objectSid         : S-1-5-21-575725702-4057784316-641645133-512
MemberDomain      : sub.pen.local

sAMAccountName     : Administrator
userPrincipalName  :
distinguishedName  : CN=Administrator,CN=Users,DC=pen,DC=local
description        : Built-in account for administering the computer/domain
objectSid          : S-1-5-21-2219892162-3422002451-1011183393-500
MemberDomain       : pen.local
pwdLastSet         : 12.06.2019 11:04:17
lastLogonTimestamp : 30.12.2020 14:06:11
UserAccountControl : NORMAL_ACCOUNT

Searching for Users in High Privileged Groups - Members of Group 'SUB\Group Policy Creator Owners':
sAMAccountName     : Administrator
userPrincipalName  : Administrator@sub.pen.local
distinguishedName  : CN=Administrator,CN=Users,DC=sub,DC=pen,DC=local
description        : Built-in account for administering the computer/domain
objectSid          : S-1-5-21-575725702-4057784316-641645133-500
MemberDomain       : sub.pen.local
pwdLastSet         : 28.10.2019 10:37:49
lastLogonTimestamp : 30.12.2020 14:10:15
UserAccountControl : NORMAL_ACCOUNT

Searching for Users in High Privileged Groups - Members of Group 'SUB\DnsAdmins':
sAMAccountName     : Andend
userPrincipalName  : Alexander.Baumgartner@sub.pen.local
distinguishedName  : CN=Alexander Baumgartner,OU=germany,OU=users,OU=corp,DC=sub,DC=pen,DC=local
description        :
objectSid          : S-1-5-21-575725702-4057784316-641645133-2273
MemberDomain       : sub.pen.local
pwdLastSet         : 12.06.2019 13:18:33
lastLogonTimestamp : 14.04.2020 15:12:20
UserAccountControl : NORMAL_ACCOUNT

Searching for Users in High Privileged Groups - Members of Group 'BUILTIN\Account Operators':
Searching for Users in High Privileged Groups - Members of Group 'BUILTIN\Server Operators':
Searching for Users in High Privileged Groups - Members of Group 'BUILTIN\Print Operators':
Searching for Users in High Privileged Groups - Members of Group 'BUILTIN\Backup Operators':
sAMAccountName     : Andend
userPrincipalName  : Alexander.Baumgartner@sub.pen.local
distinguishedName  : CN=Alexander Baumgartner,OU=germany,OU=users,OU=corp,DC=sub,DC=pen,DC=local
description        :
objectSid          : S-1-5-21-575725702-4057784316-641645133-2273
MemberDomain       : sub.pen.local
pwdLastSet         : 12.06.2019 13:18:33
lastLogonTimestamp : 14.04.2020 15:12:20
UserAccountControl : NORMAL_ACCOUNT

Searching for Users in High Privileged Groups - Members of Group 'BUILTIN\Hyper-V Administrators':
Searching for Users in High Privileged Groups - Members of Group 'BUILTIN\Access Control Assistance Operators':
Searching for Users in High Privileged Groups - Members of Group 'SUB\Cert Publishers':
sAMAccountName     : Andend
userPrincipalName  : Alexander.Baumgartner@sub.pen.local
distinguishedName  : CN=Alexander Baumgartner,OU=germany,OU=users,OU=corp,DC=sub,DC=pen,DC=local
description        :
objectSid          : S-1-5-21-575725702-4057784316-641645133-2273
MemberDomain       : sub.pen.local
pwdLastSet         : 12.06.2019 13:18:33
lastLogonTimestamp : 14.04.2020 15:12:20
UserAccountControl : NORMAL_ACCOUNT

[*] +++++ Searching for High Privileged Users where the Password does not expire +++++
[*] https://ldapwiki.com/wiki/DONT_EXPIRE_PASSWORD
[!] The password of account Andend does not expire
[+] The account Andend is or was member of a high privileged protected group
[*] https://book.hacktricks.xyz/windows/active-directory-methodology/privileged-accounts-and-token-privileges#adminsdholder-group
Searching for High Privileged Users where the Password does not expire - Details for User 'Andend':
sAMAccountName     : Andend
userPrincipalName  : Alexander.Baumgartner@sub.pen.local
distinguishedName  : CN=Alexander Baumgartner,OU=germany,OU=users,OU=corp,DC=sub,DC=pen,DC=local
description        :
objectSid          : S-1-5-21-575725702-4057784316-641645133-2273
userAccountControl : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
memberOf           : CN=Domain Admins,CN=Users,DC=sub,DC=pen,DC=local
pwdLastSet         : 12.06.2019 13:18:33
lastLogonTimestamp : 14.04.2020 15:12:20

[*] +++++ Searching for High Privileged Users which may not require a Password +++++
[*] https://ldapwiki.com/wiki/PASSWD_NOTREQD
[!] The user test does not require to have a password
[+] The account test is or was member of a high privileged protected group
[*] https://book.hacktricks.xyz/windows/active-directory-methodology/privileged-accounts-and-token-privileges#adminsdholder-group
Searching for High Privileged Users which may not require a Password - Details for User 'test':
sAMAccountName     : test
userPrincipalName  : test@sub.pen.local
distinguishedName  : CN=test,OU=test,OU=corp,DC=sub,DC=pen,DC=local
description        : 
objectSid          : S-1-5-21-2861873120-3432765274-1178769123-2613
userAccountControl : PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_REQ_PREAUTH
memberOf           : S-1-5-21-575725702-4057784316-641645133-2613
pwdLastSet         : 20.10.2020 13:48:35
lastLogonTimestamp : 19.11.2020 16:43:36

[*] +++++ Starting Computer Enumeration +++++
[*] +++++ Searching Domain Controllers +++++
Searching for Domain Controllers - Details for Computer 'PEN-SDC01$':
sAMAccountName     : PEN-SDC01$
dNSHostName        : PEN-SDC01.sub.pen.local
distinguishedName  : CN=PEN-SDC01,OU=Domain Controllers,DC=sub,DC=pen,DC=local
IPv4Address        : 192.168.46.20
operatingSystem    : Windows Server 2012 R2 Datacenter
description        :
objectSid          : S-1-5-21-575725702-4057784316-641645133-1001
userAccountControl : SERVER_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION

[*] +++++ Searching for Exchange Servers +++++
Searching for Exchange Servers - Details for Exchange Server PEN-SEXCH$:
sAMAccountName     : PEN-SEXCH$
dNSHostName        : PEN-SEXCH.sub.pen.local
distinguishedName  : CN=PEN-SEXCH,OU=servers,OU=corp,DC=sub,DC=pen,DC=local
IPv4Address        : 192.168.46.22
operatingSystem    : Windows Server 2016 Datacenter
description        :
objectSid          : S-1-5-21-575725702-4057784316-641645133-1106
userAccountControl : WORKSTATION_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION

[*] +++++ Searching for Enterprise CA Servers +++++
Searching for Computers with Constrained Delegation Rights - Details for Computer 'PEN-SCA$':
sAMAccountName     : PEN-SCA$
dNSHostName        : PEN-SCA.sub.pen.local
distinguishedName  : CN=PEN-SCA,OU=servers,OU=corp,DC=sub,DC=pen,DC=local
IPv4Address        : 192.168.46.23
operatingSystem    : Windows Server 2019 Datacenter
description        :
objectSid          : S-1-5-21-575725702-4057784316-641645133-1104
userAccountControl : WORKSTATION_TRUST_ACCOUNT, TRUSTED_TO_AUTH_FOR_DELEGATION

[*] +++++ Starting BloodHound Enumeration +++++
----------------------------------------------
Initializing SharpHound at 14:16 on 30.07.2021
----------------------------------------------

Resolved Collection Methods: Group, Trusts, ACL, ObjectProps, Container, GPOLocalGroup, DCOnly

[+] Creating Schema map for domain SUB.PEN.LOCAL using path CN=Schema,CN=Configuration,DC=SUB,DC=PEN,DC=LOCAL


PS > [+] Cache File Found! Loaded 143 Objects in cache

[+] Pre-populating Domain Controller SIDS
Status: 0 objects finished (+0) -- Using 146 MB RAM
Status: 2906 objects finished (+2906 484,3333)/s -- Using 164 MB RAM
Enumeration finished in 00:00:06.0289570
Compressing data to 20210730141650_sub.pen.local_Bloodhound.zip
You can upload this file directly to the UI

SharpHound Enumeration Completed at 14:16 on 30.07.2021! Happy Graphing!
```

## Special thanks go to...
* Will Schroeder @harmjoy, for his great PowerView
* Dirk-jan @_dirkjan, for his great AD and Windows research
* SpecterOps, for their fantastic BloodHound
* BC-Security, for their great ongoing work with Empire
* Vincent LE TOUX @vletoux, for his vulnerability detection PoC's
* Joaquim Nogueira @lkys37en, for his idea to build a simple AD enumeration tool
* Christoph Falta @cfalta, for his inspiring work on PoshADCS
* and all the people who inspired me on my journey...