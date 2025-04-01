# adPEAS

![](https://github.com/61106960/adPEAS/raw/main/images/adPEAS_large.jpg)

adPEAS is a Powershell tool to automate Active Directory enumeration.
In fact, adPEAS is like a wrapper for different other cool projects like
* PowerView
* PoshADCS
* BloodHound Community Edition
* and some own written lines of code

As said, adPEAS is a wrapper for other tools. They are almost all written in pure Powershell but some of them are included as compressed binary blob or C# code.

adPEAS-Light is a version without Bloodhound and it is more likely that it will not be blocked by an AV solution.

# How It Works

adPEAS can be run simply by starting the script via _invoke-adPEAS_ if it is started on a domain joined computer.
If the system you are running adPEAS from is not domain joined or you want to enumerate another domain, use a certain domain controller to connect to, use different credentials or just to enumerate for credential exposure only, you can do it by using defined parameters.

## adPEAS Modules

adPEAS consists of the following enumeration modules:
* Domain - Searching for basic Active Directory information, like Domain Controllers, Sites und Subnets, Trusts and Password/Kerberos policy
* Rights - Searching for specific Active Directory rights and permissions, like LAPS, DCSync and adding computer to domain
* GPO -  Searching for basic GPO related things, like local group membership on domain computer
* ADCS - Searching for basic Active Directory Certificate Services information, like CA Name, CA Server and vulnerable Templates
* Creds - Searching for different kind of credential exposure, like ASREPRoast, Kerberoasting, GroupPolicies, Netlogon scripts, LAPS, gMSA, certain legacy attributes, e.g. UnixPassword, etc.
* Delegation - Searching for delegation issues, like 'Constrained Delegation', 'Unconstrained Delegation' and 'Resource Based Constrained Delegation', for computer and user accounts
* Accounts - Searching for non-disabled high privileged user accounts in predefined groups and account issues like e.g. old passwords
* Computer - Enumerating Domain Controllers, Certificate Services, Exchange Server and outdated OS versions like Windows Server 2008R2, etc.
* BloodHound - Enumerating Active Directory with the SharpHound collector for BloodHound Community Edition

### Important Note about the BloodHound Module
* adPEAS is currently using the SharpHound ingestor by [BloodHound Community Edition](https://github.com/SpecterOps/BloodHound). This ingestor will NOT work with the older versions of BloodHound.
* Since more features are constantly added to BloodHound, the ingestor may be frequently updates as well to support more complex enumeration techniques. This repo will try to keep up with the newest versions.
* Since the older version of BloodHound is still in use, a different fork (BloodHound-Old) will exist to cover their needs.

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

Start adPEAS with all enumeration modules and enumerate the domain 'contoso.com'. In addition it writes all output without any ANSI color codes to a file.
```
Invoke-adPEAS -Domain 'contoso.com' -Outputfile 'C:\temp\adPEAS_outputfile' -NoColor
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

Start adPEAS with all enumeration modules, enumerate the domain 'contoso.com' by using the domain controller 'dc1.contoso.com' and use the username 'contoso\johndoe' with password 'Passw0rd1!' during enumeration. If, due to DNS issues Active Directory detection fails, the switch -Force forces adPEAS to ignore those issues and try to get still as much information as possible.
```
Invoke-adPEAS -Domain 'contoso.com' -Server 'dc1.contoso.com' -Username 'contoso\johndoe' -Password 'Passw0rd1!' -Force
```

## Usage with a single enumeration module
### All modules below can be combined with all generic program parameters explained above.

Enumerates basic Active Directory information, like Domain Controllers, Password Policy, Sites and Subnets and Trusts.
```
Invoke-adPEAS -Module Domain
```

Enumerates specific Active Directory rights and permissions, like LAPS, DCSync and adding computer to domain.
```
Invoke-adPEAS -Module Rights
```

Enumerates basic GPO information, like set local group membership on domain computer.
```
Invoke-adPEAS -Module GPO
```

Enumerates basic Active Directory Certificate Services information, like CA Name, CA Server and common Template vulnerabilities.
```
Invoke-adPEAS -Module ADCS
```

Enumerates credential exposure issues, like ASREPRoast, Kerberoasting, Linux/Unix password attributes, gMSA, LAPS (if your account has the rights to read it), Group Policies, Netlogon scripts.
```
Invoke-adPEAS -Module Creds
```

Enumerates delegation issues, like 'Unconstrained Delegation', 'Constrained Delegation', 'Resource Based Constrained Delegation' for user and computer objects.
```
Invoke-adPEAS -Module Delegation
```

Enumerates users in high privileged groups which are NOT disabled, like Administrators, Domain Admins, Enterprise Admins, Group Policy Creators, DNS Admins, Account Operators, Server Operators, Printer Operators, Backup Operators, Hyper-V Admins, Remote Management Users und CERT Publishers.
```
Invoke-adPEAS -Module Accounts
```

Enumerates installed Domain Controllers, Active Directory Certificate Services, Exchange Server and outdated OS versions like Windows Server 2008R2.
```
Invoke-adPEAS -Module Computer
```

Starts Bloodhound enumeration with the scope DCOnly. Output ZIP files are stored in the same directory adPEAS is started from. The implemented SharpHound ingestor supports BloodHound Community Edition only.
```
Invoke-adPEAS -Module Bloodhound
```

Starts Bloodhound enumeration with the scope All. With this option the SharpHound collector will contact each member computer of the domain. Output ZIP files are stored in the same directory adPEAS is started from.
```
Invoke-adPEAS -Module Bloodhound -Scope All
```

## Special thanks go to...
* Will Schroeder @harmjoy, for his great PowerView
* Charlie Clark @exploitph, for his ongoing work on PowerView
* Christoph Falta @cfalta, for his inspiring work on PoshADCS
* Dirk-jan @_dirkjan, for his great AD and Windows research
* SpecterOps, for their fantastic BloodHound
* and all the people who inspired me on my journey...