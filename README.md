# adPEAS

adPEAS is a Powershell tool to automate Active Directory enumeration.
In fact, adPEAS is like a wrapper for different other cool projects like
* PowerView
* Empire
* Bloodhound
* and some own written lines of code

As said, adPEAS is a wrapper for other tools. They are almost all written in pure Powershell but some of them are included as compressed binary blob.

# How it works

adPEAS can be run simply by starting the script via 'invoke-adPEAS' if it is started on a domain joined computer.
If the system you are running adPEAS from is not domain joined or you want to enumerate another domain, use a certain domain controller to connect to, use different credentials or just to enumerate for credential exposure only, you can do it by using defined parameters.

## adPEAS Modules

adPEAS consits of the following enumeration modules:
* Domain - Searching for basic Active Directory information, like Domain Controllers, Sites und Subnets, Trusts and DCSync Rights
* Creds - Searching for different kind of credential exposure, like ASREPRoast, Kereberoasting, GroupPolicies, Netlogon Scripts, LAPS, certain account attributes, e.g. UnixPassword, etc.
* Delegation - Searching for delegation issues, like 'constrained delegation', 'unconstrained delegation' and 'resource based unconstrained delegation', for Computer and User Accounts
* Accounts - Searching for high privileged user accounts in predefined groups, account issues like e.g. password not expire
* Computer - Enumerating Domain Controllers and Exchange server, with the switch -Vulns it checks the systems for EternalBlue, BlueKeep, ZeroLogon and critical Exchange vulnerabilities
* Bloodhound - Enumerating Active Directory with BloodHound

## Some Examples

TBD
```sh
TBD
```



### Special thanks go to...
* Will Schroeder @harmjoy, for his great PowerView
* Dirk-jan @_dirkjan, for his great AD and Windows research
* SpecterOps, for their fantastic BloodHound
* BC-Security, for their great ongoing work with Empire
* Vincent LE TOUX @vletoux, for his vulnerability detection PoC's
* Joaquim Nogueira @lkys37en, for his idea to build a simple AD enumeration tool
* and all the people who inspired me on my journey...