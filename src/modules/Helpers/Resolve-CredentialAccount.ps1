function Resolve-CredentialAccount {
    <#
    .SYNOPSIS
    Says what the user name found beside a password stands for in the directory.

    .DESCRIPTION
    Get-CredentialExposure reports the user name it found in a file. Whether a domain
    account of that name exists, whether it is enabled, whether it is privileged, and
    whether its password changed after the file was written is what separates a credential
    usable today from a piece of history - and the report said none of it.

    Only this domain is asked, by sAMAccountName or userPrincipalName, with the value
    escaped: a name read out of a file is data, and an asterisk in it must not turn the
    lookup into a wildcard search. Some names are said to be what they are instead of being
    looked up, because the domain account of the same name is not the account they mean:

    - a variable (%USERNAME%, $user), filled in on the computer at run time
    - a local or built-in account (.\name, BUILTIN\..., NT AUTHORITY\...)
    - a name qualified with anything but this domain's NetBIOS or DNS name. The first label
      of the DNS name is deliberately not taken for this domain: it is a different name
      wherever the NetBIOS name differs from it (see Connect-LDAP), and a computer of that
      name owns the accounts qualified with it
    - every account in a Groups.xml. Group Policy Preferences use that file to set local
      accounts on the computers the policy applies to, so its "Administrator" is each
      computer's own Administrator and not the domain's

    A user principal name is looked up as one first. When no account carries it and its
    suffix is this domain's DNS name, it is then the implicit UPN, which logs on as the
    account whose sAMAccountName is the part before the @.

    The answer is information and changes no severity: a password for an account that is
    gone is still a password somebody chose, and often one used elsewhere.

    Cached per lookup for the session in $Script:CredentialAccountCache. Never throws - the
    caller reads SYSVOL inside Invoke-SMBAccess, where an exception marks the share as
    failed for every later check.

    .PARAMETER UserName
    The user name as found in the file.

    .PARAMETER FileName
    The leaf name of the file the name was found in, for the file whose accounts are local
    by definition (Groups.xml).

    .PARAMETER FileTime
    The file's LastWriteTime, to compare the account's pwdLastSet with. Optional.

    .OUTPUTS
    [string] for the accountInAD row, or $null for an empty name or without a directory
    session.

    .NOTES
    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$false)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$UserName,

        [Parameter(Mandatory=$false)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$FileName,

        [Parameter(Mandatory=$false)]
        [AllowNull()]
        $FileTime
    )

    try {
        # Quotes around the name belong to the script, not to the account:
        # net use ... /user:"CONTOSO\svc_maps"
        $name = "$UserName".Trim().Trim([char[]]@('"', "'")).Trim()
        if (-not $name) { return $null }

        # A custom-path scan can run without a directory session. There is nothing to ask
        # then, and no row is better than one that claims a lookup failed.
        if (-not $Script:LdapConnection) { return $null }

        if ($FileName -match '^Groups\.xml$') {
            return 'Not looked up - Groups.xml sets local accounts on the computers the policy applies to, not domain accounts'
        }

        if ($name -match '%[^%]+%|^\$') {
            return 'Not looked up - the name is a variable, filled in on the computer at run time'
        }

        $domainPart  = $null
        $accountPart = $name
        $upnSuffix   = $null
        if ($name -match '^(?<domainName>[^\\]+)\\(?<accountName>[^\\]+)$') {
            $domainPart  = $Matches['domainName']
            $accountPart = $Matches['accountName']
        } elseif ($name -match '^(?<accountName>[^@\\]+)@(?<upnSuffix>[^@\\]+)$') {
            $accountPart = $Matches['accountName']
            $upnSuffix   = $Matches['upnSuffix']
        }

        if ($null -ne $domainPart) {
            if ($domainPart -in @('.', 'localhost', 'BUILTIN', 'NT AUTHORITY', 'NT SERVICE')) {
                return 'Not looked up - a local or built-in account of the computer, not a domain account'
            }

            $isOwnDomain = $false
            foreach ($ownName in @("$($Script:LDAPContext.DomainNetBIOS)", "$($Script:LDAPContext.Domain)")) {
                if ($ownName -and [string]::Equals($ownName, $domainPart, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $isOwnDomain = $true
                }
            }
            if (-not $isOwnDomain) {
                return "Not looked up - qualified with $domainPart, which is not this domain: another domain, or a computer's local accounts"
            }
        }

        # The characters a sAMAccountName cannot hold. A name carrying one is a placeholder
        # or a fragment of script syntax, and "no account of this name" would send the
        # reader looking for a deleted account.
        if ($accountPart -match '["/\\\[\]:;|=,+*?<>]') {
            return 'Not looked up - the name holds characters an account name cannot have'
        }

        $filters = @()
        if ($upnSuffix) {
            $filters += "(userPrincipalName=$(Escape-LDAPFilterValue -Value $name))"
            if ([string]::Equals($upnSuffix, "$($Script:LDAPContext.Domain)", [System.StringComparison]::OrdinalIgnoreCase)) {
                $filters += "(sAMAccountName=$(Escape-LDAPFilterValue -Value $accountPart))"
            }
        } else {
            $filters += "(sAMAccountName=$(Escape-LDAPFilterValue -Value $accountPart))"
        }

        # Keyed by the filter. A PowerShell hashtable compares its keys without regard to
        # case, which is how the directory compares the names in them.
        if ($null -eq $Script:CredentialAccountCache) { $Script:CredentialAccountCache = @{} }

        $account = $null
        foreach ($filter in $filters) {
            if (-not $Script:CredentialAccountCache.ContainsKey($filter)) {
                # -Properties: an internal lookup whose result is a sentence, not a shown
                # object.
                $Script:CredentialAccountCache[$filter] = @(Get-DomainUser -LDAPFilter $filter -Properties 'sAMAccountName', 'userAccountControl', 'pwdLastSet', 'objectSid')[0]
            }
            $account = $Script:CredentialAccountCache[$filter]
            if ($account) { break }
        }

        if (-not $account) {
            return 'No domain account of this name - the password may belong to a local account, an account outside the directory, or one that was deleted or renamed'
        }

        $isDisabled = @($account.userAccountControl) -contains 'ACCOUNTDISABLE'
        $text = if ($isDisabled) { 'Domain account of this name: disabled' } else { 'Domain account of this name: enabled' }

        $accountSid = "$($account.objectSid)"
        if ($accountSid) {
            $privilege = $null
            try { $privilege = Test-IsPrivileged -Identity $accountSid -IncludeOperators } catch { $privilege = $null }
            if ($privilege -and $privilege.IsPrivileged -eq $true) {
                $via = "$($privilege.Reason)"
                if ($privilege.MatchedGroup) {
                    $via = "member of $($privilege.MatchedGroup)"
                } elseif ($via -match 'sIDHistory') {
                    $via = 'through its sIDHistory'
                } elseif ($accountSid -match '-500$') {
                    $via = "the domain's built-in Administrator"
                }
                $text += ", privileged ($via)"
            }
        }

        # Whether the password found can still be the one set. pwdLastSet arrives as a
        # DateTime, or as the raw 0 that means "must change at next logon" -
        # ConvertFrom-LDAPAttribute passes 0 through unconverted.
        $pwdLastSet = $account.pwdLastSet
        if ($pwdLastSet -is [datetime]) {
            $setText = Format-adPEASDate $pwdLastSet 'yyyy-MM-dd'
            if ($FileTime -is [datetime]) {
                $fileText = Format-adPEASDate $FileTime 'yyyy-MM-dd'
                if ($pwdLastSet -gt $FileTime) {
                    $text += "; password changed $setText, after the file was last written ($fileText) - the password found is probably outdated"
                } else {
                    $text += "; password unchanged since $setText, before the file was last written ($fileText) - the password found may still be valid"
                }
            } else {
                $text += "; password last set $setText"
            }
        } elseif ("$pwdLastSet" -eq '0') {
            $text += '; the password must be changed at next logon'
        }

        return $text
    } catch {
        Write-Log "[Resolve-CredentialAccount] Lookup of '$UserName' failed: $_"
        return 'Unknown - the directory lookup failed'
    }
}
