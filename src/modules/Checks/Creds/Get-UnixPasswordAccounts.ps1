function Get-UnixPasswordAccounts {
    <#
    .SYNOPSIS
    Detects user accounts with readable password attributes in Active Directory.

    .DESCRIPTION
    Identifies user accounts with passwords or hashes stored in readable AD attributes.
    These passwords are often stored in weak or reversible formats and represent a security risk.

    Checked attributes:
    - unixUserPassword: Unix/Linux integration (often Base64 or plaintext)
    - userPassword: LDAP standard password attribute (often Base64)
    - msSFU30Password: Services for Unix 3.0 (plaintext/Base64)
    - sambaNTPassword: Samba integration NT hash (hex, directly usable for PtH)
    - sambaLMPassword: Samba LM hash (hex, weak encryption)

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-UnixPasswordAccounts

    .EXAMPLE
    Get-UnixPasswordAccounts -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Creds
    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    begin {
        Write-Log "[Get-UnixPasswordAccounts] Starting check"
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            Show-SubHeader "Searching for accounts with readable password attributes..." -ObjectType "UnixPassword"

            # Extended LDAP filter for all password-related attributes
            # unixUserPassword: Unix/Linux integration, userPassword: LDAP standard, msSFU30Password: Services for Unix 3.0, sambaNTPassword: Samba NT hash, sambaLMPassword: Samba LM hash
            $passwordFilter = "(|(unixUserPassword=*)(userPassword=*)(msSFU30Password=*)(sambaNTPassword=*)(sambaLMPassword=*))"

            # Get-DomainObject, not Get-DomainUser: the user query adds
            # (&(objectCategory=person)(objectClass=user)(!(objectClass=computer))), and
            # none of these five attributes is confined to user objects. A Unix-integrated
            # host with unixUserPassword on its computer account, or a contact carrying
            # userPassword, is the same leaked credential and was invisible here.
            $usersWithPasswords = Get-DomainObject -LDAPFilter $passwordFilter -ShowOwner @PSBoundParameters

            # The five attributes, in the order the filter names them. Read per object,
            # because one account can carry two of them in two different formats.
            $passwordAttributes = @('unixUserPassword', 'userPassword', 'msSFU30Password',
                                    'sambaNTPassword', 'sambaLMPassword')

            $readable = @()
            $withheld = @()

            # Ranked rather than compared: an account whose only value is the documented
            # empty-LM placeholder stays a note, and one carrying both a $6$ hash and a
            # cleartext password is rendered as the louder of the two.
            $rank = @{ 'Note' = 0; 'Hint' = 1; 'Finding' = 2 }

            foreach ($user in $usersWithPasswords) {
                # Did the value actually arrive? The presence filter is ACL-gated, so an
                # object that comes back normally carries the attribute - but it can come
                # back with the attribute stripped, by an ACL or by the confidential flag,
                # and then "readable password attribute" is a claim about access the
                # operator does not have. The two neighbouring checks grew this guard for
                # the same reason; this one reported every object the filter returned.
                $formats = @()
                $worstRank = 0
                foreach ($attribute in $passwordAttributes) {
                    $value = [string]$user.$attribute
                    if ([string]::IsNullOrWhiteSpace($value)) { continue }

                    # What the value is decides what it is worth: a cleartext password or an
                    # NT hash is usable as it stands, an LM or DES hash falls in hours, and a
                    # salted $6$ has to be cracked first. All of it used to be one red
                    # finding with one score.
                    $verdict = Get-UnixPasswordFormat -Value $value -Attribute $attribute
                    $formats += "${attribute}: $($verdict.Format)"
                    $thisRank = 1
                    if ($rank.ContainsKey([string]$verdict.Severity)) { $thisRank = $rank[[string]$verdict.Severity] }
                    if ($thisRank -gt $worstRank) { $worstRank = $thisRank }
                }

                if ($formats.Count -eq 0) {
                    $withheld += $user
                    Write-Log "[Get-UnixPasswordAccounts] Attribute withheld for '$($user.distinguishedName)'"
                    continue
                }

                $user | Add-Member -NotePropertyName 'passwordFormat' -NotePropertyValue $formats -Force
                $user | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'UnixPassword' -Force
                $worst = 'Hint'
                foreach ($name in $rank.Keys) { if ($rank[$name] -eq $worstRank) { $worst = $name } }
                $readable += [PSCustomObject]@{ Object = $user; Class = $worst }
            }

            if (@($readable).Count -gt 0) {
                Show-Line "Found $(@($readable).Count) account(s) with readable password attributes:" -Class "Finding"

                foreach ($entry in $readable) {
                    Show-Object $entry.Object -Class $entry.Class
                }
            } else {
                Show-Line "No accounts with readable password attributes found" -Class "Secure"
            }

            # Named rather than counted: these accounts do carry one of the attributes, and
            # which ones is what a reader needs to ask the directory about.
            if (@($withheld).Count -gt 0) {
                $withheldNames = @($withheld | ForEach-Object {
                    if ($_.sAMAccountName) { $_.sAMAccountName } else { $_.distinguishedName }
                })
                Show-Line "The value was not readable on: $($withheldNames -join ', ')" -Class "Note"
            }

        } catch {
            Write-Log "[Get-UnixPasswordAccounts] Error: $_" -Level Error
            Show-Line "Error during check - Unix password attributes could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-UnixPasswordAccounts] Check completed"
    }
}
