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

            $usersWithPasswords = Get-DomainUser -LDAPFilter $passwordFilter -ShowOwner @PSBoundParameters

            if (@($usersWithPasswords).Count -gt 0) {
                Show-Line "Found $(@($usersWithPasswords).Count) account(s) with readable password attributes:" -Class "Finding"

                foreach ($user in $usersWithPasswords) {
                    $user | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'UnixPassword' -Force
                    Show-Object $user
                }
            } else {
                Show-Line "No accounts with readable password attributes found" -Class "Secure"
            }

        } catch {
            Write-Log "[Get-UnixPasswordAccounts] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-UnixPasswordAccounts] Check completed"
    }
}
