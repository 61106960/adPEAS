function Get-ComputerInitialPassword {
    <#
    .SYNOPSIS
    Finds computer accounts that still carry the password they were created with.

    .DESCRIPTION
    A computer account created in advance gets its first password from the tool that creates
    it. ADUC with "Assign this computer account as a pre-Windows 2000 computer" and
    "net computer /add" set the computer name in lowercase; "dsadd computer" sets none at all
    (pwdLastSet 0, PASSWD_NOTREQD) and the account then logs on over NTLM with an empty
    password. ADUC without that option and New-ADComputer set a password that is neither.
    A join replaces whatever was there with a random password, so the risk is the account
    that was never joined.

    A Windows join also writes operatingSystem and dNSHostName, and an account that has
    neither was never joined by a Windows client. That is what selects the candidates, and
    it is what keeps a normally joined computer out even where its password never changes:
    a join that creates the account sets the password in the same moment, and with rotation
    switched off pwdLastSet then stays at whenCreated for good (Get-ComputerPasswordAge
    reports that case).

    Three verdicts, written to passwordSinceCreation:
    - "Never set - empty password": pwdLastSet 0 with PASSWD_NOTREQD. Finding.
    - "Unchanged, in use": the password dates from the creation - set within five minutes of
      whenCreated - and the account has logged on since. Whoever uses it uses the creation
      password; a computer account created through ms-DS-MachineAccountQuota by a user looks
      the same. Hint.
    - "Unchanged, never used": the same, never logged on. Created in advance and never
      joined; whether its password is the default the directory does not say. Hint.

    Whether a password really is the default takes a logon attempt per account, which this
    check does not make - Invoke-PasswordSpray -Auto -ComputerDefault does, for the
    "Unchanged" accounts (the selection is shared, Get-ComputerInitialPasswordCandidate).
    Read-only: it changes no account, and it raises no bad password count.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-ComputerInitialPassword

    .EXAMPLE
    Get-ComputerInitialPassword -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Computer
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
        Write-Log "[Get-ComputerInitialPassword] Starting check"
    }

    process {
        try {
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            Show-SubHeader "Searching for computer accounts that still carry the password they were created with..." -ObjectType "ComputerInitialPassword"

            # The selection is shared with Invoke-PasswordSpray -ComputerDefault, so the check
            # and the spray cannot disagree about which accounts are candidates.
            $candidates = @(Get-ComputerInitialPasswordCandidate @PSBoundParameters)
            $neverSet  = @($candidates | Where-Object { $_.passwordSinceCreation -eq 'Never set - empty password' })
            $inUse     = @($candidates | Where-Object { $_.passwordSinceCreation -eq 'Unchanged, in use' })
            $neverUsed = @($candidates | Where-Object { $_.passwordSinceCreation -eq 'Unchanged, never used' })

            if ($neverSet.Count + $inUse.Count + $neverUsed.Count -eq 0) {
                Show-Line "No enabled computer account still carries the password it was created with" -Class Secure
                return
            }

            if ($neverSet.Count -gt 0) {
                Show-Line "$($neverSet.Count) computer account(s) never had a password set - over NTLM they log on with an empty one:" -Class Finding
                foreach ($computer in $neverSet) {
                    $computer | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'ComputerInitialPassword' -Force
                    Show-Object $computer -Class Finding
                }
            }

            if ($inUse.Count -gt 0) {
                Show-Line "$($inUse.Count) computer account(s) no Windows client joined are in use with their creation password:" -Class Hint
                foreach ($computer in $inUse) {
                    $computer | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'ComputerInitialPassword' -Force
                    Show-Object $computer -Class Hint
                }
            }

            if ($neverUsed.Count -gt 0) {
                Show-Line "$($neverUsed.Count) computer account(s) were created in advance and never used - the password may be the default:" -Class Hint
                foreach ($computer in $neverUsed) {
                    $computer | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'ComputerInitialPassword' -Force
                    Show-Object $computer -Class Hint
                }
            }

        } catch {
            Write-Log "[Get-ComputerInitialPassword] Error: $_" -Level Error
            Show-Line "Error during check - computer accounts with their creation password could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-ComputerInitialPassword] Check completed"
    }
}
