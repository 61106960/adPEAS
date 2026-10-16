function Get-PasswordNotRequired {
    <#
    .SYNOPSIS
    Detects enabled user accounts with the PASSWD_NOTREQD flag set.

    .DESCRIPTION
    Identifies enabled user accounts where the "Password Not Required" (PASSWD_NOTREQD, UAC bit 32) flag is set.
    This flag allows the account to have an empty password, bypassing the domain password policy.
    While the flag alone does not guarantee an empty password (a password may have been set later), it indicates a hygiene issue and potential security risk.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-PasswordNotRequired

    .EXAMPLE
    Get-PasswordNotRequired -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Accounts
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
        Write-Log "[Get-PasswordNotRequired] Starting check"
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            Show-SubHeader "Searching for enabled accounts with 'Password Not Required' flag..." -ObjectType "PasswordNotRequired"

            # Query enabled user accounts with PASSWD_NOTREQD flag (UAC bit 32)
            $accounts = Get-DomainUser -Enabled -PasswordNotRequired -ShowOwner @PSBoundParameters

            if ($accounts -and @($accounts).Count -gt 0) {
                $totalAccounts = @($accounts).Count

                # One flat list used to come out of here, a kiosk account and a Domain Admin
                # next to each other with nothing to tell them apart. Three distinctions
                # carry the verdict and the check made none of them.
                #
                # Annotated, not filtered: without -IsActive or -IsInactive, -IncludeDetails
                # only adds ActivityDetails and passes every object through.
                $annotated = @($accounts | Test-AccountActivity -IncludeDetails)

                $emptyPassword = @()
                $privilegedAccounts = @()
                $trustAccounts = @()
                $ordinaryAccounts = @()

                $currentIndex = 0
                foreach ($user in $annotated) {
                    $currentIndex++
                    if ($totalAccounts -gt $Script:ProgressThreshold) { Show-Progress -Activity "Processing accounts without password requirement" -Current $currentIndex -Total $totalAccounts -ObjectName $user.sAMAccountName }

                    # A trust account carries this flag from the moment the trust is created
                    # - userAccountControl 2080 is INTERDOMAIN_TRUST_ACCOUNT plus
                    # PASSWD_NOTREQD - so every trust in the domain arrived here as a finding
                    # about a state nobody chose. Named, not assessed.
                    if (@($user.userAccountControl) -contains 'INTERDOMAIN_TRUST_ACCOUNT') {
                        $trustAccounts += $user
                        continue
                    }

                    $user | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PasswordNotRequired' -Force

                    # pwdLastSet = 0 is where "may be empty" becomes "is empty": the flag
                    # permits an empty password and none has ever been set on this account.
                    # That distinction is what makes this a finding rather than a hygiene
                    # note, and it was not made.
                    $neverSet = $false
                    if ($user.PSObject.Properties['ActivityDetails'] -and $user.ActivityDetails) {
                        $neverSet = [bool]$user.ActivityDetails.PasswordNeverSet
                    }

                    # And privilege. A Domain Admin exempt from the password policy stood in
                    # the same flat list as a kiosk account.
                    $privCheck = Test-IsPrivileged -Identity $user -IncludeOperators

                    # The verdicts are mutually exclusive by first word on purpose: two
                    # triggers on one attribute whose patterns can both match a value pick
                    # their winner by hashtable order.
                    if ($neverSet) {
                        $verdict = 'EMPTY - no password has ever been set'
                        if ($privCheck.IsPrivileged) { $verdict = $verdict + ', and the account is privileged' }
                        $user | Add-Member -NotePropertyName 'passwordNotRequiredVerdict' -NotePropertyValue $verdict -Force
                        $emptyPassword += $user
                    } elseif ($privCheck.IsPrivileged) {
                        $user | Add-Member -NotePropertyName 'passwordNotRequiredVerdict' -NotePropertyValue "PRIVILEGED ($($privCheck.Category)) - exempt from the password policy" -Force
                        $privilegedAccounts += $user
                    } else {
                        $user | Add-Member -NotePropertyName 'passwordNotRequiredVerdict' -NotePropertyValue 'Exempt from the password policy' -Force
                        $ordinaryAccounts += $user
                    }
                }
                if ($totalAccounts -gt $Script:ProgressThreshold) { Show-Progress -Activity "Processing accounts without password requirement" -Completed }

                if (@($emptyPassword).Count -gt 0) {
                    Show-Line "$(@($emptyPassword).Count) account(s) carry the flag and have never had a password set" -Class Finding
                    foreach ($user in $emptyPassword) { Show-Object $user -Class Finding }
                }

                if (@($privilegedAccounts).Count -gt 0) {
                    Show-Line "$(@($privilegedAccounts).Count) privileged account(s) are exempt from the password policy" -Class Finding
                    foreach ($user in $privilegedAccounts) { Show-Object $user -Class Finding }
                }

                if (@($ordinaryAccounts).Count -gt 0) {
                    Show-Line "$(@($ordinaryAccounts).Count) further enabled account(s) carry the 'Password Not Required' flag" -Class Hint
                    foreach ($user in $ordinaryAccounts) { Show-Object $user -Class Hint }
                }

                if (@($trustAccounts).Count -gt 0) {
                    Show-Line "Trust account(s) carrying the flag by design, not assessed: $(($trustAccounts | ForEach-Object { $_.sAMAccountName }) -join ', ')" -Class Note
                }
            } else {
                Show-Line "No enabled accounts with 'Password Not Required' flag found" -Class Secure
            }

        } catch {
            Write-Log "[Get-PasswordNotRequired] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-PasswordNotRequired] Check completed"
    }
}
