function Get-AdminPasswordNeverExpires {
    <#
    .SYNOPSIS
    Detects privileged accounts with "Password never expires" flag set and stale passwords.

    .DESCRIPTION
    Identifies privileged user accounts where:
    1. Password is configured to never expire (DONT_EXPIRE_PASSWORD flag)
    2. Password has not been changed in over 365 days
    3. Account is verifiably member of privileged groups (not just adminCount=1)

    Uses adminCount=1 as initial filter, then validates actual privilege status via Test-IsPrivileged
    to avoid false positives from orphaned adminCount flags.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .PARAMETER PasswordAgeDays
    Minimum password age in days to report (default: 365)

    .EXAMPLE
    Get-AdminPasswordNeverExpires

    .EXAMPLE
    Get-AdminPasswordNeverExpires -PasswordAgeDays 180

    .EXAMPLE
    Get-AdminPasswordNeverExpires -Domain "contoso.com" -Credential (Get-Credential)

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
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [int]$PasswordAgeDays = 365
    )

    begin {
        Write-Log "[Get-AdminPasswordNeverExpires] Starting check"
    }

    process {
        try {
            # Build connection parameters (exclude PasswordAgeDays which is not a connection parameter)
            $connectionParams = @{}
            if ($Domain) { $connectionParams['Domain'] = $Domain }
            if ($Server) { $connectionParams['Server'] = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                # Return without output to avoid redundant error display
                return
            }

            Show-SubHeader "Searching for privileged accounts with password never expires..." -ObjectType "PasswordNeverExpires"

            # Calculate FileTime for password age threshold
            $thresholdDate = (Get-Date).AddDays(-$PasswordAgeDays)
            $thresholdFileTime = $thresholdDate.ToFileTime()

            # The age is a grading now, not an entry condition. The flag says the password
            # will never rotate; the age only says how long that has already been true. A
            # Domain Admin with DONT_EXPIRE_PASSWORD whose password was set last month is
            # the same configuration as one set in 2017 - and demanding both in the filter
            # made that account invisible, so this check printed "No privileged accounts
            # with password never expires and password older than N days found" as a green
            # verdict over a domain full of them.
            #
            # pwdLastSet = 0 stays out: that is "must change at next logon", which the DC
            # honours over the flag.
            $passwordSetFilter = '(pwdLastSet>=1)'

            Write-Log "[Get-AdminPasswordNeverExpires] Password age threshold: $PasswordAgeDays days (before $(Format-adPEASDate $thresholdDate 'yyyy-MM-dd'))"

            # The candidate set is membership in a privileged group OR adminCount=1, not
            # adminCount alone. AdminSDHolder does not protect every group adPEAS counts as
            # privileged - Group Policy Creator Owners has no adminCount at all - and it
            # propagates hourly, so an account added this morning is not marked yet. Both
            # gaps used to be invisible here, and the verification below only ever removed
            # accounts, never found the missing ones.
            $privilegedFilter = Get-PrivilegedAccountFilter -IncludeOperators @connectionParams
            $candidates = Get-DomainUser -PasswordNeverExpires -LDAPFilter "(&$privilegedFilter$passwordSetFilter)" -ShowOwner @connectionParams

            if (-not $candidates -or @($candidates).Count -eq 0) {
                Show-Line "No privileged account has 'password never expires' set" -Class Secure
                return
            }

            # Annotated, not filtered: without -IsActive or -IsInactive, -IncludeDetails
            # only adds ActivityDetails and passes everything through.
            $candidates = @($candidates | Test-AccountActivity -IncludeDetails)

            Write-Log "[Get-AdminPasswordNeverExpires] Found $(@($candidates).Count) candidate(s) with adminCount=1, verifying actual privilege status..."

            # Verify each candidate is actually privileged (not just orphaned adminCount)
            $vulnerableAccounts = @()
            # The accounts that carry the flag but whose password is newer than the
            # threshold, and those where a smart card makes the flag harmless. Both used to
            # be absent from the report altogether.
            $recentAccounts = @()
            $smartcardAccounts = @()
            $totalCandidates = @($candidates).Count
            $currentIndex = 0

            foreach ($user in $candidates) {
                $currentIndex++

                # Progress indicator for large candidate counts
                if ($totalCandidates -gt $Script:ProgressThreshold) {
                    Show-Progress -Activity "Verifying privileged accounts" `
                                 -Current $currentIndex `
                                 -Total $totalCandidates `
                                 -ObjectName $user.sAMAccountName
                }

                $privCheck = Test-IsPrivileged -Identity $user

                if ($privCheck.IsPrivileged -or $privCheck.Category -eq 'Operator') {
                    # Add privilege information to the user object
                    $user | Add-Member -NotePropertyName 'PrivilegedGroup' -NotePropertyValue $privCheck.MatchedGroup -Force
                    $user | Add-Member -NotePropertyName 'PrivilegeCategory' -NotePropertyValue $privCheck.Category -Force

                    # Two things decide the grading on top of "is privileged": how long the
                    # password has already stood, and whether a smart card is required to log
                    # on at all - with SMARTCARD_REQUIRED the password is not a logon
                    # credential, so a password that never expires is not the same exposure.
                    #
                    # ActivityDetails is asked for by name first. Under Set-StrictMode
                    # -Version Latest - which Pester applies - reading a property that is not
                    # there is an error rather than $null, and a missing annotation has to
                    # mean "age unknown", not a broken check.
                    $passwordDays = $null
                    if ($user.PSObject.Properties['ActivityDetails'] -and $user.ActivityDetails) {
                        $passwordDays = $user.ActivityDetails.DaysSincePasswordChange
                    }

                    if (@($user.userAccountControl) -contains 'SMARTCARD_REQUIRED') {
                        $smartcardAccounts += $user
                    }
                    elseif ($null -ne $passwordDays -and $passwordDays -ge $PasswordAgeDays) {
                        $vulnerableAccounts += $user
                    }
                    else {
                        $recentAccounts += $user
                    }

                    Write-Log "[Get-AdminPasswordNeverExpires] Verified: $($user.sAMAccountName) is $($privCheck.Category) via $($privCheck.MatchedGroup)"
                } else {
                    Write-Log "[Get-AdminPasswordNeverExpires] Filtered out: $($user.sAMAccountName) has orphaned adminCount (Category: $($privCheck.Category))"
                }
            }

            # Clear progress bar
            if ($totalCandidates -gt $Script:ProgressThreshold) {
                Show-Progress -Activity "Verifying privileged accounts" -Completed
            }

            if (@($vulnerableAccounts).Count -gt 0) {
                Show-Line "Found $(@($vulnerableAccounts).Count) privileged account(s) with password never expires (password > $PasswordAgeDays days old):" -Class Finding

                foreach ($user in $vulnerableAccounts) {
                    $user | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PasswordNeverExpires' -Force
                    Show-Object $user -Class Finding
                }
            }

            if (@($recentAccounts).Count -gt 0) {
                Show-Line "$(@($recentAccounts).Count) further privileged account(s) carry the flag with a password newer than $PasswordAgeDays days:" -Class Hint

                foreach ($user in $recentAccounts) {
                    $user | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PasswordNeverExpires' -Force
                    Show-Object $user -Class Hint
                }
            }

            if (@($smartcardAccounts).Count -gt 0) {
                Show-Line "$(@($smartcardAccounts).Count) privileged account(s) carry the flag but require a smart card to log on:" -Class Hint

                foreach ($user in $smartcardAccounts) {
                    $user | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PasswordNeverExpires' -Force
                    Show-Object $user -Class Hint
                }
            }

            if (@($vulnerableAccounts).Count -eq 0 -and @($recentAccounts).Count -eq 0 -and @($smartcardAccounts).Count -eq 0) {
                Show-Line "No privileged account has 'password never expires' set (filtered $(@($candidates).Count) candidate(s) with orphaned adminCount)" -Class Secure
            }

        } catch {
            Write-Log "[Get-AdminPasswordNeverExpires] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-AdminPasswordNeverExpires] Check completed"
    }
}
