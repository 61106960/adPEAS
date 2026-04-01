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

            # Build LDAP filter for password age (pwdLastSet older than threshold)
            # pwdLastSet=0 means "must change at next logon" - exclude these
            $passwordAgeFilter = "(&(pwdLastSet>=1)(pwdLastSet<=$thresholdFileTime))"

            Write-Log "[Get-AdminPasswordNeverExpires] Password age threshold: $PasswordAgeDays days (before $($thresholdDate.ToString('yyyy-MM-dd')))"

            $candidates = Get-DomainUser -AdminCount -PasswordNeverExpires -LDAPFilter $passwordAgeFilter -ShowOwner @connectionParams

            if (-not $candidates -or @($candidates).Count -eq 0) {
                Show-Line "No privileged accounts with password never expires and password older than $PasswordAgeDays days found" -Class Secure
                return
            }

            Write-Log "[Get-AdminPasswordNeverExpires] Found $(@($candidates).Count) candidate(s) with adminCount=1, verifying actual privilege status..."

            # Verify each candidate is actually privileged (not just orphaned adminCount)
            $vulnerableAccounts = @()
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
                    $vulnerableAccounts += $user

                    Write-Log "[Get-AdminPasswordNeverExpires] Verified: $($user.sAMAccountName) is $($privCheck.Category) via $($privCheck.MatchedGroup)"
                } else {
                    Write-Log "[Get-AdminPasswordNeverExpires] Filtered out: $($user.sAMAccountName) has orphaned adminCount (Category: $($privCheck.Category))"
                }
            }

            # Clear progress bar
            if ($totalCandidates -gt $Script:ProgressThreshold) {
                Show-Progress -Activity "Verifying privileged accounts" -Completed
            }

            if ($vulnerableAccounts -and @($vulnerableAccounts).Count -gt 0) {
                Show-Line "Found $(@($vulnerableAccounts).Count) privileged account(s) with password never expires (password > $PasswordAgeDays days old):" -Class Finding

                foreach ($user in $vulnerableAccounts) {
                    $user | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PasswordNeverExpires' -Force
                    Show-Object $user
                }
            } else {
                Show-Line "No privileged accounts with password never expires found (filtered $(@($candidates).Count) candidate(s) with orphaned adminCount)" -Class Secure
            }

        } catch {
            Write-Log "[Get-AdminPasswordNeverExpires] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-AdminPasswordNeverExpires] Check completed"
    }
}
