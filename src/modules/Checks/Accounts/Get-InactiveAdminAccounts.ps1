function Get-InactiveAdminAccounts {
    <#
    .SYNOPSIS
    Detects inactive privileged user accounts (adminCount=1).

    .DESCRIPTION
    Identifies privileged user accounts (adminCount=1) that have been inactive for an extended period based on lastLogonTimestamp.
    Also detects orphaned admin accounts: accounts with adminCount=1 but no current privileged group memberships (former admins with AdminSDHolder protection).

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .PARAMETER InactiveDays
    Number of days without login to consider an account inactive (default: 180)

    .EXAMPLE
    Get-InactiveAdminAccounts

    .EXAMPLE
    Get-InactiveAdminAccounts -InactiveDays 90

    .NOTES
    Category: Accounts
    Author: Alexander Sturz (@_61106960_)
    Privileged Groups Checked: Uses Test-IsPrivileged with SID-based detection (language-independent)
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
        [int]$InactiveDays = 180
    )

    begin {
        Write-Log "[Get-InactiveAdminAccounts] Starting check"
    }

    process {
        try {
            # Build connection parameters (exclude InactiveDays which is not a connection parameter)
            $connectionParams = @{}
            if ($Domain) { $connectionParams['Domain'] = $Domain }
            if ($Server) { $connectionParams['Server'] = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                # Return without output to avoid redundant error display
                return
            }

            Show-SubHeader "Searching for inactive privileged accounts (>$InactiveDays days)..." -ObjectType "InactiveAdmin"

            # Membership in a privileged group OR adminCount=1, not adminCount alone.
            # AdminSDHolder does not protect every group adPEAS counts as privileged -
            # Group Policy Creator Owners never receives adminCount - and it propagates
            # hourly, so a recent addition is not marked yet. The per-account group
            # resolution below then decides what each hit actually is.
            # -Enabled stays, deliberately. The review asked for disabled privileged
            # accounts to be reported here too, on the grounds that the account keeps its
            # membership and anybody who can write its userAccountControl can turn it back
            # on. That is true, and it is still the wrong place: disabling an account
            # instead of leaving it live is what a well-run domain DOES with a former
            # admin, so every one of them would arrive as a red row - a finding against
            # good practice. The re-enable path is about who holds rights on the object,
            # and Get-NonDefaultUserOwners covers that; it reads disabled accounts for
            # exactly this reason and says so in its own header.
            $privilegedFilter = Get-PrivilegedAccountFilter -IncludeOperators @connectionParams
            $adminAccounts = Get-DomainUser -Enabled -LDAPFilter $privilegedFilter @connectionParams

            $inactiveAccounts = @()

            if ($adminAccounts) {
                # Two passes, because -IsInactive and -NeverLoggedIn are different questions
                # and the first one answers "no" to the second: Test-AccountActivity drops an
                # account that has never logged in from -IsInactive on purpose and points at
                # -NeverLoggedIn for it. A privileged account that was created and never used
                # is the extreme case of inactive, not an account to leave out - and it used
                # to be invisible here.
                $inactiveAdmins = @($adminAccounts | Test-AccountActivity -IsInactive -InactiveDays $InactiveDays -IncludeDetails)
                $inactiveAdmins += @($adminAccounts | Test-AccountActivity -NeverLoggedIn -IncludeDetails)
                # One account cannot be in both passes - Test-AccountActivity decides by the
                # same timestamp - but the array is built from two of them, so the count has
                # to come from the joined set rather than from either pass.
                $inactiveAdmins = @($inactiveAdmins)
                $totalInactive = $inactiveAdmins.Count
                $currentIndex = 0

                foreach ($account in $inactiveAdmins) {
                    $currentIndex++
                    if ($totalInactive -gt $Script:ProgressThreshold) { 
                        Show-Progress -Activity "Processing inactive admin accounts" -Current $currentIndex -Total $totalInactive -ObjectName $account.sAMAccountName
                    }
                    # Get days since logon from Test-AccountActivity
                    $daysSinceLogon = $account.ActivityDetails.DaysSinceActivity

                    # Whether the account still holds privilege anywhere, or carries nothing
                    # but a left-over adminCount. SID-based through Test-IsPrivileged, so the
                    # answer does not depend on the language of the directory.
                    $privilegedGroups = @()
                    $isOrphaned = $true

                    # The primary group first. primaryGroupID puts the group's RID in the
                    # account's token and appears in no memberOf attribute, so an account
                    # whose primary group is Domain Admins was reported as "adminCount=1 but
                    # no privileged groups" while being a Domain Admin.
                    #
                    # Asked for by name: under Set-StrictMode -Version Latest, which Pester
                    # applies, reading a property that is not on the object is an error
                    # rather than $null, and an account without the attribute has to mean
                    # "no primary-group privilege", not a broken check.
                    $primaryRID = $null
                    if ($account.PSObject.Properties['primaryGroupID']) {
                        $primaryRID = [string]$account.primaryGroupID
                    }
                    if ($primaryRID -and $Script:LDAPContext.DomainSID) {
                        $primarySID = "$($Script:LDAPContext.DomainSID)-$primaryRID"
                        $primaryCheck = Test-IsPrivileged -Identity $primarySID -IncludeOperators
                        if ($primaryCheck.Category -in @('Privileged', 'Operator')) {
                            $primaryName = [string]$primaryCheck.MatchedGroup
                            if (-not $primaryName) { $primaryName = $primarySID }
                            $privilegedGroups += [PSCustomObject]@{
                                Name        = $primaryName
                                SID         = $primarySID
                                DisplayText = $primaryName
                            }
                            $isOrphaned = $false
                        }
                    }

                    if ($account.memberOf) {
                        foreach ($groupDN in $account.memberOf) {
                            # Test-IsPrivileged accepts DN and resolves to SID internally
                            $category = (Test-IsPrivileged -Identity $groupDN -IncludeOperators).Category
                            # 'Operator' counts as privilege here. The candidate filter above
                            # is built with -IncludeOperators, so an account whose only
                            # privileged membership is Account Operators arrives in this loop
                            # - and was then called orphaned, because Test-IsPrivileged
                            # answers Category = 'Operator' with IsPrivileged = $false for
                            # the four operator groups.
                            if ($category -in @('Privileged', 'Operator')) {
                                # Extract group name and resolve SID for proper classification
                                $groupName = if ($groupDN -match '^CN=([^,]+)') { $matches[1] } else { $groupDN }
                                $groupSID = ConvertTo-SID -Identity $groupDN

                                # Use new format with SID for tier classification
                                $privilegedGroups += [PSCustomObject]@{
                                    Name = $groupName
                                    SID = $groupSID
                                    DisplayText = $groupName
                                }
                                $isOrphaned = $false
                            }
                        }
                    }

                    # Add analysis properties to the full account object
                    # Note: privilegedGroups is intentionally NOT added here - memberOf already shows group membership
                    # privilegedGroups is only used in Get-PrivilegedGroupMembers for tier classification
                    $account | Add-Member -NotePropertyName 'daysSinceLastLogon' -NotePropertyValue $daysSinceLogon -Force
                    $account | Add-Member -NotePropertyName 'isOrphaned' -NotePropertyValue $isOrphaned -Force

                    # Said rather than implied. An account that never logged on has no
                    # "days since" to report, and a disabled one is not harmless - the
                    # owner of its userAccountControl can re-enable it.
                    if ($null -eq $daysSinceLogon) {
                        $account | Add-Member -NotePropertyName 'neverLoggedOn' -NotePropertyValue 'The account has never logged on - it was created and not used' -Force
                    }


                    $inactiveAccounts += $account
                }
            }

            # Clear progress bar
            if ($totalInactive -gt $Script:ProgressThreshold) { 
                Show-Progress -Activity "Processing inactive admin accounts" -Completed
            }

            # Output results: summary first, then objects
            if (@($inactiveAccounts).Count -gt 0) {
                $orphanedCount = @($inactiveAccounts | Where-Object { $_.isOrphaned }).Count
                $orphanedInfo = if ($orphanedCount -gt 0) { ", $orphanedCount orphaned (adminCount=1 but no privileged groups)" } else { "" }
                Show-Line "Found $(@($inactiveAccounts).Count) inactive privileged account(s) (>$InactiveDays days$orphanedInfo):" -Class Finding

                foreach ($account in $inactiveAccounts) {
                    $account | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'InactiveAdmin' -Force
                    Show-Object $account -Class Finding
                }
            } else {
                Show-Line "No inactive privileged accounts found" -Class Secure
            }

        } catch {
            Write-Log "[Get-InactiveAdminAccounts] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-InactiveAdminAccounts] Check completed"
    }
}
