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

            # Query privileged accounts (adminCount=1), enabled, using optimized filters and filter for inactive accounts using Test-AccountActivity
            $adminAccounts = Get-DomainUser -AdminCount -Enabled @connectionParams

            $inactiveAccounts = @()

            if ($adminAccounts) {
                # Use Test-AccountActivity to filter for inactive accounts
                # -IsInactive: accounts that haven't logged in within InactiveDays
                # -IncludeDetails: adds ActivityDetails property with parsed timestamps
                $inactiveAdmins = @($adminAccounts | Test-AccountActivity -IsInactive -InactiveDays $InactiveDays -IncludeDetails)
                $totalInactive = $inactiveAdmins.Count
                $currentIndex = 0

                foreach ($account in $inactiveAdmins) {
                    $currentIndex++
                    if ($totalInactive -gt $Script:ProgressThreshold) { 
                        Show-Progress -Activity "Processing inactive admin accounts" -Current $currentIndex -Total $totalInactive -ObjectName $account.sAMAccountName
                    }
                    # Get days since logon from Test-AccountActivity
                    $daysSinceLogon = $account.ActivityDetails.DaysSinceActivity

                    # Check if account is orphaned (no privileged groups)
                    # Use SID-based detection via Test-IsPrivileged for language independence
                    $privilegedGroups = @()
                    $isOrphaned = $true

                    if ($account.memberOf) {
                        foreach ($groupDN in $account.memberOf) {
                            # Test-IsPrivileged accepts DN and resolves to SID internally
                            $category = (Test-IsPrivileged -Identity $groupDN -IncludeOperators).Category
                            if ($category -eq 'Privileged') {
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
                    Show-Object $account
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
