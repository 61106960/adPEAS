function Get-OutdatedComputers {
    <#
    .SYNOPSIS
    Detects computers running outdated/unsupported Windows operating systems.

    .DESCRIPTION
    Identifies active computer accounts running unsupported Windows versions that pose security risks due to lack of security updates.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .PARAMETER InactiveDays
    Number of days since last logon to consider a computer as inactive (default: 90)

    .EXAMPLE
    Get-OutdatedComputers

    .EXAMPLE
    Get-OutdatedComputers -InactiveDays 180

    .NOTES
    Category: Computer
    Author: Alexander Sturz (@_61106960_)
    Note: lastLogonTimestamp has 9-14 day replication latency.
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
        [int]$InactiveDays = 90,

        [Parameter(Mandatory=$false)]
        [switch]$OPSEC
    )

    begin {
        Write-Log "[Get-OutdatedComputers] Starting check"

        # Windows lifecycle data is now centralized in adPEAS-SoftwareLifecycle.ps1
        # Uses: $Script:WindowsLifecycle, Get-NormalizedOSName, Test-IsOutdatedOS

        # Properties needed for filtering
        $FilterProperties = @('distinguishedName', 'operatingSystem', 'operatingSystemVersion', 'userAccountControl', 'lastLogonTimestamp')
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
                return
            }

            Show-SubHeader "Searching for computers with outdated operating systems..." -ObjectType "OutdatedComputer"

            # OPSEC mode: Skip heavy-load enumeration
            if ($OPSEC) {
                Show-Line "OPSEC mode: Skipping outdated computer check (would check all enabled computers)" -Class "Hint"
                return
            }

            # Step 1: Get computers with minimal attributes for filtering
            $computers = @(Get-DomainComputer -Enabled -Properties $FilterProperties @connectionParams)

            $inactiveFilteredCount = 0
            $outdatedComputerDNs = @()

            if (@($computers).Count -gt 0) {
                # Get enabled computers with activity details
                $computersWithActivity = $computers | Test-AccountActivity -IncludeDetails

                $currentIndex = 0
                $totalComputers = @($computersWithActivity).Count

                foreach ($computer in $computersWithActivity) {
                    $currentIndex++

                    # Progress indicator for large computer counts
                    if ($totalComputers -gt 50) {
                        Show-Progress -Activity "Checking outdated OS" `
                                     -Current $currentIndex `
                                     -Total $totalComputers
                    }
                    # Skip if no OS info
                    if ([string]::IsNullOrEmpty($computer.operatingSystem)) {
                        continue
                    }

                    # Check if OS is outdated using central lifecycle module
                    $eolCheck = Test-IsOutdatedOS -OSName $computer.operatingSystem -OSVersion $computer.operatingSystemVersion

                    if ($eolCheck.IsOutdated) {
                        # Check if computer is active
                        $isActive = $computer.ActivityDetails.IsActive

                        if ($isActive) {
                            # Store DN for later full fetch
                            $outdatedComputerDNs += $computer.distinguishedName
                        } else {
                            # Count inactive outdated computers (stale accounts, not displayed)
                            $inactiveFilteredCount++
                        }
                    }
                }

                # Clear progress bar
                if ($totalComputers -gt 50) {
                    Show-Progress -Activity "Checking outdated OS" -Completed
                }
            }

            # Step 2: Only fetch full objects for outdated computers (for Show-Object)
            if (@($outdatedComputerDNs).Count -gt 0) {
                $inactiveInfo = if ($inactiveFilteredCount -gt 0) { " ($inactiveFilteredCount inactive accounts filtered)" } else { "" }
                Show-Line "Found $(@($outdatedComputerDNs).Count) computer(s) with outdated operating systems:$inactiveInfo" -Class "Finding"

                foreach ($dn in $outdatedComputerDNs) {
                    $fullComputer = @(Get-DomainComputer -Identity $dn @connectionParams)[0]
                    if ($fullComputer) {
                        # Get EOL details using central lifecycle module
                        $eolCheck = Test-IsOutdatedOS -OSName $fullComputer.operatingSystem -OSVersion $fullComputer.operatingSystemVersion
                        if ($eolCheck.IsOutdated) {
                            # Format EOL date as string for display
                            $eolDateStr = if ($eolCheck.EOLDate) { $eolCheck.EOLDate.ToString("yyyy-MM-dd") } else { "Unknown" }
                            $fullComputer | Add-Member -NotePropertyName 'eolDate' -NotePropertyValue $eolDateStr -Force
                            $fullComputer | Add-Member -NotePropertyName 'daysSinceEoL' -NotePropertyValue $eolCheck.DaysSinceEOL -Force
                        }
                        $fullComputer | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'OutdatedComputer' -Force
                        Show-Object $fullComputer
                    }
                }
            } elseif ($inactiveFilteredCount -gt 0) {
                Show-Line "No active computers with outdated OS ($inactiveFilteredCount inactive accounts filtered)" -Class "Secure"
            } else {
                Show-Line "No computers with outdated operating systems found" -Class "Secure"
            }

        } catch {
            Write-Log "[Get-OutdatedComputers] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-OutdatedComputers] Check completed"
    }
}

# Note: Get-NormalizedOSName and Test-IsOutdatedOS are now in adPEAS-SoftwareLifecycle.ps1
