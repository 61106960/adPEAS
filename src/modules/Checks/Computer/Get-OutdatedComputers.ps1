function Get-OutdatedComputers {
    <#
    .SYNOPSIS
    Detects computers running an outdated Microsoft operating system.

    .DESCRIPTION
    Identifies active computer accounts running an unsupported Microsoft operating system,
    which poses a security risk because it no longer receives security updates.

    The subject is the Microsoft lifecycle. A member whose operatingSystem is not a
    Microsoft product - a Linux host, an appliance, a network printer - has no support date
    to run out and is not part of the figures. Every domain has some; reporting how many
    were "not evaluated" stated a number nobody could act on.

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

            Show-SubHeader "Searching for computers with outdated Microsoft operating systems..." -ObjectType "OutdatedComputer"

            # OPSEC mode: Skip heavy-load enumeration
            if ($OPSEC) {
                Show-Line "OPSEC mode: Skipping outdated computer check (would check all enabled computers)" -Class "Hint"
                return
            }

            # Step 1: Get computers with minimal attributes for filtering
            $computers = @(Get-DomainComputer -Enabled -Properties $FilterProperties @connectionParams)

            $inactiveFilteredCount = 0
            $outdatedComputerDNs = @()

            # Three states instead of a boolean, because the middle one cannot be
            # expressed as one: a machine past the date everyone stopped getting updates,
            # but inside a paid Extended Security Updates window its owner may or may not
            # have bought. Reporting that as a plain finding accuses every ESU customer;
            # reporting it as clean - which the lifecycle table used to do, by carrying the
            # ESU end as the support end - hides the most common end-of-life server there
            # is. It gets its own count and its own sentence.
            $esuOnlyComputerDNs = @()

            # A recognized product this table cannot place: a Windows 11 machine whose
            # build is absent or unknown. Counted and named, because "not assessable" is
            # not "supported" -
            # and Windows 11 used to fall into exactly this gap silently, for every build.
            $notAssessableCount = 0
            # Which systems, not only how many. Keyed by the OS string, so the output
            # names the build the table is missing - that is what lets a reader look the
            # support date up, and what says which entry has to be added here. The
            # comment above claimed these were "counted and named"; only the count was
            # ever kept.
            $notAssessableOS = @{}

            if (@($computers).Count -gt 0) {
                # Get enabled computers with activity details.
                # -InactiveDays has to be handed on: the parameter was declared, defaulted
                # and documented here, but never reached Test-AccountActivity, which then
                # fell back to the session default. "-InactiveDays 365" silently did nothing.
                $computersWithActivity = $computers | Test-AccountActivity -IncludeDetails -InactiveDays $InactiveDays

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

                    # Check if OS is outdated using central lifecycle module.
                    #
                    # An operating system the lifecycle table does not know is simply not
                    # this check's subject. The question is whether a Microsoft operating
                    # system has run out of support, and a Linux member, an appliance or a
                    # network printer has no answer to it - every domain has some, and
                    # counting them told the reader a number they could do nothing with.
                    $eolCheck = Test-IsOutdatedOS -OSName $computer.operatingSystem -OSVersion $computer.operatingSystemVersion

                    if ($eolCheck.SupportState -eq 'NotAssessable' -and $computer.ActivityDetails.IsActive) {
                        $notAssessableCount++
                        $osLabel = if ($computer.operatingSystemVersion) {
                            "$($computer.operatingSystem) / $($computer.operatingSystemVersion)"
                        } else {
                            [string]$computer.operatingSystem
                        }
                        if (-not $notAssessableOS.ContainsKey($osLabel)) { $notAssessableOS[$osLabel] = 0 }
                        $notAssessableOS[$osLabel]++
                        continue
                    }

                    if ($eolCheck.IsOutdated) {
                        # Check if computer is active
                        $isActive = $computer.ActivityDetails.IsActive

                        if ($isActive) {
                            # Store DN for later full fetch
                            if ($eolCheck.SupportState -eq 'ESUOnly') {
                                $esuOnlyComputerDNs += $computer.distinguishedName
                            } else {
                                $outdatedComputerDNs += $computer.distinguishedName
                            }
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

            # Step 2: Only fetch full objects for the machines that have a finding
            $inactiveInfo = if ($inactiveFilteredCount -gt 0) { " ($inactiveFilteredCount inactive accounts filtered)" } else { "" }

            if (@($outdatedComputerDNs).Count -gt 0) {
                Show-Line "Found $(@($outdatedComputerDNs).Count) computer(s) with an outdated Microsoft operating system:$inactiveInfo" -Class "Finding"
            }

            if (@($esuOnlyComputerDNs).Count -gt 0) {
                # The reader gets the conclusion; the card says what ESU means and that
                # the extension may never have been bought.
                Show-Line "$(@($esuOnlyComputerDNs).Count) computer(s) are past general support and inside the paid ESU window:" -Class "Hint"
            }

            if ($notAssessableCount -gt 0) {
                # Ten lines above, this check explains why it skips an operating system it
                # does not know: "counting them told the reader a number they could do
                # nothing with". This counter did exactly that - a number, no name, no
                # version, nothing to act on. Now it says which build is missing.
                Show-Line "$notAssessableCount active computer(s) run a Microsoft operating system this lifecycle table cannot place:" -Class "Note"
                foreach ($osLabel in ($notAssessableOS.Keys | Sort-Object)) {
                    Show-Line "  $osLabel - $($notAssessableOS[$osLabel]) computer(s)" -Class "Hint"
                }
            }

            $findingDNs = @($outdatedComputerDNs) + @($esuOnlyComputerDNs)
            if (@($findingDNs).Count -gt 0) {
                # Read the full objects in batches. One query per finding meant a domain
                # with three hundred end-of-life machines paid three hundred round-trips
                # for data a handful of queries return.
                $dnFilters = @(ConvertTo-LDAPDNFilter -DistinguishedName $findingDNs)
                foreach ($dnFilter in $dnFilters) {
                    foreach ($fullComputer in @(Get-DomainComputer -LDAPFilter $dnFilter @connectionParams)) {
                        # Get EOL details using central lifecycle module
                        $eolCheck = Test-IsOutdatedOS -OSName $fullComputer.operatingSystem -OSVersion $fullComputer.operatingSystemVersion
                        if ($eolCheck.IsOutdated) {
                            # Format EOL date as string for display
                            $eolDateStr = if ($eolCheck.EOLDate) { (Format-adPEASDate $eolCheck.EOLDate 'yyyy-MM-dd') } else { "Unknown" }
                            $fullComputer | Add-Member -NotePropertyName 'eolDate' -NotePropertyValue $eolDateStr -Force
                            $fullComputer | Add-Member -NotePropertyName 'daysSinceEoL' -NotePropertyValue $eolCheck.DaysSinceEOL -Force

                            # Which Windows 11 release the build identifies. Without it the
                            # row says "Windows 11 Enterprise" and nothing about the one
                            # property that decides whether it still gets updates.
                            if ($eolCheck.Release) {
                                $fullComputer | Add-Member -NotePropertyName 'osRelease' -NotePropertyValue $eolCheck.Release -Force
                            }

                            # The ESU window gets a sentence rather than a silent downgrade:
                            # the reader has to know that the date above is when updates
                            # stopped by default, and what would have had to be bought.
                            if ($eolCheck.SupportState -eq 'ESUOnly' -and $eolCheck.ESUEnd) {
                                $fullComputer | Add-Member -NotePropertyName 'osExtendedSecurityUpdates' -NotePropertyValue (
                                    "General support ended on $eolDateStr. Extended Security Updates are available until $(Format-adPEASDate $eolCheck.ESUEnd 'yyyy-MM-dd'), so this machine is patched only if that extension was purchased - which Active Directory does not record. Without it, it has been unpatched since $eolDateStr."
                                ) -Force
                            }
                        }
                        $fullComputer | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'OutdatedComputer' -Force
                        # The class of the line that announced it: past general support is
                        # the finding, inside the paid ESU window the hint.
                        Show-Object $fullComputer -Class $(if ($eolCheck.SupportState -eq 'ESUOnly') { 'Hint' } else { 'Finding' })
                    }
                }
            } elseif ($notAssessableCount -eq 0 -and $inactiveFilteredCount -gt 0) {
                Show-Line "No active computers with an outdated Microsoft operating system ($inactiveFilteredCount inactive accounts filtered)" -Class "Secure"
            } elseif ($notAssessableCount -eq 0) {
                Show-Line "No computers with an outdated Microsoft operating system found" -Class "Secure"
            }

        } catch {
            # Say so on the console, not only in the log - an aborted check is otherwise
            # indistinguishable from a domain without an outdated machine.
            Write-Log "[Get-OutdatedComputers] Error: $_" -Level Error
            Show-Line "Error during check - outdated operating systems could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-OutdatedComputers] Check completed"
    }
}

# Note: Get-NormalizedOSName and Test-IsOutdatedOS are now in adPEAS-SoftwareLifecycle.ps1
