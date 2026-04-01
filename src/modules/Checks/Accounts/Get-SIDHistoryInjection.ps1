function Get-SIDHistoryInjection {
    <#
    .SYNOPSIS
    Detects accounts with privileged SIDs in sIDHistory (SID History Injection attack vector).

    .DESCRIPTION
    Identifies user and computer accounts that have privileged SIDs stored in their sIDHistory attribute.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .PARAMETER IncludeNonPrivileged
    Also report accounts with non-privileged SIDs in sIDHistory (migration artifacts)

    .EXAMPLE
    Get-SIDHistoryInjection

    .EXAMPLE
    Get-SIDHistoryInjection -IncludeNonPrivileged

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
        [switch]$IncludeNonPrivileged
    )

    begin {
        Write-Log "[Get-SIDHistoryInjection] Starting check"
    }

    process {
        try {
            # Build connection parameters (exclude IncludeNonPrivileged which is not a connection parameter)
            $connectionParams = @{}
            if ($Domain) { $connectionParams['Domain'] = $Domain }
            if ($Server) { $connectionParams['Server'] = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            Show-SubHeader "Searching for SID History Injection (privileged SIDs in sIDHistory)..." -ObjectType "SIDHistory"

            # Query all objects with sIDHistory attribute set
            $objectsWithSIDHistory = Get-DomainObject -LDAPFilter "(sIDHistory=*)" @connectionParams

            $privilegedFindings = @()
            $nonPrivilegedFindings = @()

            if ($objectsWithSIDHistory) {
                Write-Log "[Get-SIDHistoryInjection] Found $(@($objectsWithSIDHistory).Count) object(s) with sIDHistory"

                $totalObjects = @($objectsWithSIDHistory).Count
                $currentIndex = 0
                foreach ($obj in $objectsWithSIDHistory) {
                    $currentIndex++
                    if ($totalObjects -gt $Script:ProgressThreshold) { Show-Progress -Activity "Checking SID history" -Current $currentIndex -Total $totalObjects -ObjectName $obj.sAMAccountName }
                    $sidHistoryRaw = @($obj.sIDHistory)
                    $privilegedSIDs = @()
                    $nonPrivilegedSIDs = @()

                    foreach ($sidEntry in $sidHistoryRaw) {
                        # Convert byte array to SID string if needed
                        $sidString = $null
                        if ($sidEntry -is [byte[]]) {
                            try {
                                $secId = New-Object System.Security.Principal.SecurityIdentifier($sidEntry, 0)
                                $sidString = $secId.Value
                            } catch {
                                Write-Log "[Get-SIDHistoryInjection] Failed to convert sIDHistory byte array: $_"
                                continue
                            }
                        } elseif ($sidEntry -is [string]) {
                            $sidString = $sidEntry
                        } else {
                            continue
                        }

                        if (-not $sidString) { continue }

                        # Check if this sIDHistory SID is privileged
                        $privilegeCheck = Test-IsPrivileged -Identity $sidString -IncludeOperators
                        $resolvedName = ConvertFrom-SID -SID $sidString

                        $sidInfo = [PSCustomObject]@{
                            SID = $sidString
                            ResolvedName = if ($resolvedName -and $resolvedName -ne $sidString) { $resolvedName } else { "[Unresolved]" }
                            Category = $privilegeCheck.Category
                            Reason = $privilegeCheck.Reason
                        }

                        if ($privilegeCheck.Category -in @('Privileged', 'Operator')) {
                            $privilegedSIDs += $sidInfo
                            Write-Log "[Get-SIDHistoryInjection] $($obj.sAMAccountName) has privileged SID in sIDHistory: $sidString ($resolvedName)"
                        } else {
                            $nonPrivilegedSIDs += $sidInfo
                            Write-Log "[Get-SIDHistoryInjection] $($obj.sAMAccountName) has non-privileged SID in sIDHistory: $sidString"
                        }
                    }

                    # Add findings
                    if (@($privilegedSIDs).Count -gt 0) {
                        # Format privileged SIDs for display
                        $privilegedSIDsDisplay = ($privilegedSIDs | ForEach-Object {
                            if ($_.ResolvedName -ne "[Unresolved]") {
                                "$($_.ResolvedName) ($($_.SID))"
                            } else {
                                $_.SID
                            }
                        }) -join ", "

                        $obj | Add-Member -NotePropertyName 'privilegedSIDHistory' -NotePropertyValue $privilegedSIDsDisplay -Force
                        $obj | Add-Member -NotePropertyName 'privilegedSIDHistoryCount' -NotePropertyValue @($privilegedSIDs).Count -Force
                        $obj | Add-Member -NotePropertyName 'sidHistoryInjectionRisk' -NotePropertyValue "CRITICAL" -Force

                        $privilegedFindings += $obj
                    }

                    if ($IncludeNonPrivileged -and @($nonPrivilegedSIDs).Count -gt 0 -and @($privilegedSIDs).Count -eq 0) {
                        # Only add to non-privileged if no privileged SIDs found (avoid duplicates)
                        $nonPrivilegedSIDsDisplay = ($nonPrivilegedSIDs | ForEach-Object {
                            if ($_.ResolvedName -ne "[Unresolved]") {
                                "$($_.ResolvedName) ($($_.SID))"
                            } else {
                                $_.SID
                            }
                        }) -join ", "

                        $obj | Add-Member -NotePropertyName 'nonPrivilegedSIDHistory' -NotePropertyValue $nonPrivilegedSIDsDisplay -Force
                        $obj | Add-Member -NotePropertyName 'sIDHistoryCount' -NotePropertyValue $nonPrivilegedSIDs.Count -Force

                        $nonPrivilegedFindings += $obj
                    }
                }
            }
            if ($totalObjects -gt $Script:ProgressThreshold) { Show-Progress -Activity "Checking SID history" -Completed }

            # Output results
            if (@($privilegedFindings).Count -gt 0) {
                Show-Line "Found $(@($privilegedFindings).Count) account(s) with PRIVILEGED SIDs in sIDHistory (SID History Injection):" -Class Finding

                foreach ($finding in $privilegedFindings) {
                    $finding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SIDHistory' -Force
                    $finding | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'Privileged' -Force
                    Show-Object $finding
                }
            } else {
                Show-Line "No accounts with privileged SIDs in sIDHistory found" -Class Secure
            }

            # Non-privileged findings (migration artifacts) - only if requested
            if ($IncludeNonPrivileged -and @($nonPrivilegedFindings).Count -gt 0) {
                Show-SubHeader "Migration artifacts (non-privileged sIDHistory)..." -ObjectType "SIDHistory"
                Show-Line "Found $(@($nonPrivilegedFindings).Count) account(s) with non-privileged SIDs in sIDHistory (migration artifacts):" -Class Hint

                foreach ($finding in $nonPrivilegedFindings) {
                    $finding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SIDHistory' -Force
                    $finding | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'Migration' -Force
                    Show-Object $finding
                }
            }

        } catch {
            Write-Log "[Get-SIDHistoryInjection] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-SIDHistoryInjection] Check completed"
    }
}
