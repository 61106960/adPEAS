function Get-SIDHistoryInjection {
    <#
    .SYNOPSIS
    Detects accounts with privileged SIDs in sIDHistory (SID History Injection attack vector).

    .DESCRIPTION
    Identifies user and computer accounts that have privileged SIDs stored in their sIDHistory attribute.

    For a SID of another domain it also says where the source domain is: a domain of this
    forest (the Global Catalog lists them), a domain this domain trusts (securityIdentifier
    on its trust objects), or neither - the leftover of a migration from a domain that is
    gone or no longer trusted, counted in a line of its own for every account.

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

            # The yardstick the check was missing. sIDHistory holds, by definition, a SID
            # an account used to have in a *source* domain, so where the SID comes from
            # decides what the entry means:
            #
            #   own domain + privileged RID -> injection. The only way this arises is that
            #       somebody wrote it: no migration produces a SID of the domain the object
            #       already lives in.
            #   own domain + any other RID  -> the same anomaly with a less obvious target.
            #       An unprivileged account can still be the one with the DCSync ACE or the
            #       wide share access.
            #   foreign domain + privileged RID -> the documented ADMT result. Every
            #       migrated administrator carries the -512 of the domain they came from.
            #       Worth a look, because without SID filtering at the trust it is also how
            #       cross-forest injection presents - but it is not evidence on its own.
            #   foreign domain + other RID -> ordinary migration leftover.
            #
            # Without this comparison the check read the RID alone, so it reported a
            # CRITICAL injection for every migrated admin in every migrated domain, and
            # stayed silent on the one case that actually proves injection.
            $ownDomainSID = $Script:LDAPContext.DomainSID
            if ([string]::IsNullOrWhiteSpace($ownDomainSID)) {
                # Unknown origin is not the same statement as either answer. The check
                # falls back to the RID-only reading it had before and says so, rather
                # than accusing or clearing an account on a comparison it could not make.
                Write-Log "[Get-SIDHistoryInjection] Domain SID unknown - sIDHistory entries cannot be sorted by source domain" -Level Warning
                $ownDomainSID = $null
            }

            $privilegedFindings = @()
            $ownDomainFindings = @()
            $foreignPrivilegedFindings = @()
            $nonPrivilegedFindings = @()

            # Where a SID of another domain comes from: a domain of this forest, a domain
            # this domain trusts, or neither. sIDHistory bridges a migration; a SID whose
            # source domain is neither is the leftover of one that ended with the domain
            # gone or the trust removed. It still goes into the token at every logon here
            # and is honoured by every ACL that names it, and nothing in the directory
            # says what it was. Read only where there is a SID history to sort; $null in
            # either table means it could not be read.
            $forestDomains = @{}
            $trustedDomains = @{}
            $orphanedAccounts = @()
            $orphanedDomainSIDs = @()
            if ($objectsWithSIDHistory) {
                $forestDomains = Get-ForestDomainSID
                try {
                    foreach ($trustObject in @(Get-DomainObject -LDAPFilter '(objectClass=trustedDomain)' @connectionParams)) {
                        if ($trustObject -and $trustObject.securityIdentifier) {
                            $trustedDomains[[string]$trustObject.securityIdentifier] = [string]$trustObject.trustPartner
                        }
                    }
                } catch {
                    Write-Log "[Get-SIDHistoryInjection] Could not read the trusts: $_"
                    $trustedDomains = $null
                }
            }

            if ($objectsWithSIDHistory) {
                Write-Log "[Get-SIDHistoryInjection] Found $(@($objectsWithSIDHistory).Count) object(s) with sIDHistory"

                $totalObjects = @($objectsWithSIDHistory).Count
                $currentIndex = 0
                foreach ($obj in $objectsWithSIDHistory) {
                    $currentIndex++
                    if ($totalObjects -gt $Script:ProgressThreshold) { Show-Progress -Activity "Checking SID history" -Current $currentIndex -Total $totalObjects -ObjectName $obj.sAMAccountName }
                    $sidHistoryRaw = @($obj.sIDHistory)
                    $privilegedSIDs = @()
                    $ownDomainSIDs = @()
                    $foreignPrivilegedSIDs = @()
                    $nonPrivilegedSIDs = @()
                    # Source domain of every foreign SID on this account, domain SID -> text.
                    $sourceTexts = [ordered]@{}
                    $accountOrphaned = $false

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

                        $isPrivilegedRID = ($privilegeCheck.Category -in @('Privileged', 'Operator'))

                        # -like with the domain SID plus a dash, not -match: the SID is a
                        # value, not a pattern, and the trailing dash is what keeps a
                        # different domain whose SID merely starts with the same digits
                        # from counting as this one.
                        $isOwnDomain = $false
                        if ($ownDomainSID) { $isOwnDomain = ($sidString -like "$ownDomainSID-*") }

                        # Only an S-1-5-21 SID belongs to a domain at all, and only such a
                        # SID can be a migration record. A BUILTIN or NT AUTHORITY SID -
                        # S-1-5-32-548 and the like - is not from any source domain: ADMT
                        # does not write them, so one sitting in sIDHistory is an anomaly
                        # and belongs with the injections, not with the leftovers.
                        #
                        # Without a domain SID to compare against, nothing is treated as
                        # foreign: the check then reports what it reported before rather
                        # than clearing an account on a comparison it could not make.
                        $isForeignDomain = $false
                        if ($ownDomainSID) {
                            $isForeignDomain = ($sidString -like 'S-1-5-21-*') -and (-not $isOwnDomain)
                        }

                        if ($isForeignDomain) {
                            $sourceDomainSID = $sidString -replace '-\d+$', ''
                            if (-not $sourceTexts.Contains($sourceDomainSID)) {
                                $sourceTexts[$sourceDomainSID] = if ($null -ne $forestDomains -and $forestDomains.ContainsKey($sourceDomainSID)) {
                                    "$($forestDomains[$sourceDomainSID]) - a domain of this forest"
                                } elseif ($null -ne $trustedDomains -and $trustedDomains.ContainsKey($sourceDomainSID)) {
                                    "$($trustedDomains[$sourceDomainSID]) - trusted by this domain"
                                } elseif ($null -eq $forestDomains -or $null -eq $trustedDomains) {
                                    "$sourceDomainSID - unknown: the domains of the forest or the trusts could not be read"
                                } else {
                                    $accountOrphaned = $true
                                    if ($orphanedDomainSIDs -notcontains $sourceDomainSID) { $orphanedDomainSIDs += $sourceDomainSID }
                                    "$sourceDomainSID - neither a domain of this forest nor trusted by this domain"
                                }
                            }
                        }

                        if ($isPrivilegedRID -and -not $isForeignDomain) {
                            $privilegedSIDs += $sidInfo
                            Write-Log "[Get-SIDHistoryInjection] $($obj.sAMAccountName) has a privileged SID that is not from a source domain in sIDHistory: $sidString ($resolvedName)"
                        } elseif ($isPrivilegedRID) {
                            $foreignPrivilegedSIDs += $sidInfo
                            Write-Log "[Get-SIDHistoryInjection] $($obj.sAMAccountName) has a privileged SID of another domain in sIDHistory: $sidString ($resolvedName)"
                        } elseif ($isOwnDomain) {
                            $ownDomainSIDs += $sidInfo
                            Write-Log "[Get-SIDHistoryInjection] $($obj.sAMAccountName) has a SID of this domain in sIDHistory: $sidString ($resolvedName)"
                        } else {
                            $nonPrivilegedSIDs += $sidInfo
                            Write-Log "[Get-SIDHistoryInjection] $($obj.sAMAccountName) has non-privileged SID in sIDHistory: $sidString"
                        }
                    }

                    if ($accountOrphaned) { $orphanedAccounts += [string]$obj.sAMAccountName }
                    $sourceDisplay = @($sourceTexts.Values)

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

                        # sidHistoryInjectionRisk = "CRITICAL" used to sit here. No trigger
                        # matched it, CRITICAL is not an adPEAS severity class, and the row
                        # rendered as colourless text - it restated the card's own severity
                        # and carried no information of its own. The statement below says
                        # what the entry is instead, and names a card.
                        $obj | Add-Member -NotePropertyName 'sidHistoryNotFromSourceDomain' -NotePropertyValue (
                            $(if ($ownDomainSID) {
                                'This is a privileged SID that no migration can have written: it belongs either to this very domain or to no domain at all. sIDHistory holds the SID an account had in a source domain, so this entry was put there deliberately.'
                            } else {
                                'This is a privileged SID. The SID of this domain could not be read, so whether the entry comes from here or from a source domain is undecided - it is reported as it would have been before that comparison existed.'
                            })
                        ) -Force

                        $privilegedFindings += $obj
                    }

                    if (@($ownDomainSIDs).Count -gt 0 -and @($privilegedSIDs).Count -eq 0) {
                        $ownDomainDisplay = ($ownDomainSIDs | ForEach-Object {
                            if ($_.ResolvedName -ne "[Unresolved]") { "$($_.ResolvedName) ($($_.SID))" } else { $_.SID }
                        }) -join ", "

                        $obj | Add-Member -NotePropertyName 'ownDomainSIDHistory' -NotePropertyValue $ownDomainDisplay -Force
                        $obj | Add-Member -NotePropertyName 'sidHistoryOwnDomain' -NotePropertyValue (
                            'This SID belongs to this domain. sIDHistory holds the SID an account had in a source domain, so an entry from the local domain is an anomaly whatever its RID - the account it points at may be unprivileged and still hold the access an attacker wanted.'
                        ) -Force

                        $ownDomainFindings += $obj
                    }

                    if (@($foreignPrivilegedSIDs).Count -gt 0 -and @($privilegedSIDs).Count -eq 0) {
                        $foreignPrivilegedDisplay = ($foreignPrivilegedSIDs | ForEach-Object {
                            if ($_.ResolvedName -ne "[Unresolved]") { "$($_.ResolvedName) ($($_.SID))" } else { $_.SID }
                        }) -join ", "

                        $obj | Add-Member -NotePropertyName 'foreignPrivilegedSIDHistory' -NotePropertyValue $foreignPrivilegedDisplay -Force
                        $obj | Add-Member -NotePropertyName 'sidHistoryForeignPrivileged' -NotePropertyValue (
                            'This is a privileged SID of another domain, which is what a migration leaves behind - every account moved with ADMT from an administrative group carries one. It is also how cross-forest injection presents, so what decides between them is whether SID filtering is enforced on the trust - and sidHistorySource says whether a trust still leads to the source domain.'
                        ) -Force
                        $obj | Add-Member -NotePropertyName 'sidHistorySource' -NotePropertyValue $sourceDisplay -Force

                        $foreignPrivilegedFindings += $obj
                    }

                    if ($IncludeNonPrivileged -and @($nonPrivilegedSIDs).Count -gt 0 -and @($privilegedSIDs).Count -eq 0 -and @($ownDomainSIDs).Count -eq 0 -and @($foreignPrivilegedSIDs).Count -eq 0) {
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
                        if ($sourceDisplay.Count -gt 0) {
                            $obj | Add-Member -NotePropertyName 'sidHistorySource' -NotePropertyValue $sourceDisplay -Force
                        }

                        $nonPrivilegedFindings += $obj
                    }
                }
            }
            if ($totalObjects -gt $Script:ProgressThreshold) { Show-Progress -Activity "Checking SID history" -Completed }

            # Output results
            if (@($privilegedFindings).Count -gt 0) {
                Show-Line "Found $(@($privilegedFindings).Count) account(s) with a privileged SID in sIDHistory that no source domain explains:" -Class Finding

                foreach ($finding in $privilegedFindings) {
                    $finding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SIDHistory' -Force
                    $finding | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'Privileged' -Force
                    Show-Object $finding -Class Finding
                }
            } else {
                Show-Line "No account holds a privileged SID in sIDHistory that did not come from a source domain" -Class Secure
            }

            # A SID of this domain with any RID. Reported whether or not
            # -IncludeNonPrivileged was given: this is not a migration artifact, and the
            # account the SID points at can hold access that no group membership shows.
            if (@($ownDomainFindings).Count -gt 0) {
                Show-Line "Found $(@($ownDomainFindings).Count) account(s) whose sIDHistory holds a SID of this domain (not a migration artifact):" -Class Finding

                foreach ($finding in $ownDomainFindings) {
                    $finding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SIDHistory' -Force
                    $finding | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'Local SID' -Force
                    Show-Object $finding -Class Finding
                }
            }

            # A privileged SID of another domain: the documented result of a migration,
            # and worth a look rather than an accusation.
            if (@($foreignPrivilegedFindings).Count -gt 0) {
                Show-Line "Found $(@($foreignPrivilegedFindings).Count) account(s) whose sIDHistory holds a privileged SID of another domain (check SID filtering on the trust):" -Class Hint

                foreach ($finding in $foreignPrivilegedFindings) {
                    $finding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SIDHistory' -Force
                    $finding | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'Migrated privileged SID' -Force
                    Show-Object $finding -Class Hint
                }
            }

            # SID history whose source domain is neither in this forest nor trusted, for
            # every account and whether or not -IncludeNonPrivileged was given: a leftover
            # to remove, which the per-account rows above show only for privileged SIDs.
            if (@($orphanedAccounts).Count -gt 0) {
                Show-Line ("$(@($orphanedAccounts).Count) account(s) carry sIDHistory from $(@($orphanedDomainSIDs).Count) domain(s) this domain " +
                           "neither trusts nor shares a forest with - leftovers of a migration to remove: $(@($orphanedDomainSIDs) -join ', ')") -Class Hint -FindingId 'SID_HISTORY_ORPHANED'
            }

            # Non-privileged findings (migration artifacts) - only if requested
            if ($IncludeNonPrivileged -and @($nonPrivilegedFindings).Count -gt 0) {
                Show-SubHeader "Migration artifacts (non-privileged sIDHistory)..." -ObjectType "SIDHistory"
                Show-Line "Found $(@($nonPrivilegedFindings).Count) account(s) with non-privileged SIDs in sIDHistory (migration artifacts):" -Class Hint

                foreach ($finding in $nonPrivilegedFindings) {
                    $finding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SIDHistory' -Force
                    $finding | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'Migration' -Force
                    Show-Object $finding -Class Hint
                }
            }

        } catch {
            Write-Log "[Get-SIDHistoryInjection] Error: $_" -Level Error
            Show-Line "Error during check - SID history could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-SIDHistoryInjection] Check completed"
    }
}
