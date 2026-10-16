function Get-LAPSPermissions {
    <#
    .SYNOPSIS
    Analyzes LAPS password read permissions across Organizational Units.

    .DESCRIPTION
    Scans all OUs containing computers and identifies who has permissions to read LAPS password attributes:

    - ms-Mcs-AdmPwd (Legacy LAPS)
    - msLAPS-Password (Windows LAPS Native)

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .PARAMETER IncludePrivileged
    Also report privileged accounts with LAPS read access (shown as yellow/Hint severity).

    .EXAMPLE
    Get-LAPSPermissions

    .EXAMPLE
    Get-LAPSPermissions -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Rights
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
        [switch]$IncludePrivileged
    )

    begin {
        Write-Log "[Get-LAPSPermissions] Starting check"
    }

    process {
        try {
            # Build connection parameters (exclude IncludePrivileged which is not a connection parameter)
            $connectionParams = @{}
            if ($Domain) { $connectionParams['Domain'] = $Domain }
            if ($Server) { $connectionParams['Server'] = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            Show-SubHeader "Analyzing LAPS read permissions by OU..." -ObjectType "LAPSPermission"

            # One definition of "does this domain run LAPS", shared with
            # Get-LAPSConfiguration and Get-LAPSCredentialAccess and cached for the session.
            $lapsSchema = Get-LAPSSchemaPresence @connectionParams
            $lapsLegacySchemaPresent = $lapsSchema.LegacyPresent
            $windowsLAPSSchemaPresent = $lapsSchema.NativePresent

            if (-not $lapsLegacySchemaPresent -and -not $windowsLAPSSchemaPresent) {
                Show-Line "No LAPS schema found" -Class Note
                return
            }

            # Every enabled computer, and the activity measured per OU rather than used
            # to build the scope. The scope used to be the output of
            # Test-AccountActivity -IsActive, which drops a machine that has not logged
            # on within $Script:DefaultInactiveDays and drops one that never logged on
            # outright - so an OU whose machines are all dormant or pre-staged was never
            # analysed at all.
            #
            # That is the wrong way round for LAPS specifically. The password rotates
            # when the machine checks in, so a dormant machine is precisely the one
            # whose stored password is still the current local administrator password. A
            # staging or imaging OU, where machines are created in advance and have
            # never logged on, is the most convenient route to a golden image, and it
            # was invisible.
            #
            # The reason this filter was added - a decommissioned computer would invent
            # an OU nobody has to clean up any more - is already served by -Enabled,
            # which filters server-side: a decommissioned machine is a disabled one. On
            # top of -Enabled, the activity test removes exactly the enabled-but-quiet
            # machines, which are the interesting ones here. Activity now shapes the
            # text instead of the scope, so a reader can still tell a live OU from a
            # graveyard.
            $allComputers = @(Get-DomainComputer -Enabled -Properties "distinguishedName","lastLogonTimestamp" @connectionParams)
            $activeDNs = @{}
            foreach ($active in @($allComputers | Test-AccountActivity -IsActive)) {
                if ($active.distinguishedName) { $activeDNs[[string]$active.distinguishedName] = $true }
            }

            $computersByOU = @{}
            $activeByOU = @{}
            foreach ($computer in $allComputers) {
                $dn = $computer.distinguishedName
                if ($dn -match '^CN=[^,]+,(.+)$') {
                    $ouDN = $Matches[1]
                    if (-not $computersByOU.ContainsKey($ouDN)) {
                        $computersByOU[$ouDN] = 0
                        $activeByOU[$ouDN] = 0
                    }
                    $computersByOU[$ouDN]++
                    if ($activeDNs.ContainsKey([string]$dn)) { $activeByOU[$ouDN]++ }
                }
            }

            Write-Log "[Get-LAPSPermissions] Found $(@($computersByOU.Keys).Count) unique OUs with computers"

            # Analyze permissions for each OU
            $ouPermissionsResults = @()
            $filteredFindings = @()
            $allowedSeverities = if ($IncludePrivileged) { @('Critical', 'High', 'Medium', 'Info') } else { @('Critical', 'High', 'Medium') }

            $totalOUs = $computersByOU.Keys.Count
            $currentIndex = 0
            $unreadOUs = @()
            foreach ($ouDN in $computersByOU.Keys) {
                $currentIndex++
                if ($totalOUs -gt $Script:ProgressThreshold) { Show-Progress -Activity "Checking LAPS permissions" -Current $currentIndex -Total $totalOUs -ObjectName $ouDN }
                $computerCount = $computersByOU[$ouDN]
                $activeCount = $activeByOU[$ouDN]
                Write-Log "[Get-LAPSPermissions] Analyzing OU: $ouDN ($computerCount computers, $activeCount active)"

                try {
                    # Get-OUPermissions uses session context automatically
                    $ouPerms = Get-OUPermissions -DistinguishedName $ouDN -CheckType 'LAPS'

                    # An OU whose descriptor could not be read has no findings either, and
                    # the conclusion below used to count it as analyzed. Only an explicit
                    # $false counts as unread - see Get-DangerousOUPermissions.
                    if (-not $ouPerms -or $ouPerms.Read -eq $false) {
                        $unreadOUs += $ouDN
                    }

                    if ($ouPerms -and $ouPerms.Findings) {
                        $legacyReaders = @()
                        $nativeReaders = @()

                        # Whether the trustee holds CONTROL_ACCESS anywhere on this OU,
                        # which is not the same question as whether one ACE carries it.
                        # Set-AdmPwdReadPasswordPermission writes two ACEs - a ReadProperty
                        # on the attribute and All Extended Rights - and they arrive here as
                        # two findings for the same principal, only the second of which has
                        # GrantsControlAccess. They are also sorted into different lists, and
                        # the legacy list keeps the first entry per SID, so the attribute
                        # finding would never have seen the other one. Judging it alone
                        # downgrades the standard LAPS delegation - the common case, and a
                        # real finding - to a hint.
                        $controlAccessBySID = @{}
                        foreach ($caFinding in $ouPerms.Findings) {
                            if ($caFinding.GrantsControlAccess -ne $true) { continue }
                            $caSID = [string]$caFinding.SID
                            if ($caSID) { $controlAccessBySID[$caSID] = $true }
                        }

                        foreach ($finding in $ouPerms.Findings) {
                            $principal = $finding.Principal
                            $sid = $finding.SID
                            $severity = $finding.Severity

                            # A blanket "read all properties" ACE does not reach a LAPS
                            # password while the attribute is confidential in the schema:
                            # MS-ADTS requires READ_PROPERTY *and* CONTROL_ACCESS for such
                            # an attribute, which is why Set-AdmPwdReadPasswordPermission
                            # writes two ACEs. Every one of those delegations used to be
                            # reported as "LAPS Password Read" at finding severity, so a
                            # helpdesk or monitoring read on a computer OU came out as
                            # "can read every local administrator password here" - and the
                            # customer removed a permission that grants nothing while
                            # believing LAPS was compromised.
                            #
                            # Three states, not two. The right is live when the ACE carries
                            # CONTROL_ACCESS, live as well when the attribute is NOT
                            # confidential (then a plain read is enough), and otherwise
                            # blocked by the flag - which is worth a hint rather than a
                            # finding, because it becomes live the moment the flag is
                            # cleared.
                            # The severity stays where it is, so the row keeps its place in
                            # the report - it is the label and the card behind it that
                            # change. Dropping the severity instead would take the row out
                            # of the output altogether, which is the other way to be wrong
                            # about it.
                            # Any read short of CONTROL_ACCESS, not just an all-properties
                            # one. A ReadProperty ACE on the confidential attribute itself is
                            # equally short of what MS-ADTS requires, and the ADUC checkbox
                            # "Read ms-Mcs-AdmPwd" without "All extended rights" produces
                            # exactly that - it was reported as a live password read.
                            $holdsControlAccess = ($finding.GrantsControlAccess -eq $true) -or
                                                  ($controlAccessBySID.ContainsKey([string]$finding.SID))
                            $blockedByConfidentialFlag = ((-not $holdsControlAccess) -and
                                                          ($Script:LAPSSchemaInfo.PasswordConfidential -eq $true))

                            # Which generation this right reads is decided here, where the
                            # Right string is still at hand, and carried on the reader. The
                            # output used to say "LAPS Password Read" for either, and in a
                            # domain part way through the migration that is the difference
                            # between reading the password of the machines already moved
                            # and of the ones still on the legacy attribute.

                            # Match Legacy LAPS (ms-Mcs-AdmPwd)
                            if ($finding.Right -match 'ms-Mcs-AdmPwd') {
                                if ($sid -notin @($legacyReaders | ForEach-Object { $_.SID })) {
                                    $legacyReaders += [PSCustomObject]@{
                                        Principal = $principal
                                        SID = $sid
                                        Severity = $severity
                                        BlockedByConfidentialFlag = $blockedByConfidentialFlag
                                        Generation = 'Legacy'
                                    }
                                }
                            }
                            # Match Windows LAPS (msLAPS-*) - includes EncryptedPassword, EncryptedPasswordHistory, Password, etc.
                            # Also match "All Properties" which covers all LAPS types
                            elseif ($finding.Right -match 'msLAPS-' -or $finding.Right -match 'All Properties') {
                                # The encrypted attribute is kept apart from the
                                # plaintext one. Reading msLAPS-EncryptedPassword
                                # returns a blob that only the principal named in
                                # ADPasswordEncryptionPrincipal can open through
                                # NCryptUnprotectSecret, so it is not a password read -
                                # and reporting it as one teaches the reader that the
                                # encrypted generation buys nothing.
                                $thisGeneration = if ($finding.Right -match 'All Properties') {
                                    # A read on every property covers whichever
                                    # attribute the machine actually carries.
                                    'Legacy and Windows LAPS'
                                } elseif ($finding.Right -match 'msLAPS-Encrypted') {
                                    'Windows LAPS (encrypted)'
                                } else {
                                    'Windows LAPS'
                                }

                                $existingNative = @($nativeReaders | Where-Object { $_.SID -eq $sid })[0]
                                if (-not $existingNative) {
                                    $nativeReaders += [PSCustomObject]@{
                                        Principal = $principal
                                        SID = $sid
                                        Severity = $severity
                                        BlockedByConfidentialFlag = $blockedByConfidentialFlag
                                        Generation = $thisGeneration
                                    }
                                } elseif ($existingNative.Generation -eq 'Windows LAPS (encrypted)' -and
                                          $thisGeneration -ne 'Windows LAPS (encrypted)') {
                                    # A plaintext or all-properties read outranks a blob
                                    # read: the same principal gets the password without
                                    # the decryptor. Upgrading in place rather than adding
                                    # a second entry keeps one row per principal, which is
                                    # what this check reports - and stops the order the
                                    # findings happen to arrive in deciding the verdict.
                                    $existingNative.Generation = $thisGeneration
                                }
                            }
                        }

                        # Filter findings by allowed severities
                        # Check each reader for Exchange service group membership
                        $allReaders = $legacyReaders + $nativeReaders
                        $matchedReaders = @($allReaders | Where-Object { $_.Severity -in $allowedSeverities })

                        foreach ($reader in $matchedReaders) {
                            # Check if this is an Exchange service group
                            $exchangeCheck = Test-IsExchangeServiceGroup -Identity $reader.SID
                            if ($exchangeCheck.IsExchangeService) {
                                $reader | Add-Member -NotePropertyName 'IsExchangeService' -NotePropertyValue $true -Force
                                $reader | Add-Member -NotePropertyName 'OriginalSeverity' -NotePropertyValue $reader.Severity -Force
                                $reader.Severity = 'Attention'
                                Write-Log "[Get-LAPSPermissions] Exchange service group detected: $($reader.Principal)"
                            } else {
                                $reader | Add-Member -NotePropertyName 'IsExchangeService' -NotePropertyValue $false -Force
                                # Mark privileged accounts (Info from Get-OUPermissions) for yellow display
                                $isPriv = $reader.Severity -eq 'Info'
                                $reader | Add-Member -NotePropertyName 'IsPrivilegedAccount' -NotePropertyValue $isPriv -Force
                                if ($isPriv) {
                                    $reader | Add-Member -NotePropertyName 'OriginalSeverity' -NotePropertyValue $reader.Severity -Force
                                    $reader.Severity = 'Attention'
                                }
                            }
                        }

                        if (@($matchedReaders).Count -gt 0) {
                            $filteredFindings += [PSCustomObject]@{
                                OU = $ouDN
                                ComputerCount = $computerCount
                                ActiveComputerCount = $activeCount
                                MatchedReaders = $matchedReaders
                                LegacyReaders = $legacyReaders
                                NativeReaders = $nativeReaders
                            }
                        }

                        $ouPermissionsResults += [PSCustomObject]@{
                            OU = $ouDN
                            ComputerCount = $computerCount
                            ActiveComputerCount = $activeCount
                            LegacyReaders = $legacyReaders
                            NativeReaders = $nativeReaders
                        }
                    }
                } catch {
                    if ($unreadOUs -notcontains $ouDN) { $unreadOUs += $ouDN }
                    Write-Log "[Get-LAPSPermissions] Failed to query permissions for OU '$ouDN': $_"
                }
            }
            if ($totalOUs -gt $Script:ProgressThreshold) { Show-Progress -Activity "Checking LAPS permissions" -Completed }

            # How many were really examined, and the class the clean conclusion deserves.
            # Both conclusion lines below used to name the full OU count and stay Secure
            # whatever was readable.
            $readOUs = $totalOUs - @($unreadOUs).Count
            $coverageIncomplete = Show-OUPermissionsCoverageNote -UnreadOUs $unreadOUs -TotalOUs $totalOUs
            $conclusionClass = 'Secure'
            if ($coverageIncomplete) { $conclusionClass = 'Note' }

            # Names the right and which LAPS generation it reads. Without the suffix a
            # delegation on the legacy attribute and one on the Windows LAPS attribute
            # printed identically, and the reader had no way to tell whether the principal
            # can read the password of the machines already migrated, of the ones still on
            # the old attribute, or of both.
            function Get-LAPSRightLabel {
                param($ReaderInfo)

                # A principal whose only right is a blanket read of all properties does
                # not reach the password while the attribute is confidential, so the
                # label says that instead of "LAPS Password Read" - and a different
                # finding definition hangs off this text, a hint rather than a finding.
                if ($ReaderInfo.AllBlockedByConfidentialFlag -eq $true) {
                    return 'Read all properties - blocked by the confidential flag on the LAPS password attribute, live as soon as that flag is cleared'
                }

                $generations = @($ReaderInfo.Generations)
                if ($generations.Count -eq 0) { return 'LAPS Password Read' }

                # Only the encrypted attribute, and nothing else that carries the
                # password: the right returns a blob rather than a password, so the
                # label says so and a hint hangs off this wording instead of the
                # password-read finding. Same shape as the confidential-flag case
                # above. If the principal also reads a plaintext attribute the
                # generation list holds that too, and this branch is not taken.
                $encryptedOnly = ($generations.Count -eq 1) -and
                                 ($generations -contains 'Windows LAPS (encrypted)')
                if ($encryptedOnly) {
                    return 'LAPS Password Read (Windows LAPS - encrypted) - needs the authorized decryptor named in ADPasswordEncryptionPrincipal to open the blob'
                }

                return ('LAPS Password Read (' + (($generations | Sort-Object) -join ', ') + ')')
            }

            # ===== Output findings =====
            if (@($filteredFindings).Count -gt 0) {
                # Group findings by principal and deduplicate OUs - a principal may have multiple LAPS property rights on the same OU
                # Track Exchange, privileged, and non-privileged separately
                $allReaderSIDs = @{}
                $exchangeReaderSIDs = @{}
                $privilegedReaderSIDs = @{}

                foreach ($finding in $filteredFindings) {
                    foreach ($reader in $finding.MatchedReaders) {
                        $sid = $reader.SID
                        $isExchange = $reader.IsExchangeService -eq $true
                        $isPriv = $reader.IsPrivilegedAccount -eq $true

                        # Choose correct hashtable based on status
                        $targetHash = if ($isExchange) { $exchangeReaderSIDs }
                            elseif ($isPriv) { $privilegedReaderSIDs }
                            else { $allReaderSIDs }

                        if (-not $targetHash.ContainsKey($sid)) {
                            $targetHash[$sid] = @{
                                Principal = $reader.Principal
                                SID = $sid
                                OUs = @()
                                Generations = @()
                                IsExchangeService = $isExchange
                                IsPrivilegedAccount = $isPriv

                                # Starts true and is cleared by the first contribution that
                                # does reach a password. A principal holding a blanket read
                                # on one OU and a delegated read of the password attribute
                                # on another has the password, and the label has to say so.
                                AllBlockedByConfidentialFlag = $true
                            }
                        }

                        if ($reader.BlockedByConfidentialFlag -ne $true) {
                            $targetHash[$sid].AllBlockedByConfidentialFlag = $false
                        }
                        # Only add OU if not already in the list (deduplicate)
                        # The active count is named only when it differs. Saying
                        # "3 computers, 3 active" on every line would add a word and no
                        # information; saying "12 computers, 3 active" tells the reader
                        # nine machines hold a password LAPS has not rotated since they
                        # went quiet - which is the password that still works on them.
                        $ouEntry = if ($null -ne $finding.ActiveComputerCount -and $finding.ActiveComputerCount -ne $finding.ComputerCount) {
                            "$($finding.OU) ($($finding.ComputerCount) computers, $($finding.ActiveComputerCount) active)"
                        } else {
                            "$($finding.OU) ($($finding.ComputerCount) computers)"
                        }
                        if ($targetHash[$sid].OUs -notcontains $ouEntry) {
                            $targetHash[$sid].OUs += $ouEntry
                        }

                        # A principal can hold a right on both generations, and on several
                        # OUs, so the labels accumulate per principal rather than replace.
                        if ($reader.Generation -and $targetHash[$sid].Generations -notcontains $reader.Generation) {
                            $targetHash[$sid].Generations += $reader.Generation
                        }
                    }
                }

                # Batch resolve all unique SIDs to AD objects (avoids N+1 LDAP queries in display loops)
                $sidObjectMap = @{}
                $allUniqueSIDs = @(@($allReaderSIDs.Keys) + @($privilegedReaderSIDs.Keys) + @($exchangeReaderSIDs.Keys) | Sort-Object -Unique)
                $resolvableSIDs = @($allUniqueSIDs | Where-Object { $_ -notmatch '^S-1-5-\d+$' })

                if ($resolvableSIDs.Count -gt 0) {
                    $totalSIDs = $resolvableSIDs.Count
                    $currentSIDIndex = 0
                    foreach ($resolveSID in $resolvableSIDs) {
                        $currentSIDIndex++
                        if ($totalSIDs -gt $Script:ProgressThreshold) {
                            Show-Progress -Activity "Resolving account details" -Current $currentSIDIndex -Total $totalSIDs
                        }
                        $sidHex = ConvertTo-LDAPSIDHex -SID $resolveSID
                        if ($sidHex) {
                            $obj = @(Get-DomainObject -LDAPFilter "(objectSid=$sidHex)" @connectionParams)[0]
                            if ($obj) { $sidObjectMap[$resolveSID] = $obj }
                        }
                    }
                    if ($totalSIDs -gt $Script:ProgressThreshold) {
                        Show-Progress -Activity "Resolving account details" -Completed
                    }
                }

                # Display non-privileged, non-Exchange findings as Finding (red)
                if ($allReaderSIDs.Keys.Count -gt 0) {
                    Show-Line "Found $($allReaderSIDs.Keys.Count) non-privileged account(s) with LAPS read access" -Class Finding

                    foreach ($sid in $allReaderSIDs.Keys) {
                        $readerInfo = $allReaderSIDs[$sid]
                        $isWellKnownSID = $sid -match '^S-1-5-\d+$'
                        $adObject = if ($sidObjectMap.ContainsKey($sid)) { $sidObjectMap[$sid] } else { $null }

                        # A read the confidential flag blocks is not a password read, so the
                        # row is a hint. Severity for the dangerousRights family is decided
                        # by this property - the per-definition Risk is display-only - so
                        # without it the row would be red whatever the card behind it says.
                        $readerSeverity = $null
                        if ($readerInfo.AllBlockedByConfidentialFlag -eq $true) { $readerSeverity = 'Hint' }

                        if ($adObject) {
                            $adObject | Add-Member -NotePropertyName 'dangerousRights' -NotePropertyValue (Get-LAPSRightLabel -ReaderInfo $readerInfo) -Force
                            $adObject | Add-Member -NotePropertyName 'affectedOUs' -NotePropertyValue $readerInfo.OUs -Force
                            if ($readerSeverity) {
                                $adObject | Add-Member -NotePropertyName 'dangerousRightsSeverity' -NotePropertyValue $readerSeverity -Force
                            }
                            $adObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LAPSPermission' -Force
                            Show-Object $adObject -Class $(if ([string]$adObject.dangerousRightsSeverity -in @('Expected', 'Attention', 'Hint')) { 'Hint' } else { 'Finding' })
                        } else {
                            $resolvedName = if ($isWellKnownSID) { ConvertFrom-SID -SID $sid } else { $readerInfo.Principal }
                            $fallbackObject = [PSCustomObject]@{
                                sAMAccountName = $resolvedName
                                objectSid = $sid
                                dangerousRights = (Get-LAPSRightLabel -ReaderInfo $readerInfo)
                                affectedOUs = $readerInfo.OUs
                            }
                            if ($readerSeverity) {
                                $fallbackObject | Add-Member -NotePropertyName 'dangerousRightsSeverity' -NotePropertyValue $readerSeverity -Force
                            }
                            $fallbackObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LAPSPermission' -Force
                            Show-Object $fallbackObject -Class $(if ([string]$fallbackObject.dangerousRightsSeverity -in @('Expected', 'Attention', 'Hint')) { 'Hint' } else { 'Finding' })
                        }
                    }
                }

                # Display privileged findings as Hint (yellow) when -IncludePrivileged
                if ($IncludePrivileged -and $privilegedReaderSIDs.Keys.Count -gt 0) {
                    Show-Line "Found $($privilegedReaderSIDs.Keys.Count) privileged account(s) with LAPS read access (expected)" -Class Hint

                    foreach ($sid in $privilegedReaderSIDs.Keys) {
                        $readerInfo = $privilegedReaderSIDs[$sid]
                        $isWellKnownSID = $sid -match '^S-1-5-\d+$'
                        $adObject = if ($sidObjectMap.ContainsKey($sid)) { $sidObjectMap[$sid] } else { $null }

                        if ($adObject) {
                            $adObject | Add-Member -NotePropertyName 'dangerousRights' -NotePropertyValue (Get-LAPSRightLabel -ReaderInfo $readerInfo) -Force
                            $adObject | Add-Member -NotePropertyName 'affectedOUs' -NotePropertyValue $readerInfo.OUs -Force
                            $adObject | Add-Member -NotePropertyName 'dangerousRightsSeverity' -NotePropertyValue 'Hint' -Force
                            $adObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LAPSPermission' -Force
                            Show-Object $adObject -Class Hint
                        } else {
                            $resolvedName = if ($isWellKnownSID) { ConvertFrom-SID -SID $sid } else { $readerInfo.Principal }
                            $fallbackObject = [PSCustomObject]@{
                                sAMAccountName = $resolvedName
                                objectSid = $sid
                                dangerousRights = (Get-LAPSRightLabel -ReaderInfo $readerInfo)
                                affectedOUs = $readerInfo.OUs
                                dangerousRightsSeverity = 'Hint'
                            }
                            $fallbackObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LAPSPermission' -Force
                            Show-Object $fallbackObject -Class Hint
                        }
                    }
                }

                # Display Exchange service group findings as Hint (yellow) - by-design permissions
                # Only shown with -IncludePrivileged (Exchange groups are privileged by design)
                if ($IncludePrivileged -and $exchangeReaderSIDs.Keys.Count -gt 0) {
                    Show-Line "Found $($exchangeReaderSIDs.Keys.Count) Exchange service group(s) with LAPS read access (by-design, cannot be removed)" -Class Hint

                    foreach ($sid in $exchangeReaderSIDs.Keys) {
                        $readerInfo = $exchangeReaderSIDs[$sid]
                        $isWellKnownSID = $sid -match '^S-1-5-\d+$'
                        $adObject = if ($sidObjectMap.ContainsKey($sid)) { $sidObjectMap[$sid] } else { $null }

                        if ($adObject) {
                            $adObject | Add-Member -NotePropertyName 'dangerousRights' -NotePropertyValue (Get-LAPSRightLabel -ReaderInfo $readerInfo) -Force
                            $adObject | Add-Member -NotePropertyName 'affectedOUs' -NotePropertyValue $readerInfo.OUs -Force
                            $adObject | Add-Member -NotePropertyName 'dangerousRightsSeverity' -NotePropertyValue 'Hint' -Force
                            $adObject | Add-Member -NotePropertyName '_isExchangeGroup' -NotePropertyValue $true -Force
                            $adObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LAPSPermission' -Force
                            Show-Object $adObject -Class Hint
                        } else {
                            $resolvedName = if ($isWellKnownSID) { ConvertFrom-SID -SID $sid } else { $readerInfo.Principal }
                            $fallbackObject = [PSCustomObject]@{
                                sAMAccountName = $resolvedName
                                objectSid = $sid
                                dangerousRights = (Get-LAPSRightLabel -ReaderInfo $readerInfo)
                                affectedOUs = $readerInfo.OUs
                                dangerousRightsSeverity = 'Hint'
                            }
                            $fallbackObject | Add-Member -NotePropertyName '_isExchangeGroup' -NotePropertyValue $true -Force
                            $fallbackObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LAPSPermission' -Force
                            Show-Object $fallbackObject -Class Hint
                        }
                    }
                }

                # If no non-Exchange findings were displayed (and Exchange is hidden without -IncludePrivileged)
                if ($allReaderSIDs.Keys.Count -eq 0 -and $privilegedReaderSIDs.Keys.Count -eq 0 -and (-not $IncludePrivileged -or $exchangeReaderSIDs.Keys.Count -eq 0)) {
                    Show-Line "No non-privileged accounts with LAPS read access found in $readOUs analyzed OU(s)" -Class $conclusionClass
                }

            } elseif ($totalOUs -gt 0 -and $readOUs -le 0) {
                Show-Line "LAPS read permissions were not evaluated - no security descriptor could be read" -Class Note
            } else {
                Show-Line "No non-privileged accounts with LAPS read access found in $readOUs analyzed OU(s)" -Class $conclusionClass
            }

        } catch {
            # Say so on the console, not only in the log - an aborted check is otherwise
            # indistinguishable from a domain with nothing to report.
            Write-Log "[Get-LAPSPermissions] Error: $_" -Level Error
            Show-Line "Error during check - LAPS read permissions could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-LAPSPermissions] Check completed"
    }
}
