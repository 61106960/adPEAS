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

            # Check if LAPS schema info is available
            $lapsLegacySchemaPresent = $false
            $windowsLAPSSchemaPresent = $false

            if ($Script:LAPSSchemaInfo) {
                $lapsLegacySchemaPresent = $Script:LAPSSchemaInfo.LegacyPresent
                $windowsLAPSSchemaPresent = $Script:LAPSSchemaInfo.NativePresent
            } else {
                # Detect schema ourselves using Invoke-LDAPSearch with Schema Partition
                $schemaDN = $Script:LDAPContext.SchemaNamingContext

                if ($schemaDN) {
                    try {
                        # Check for Legacy LAPS schema attribute using Invoke-LDAPSearch
                        $legacySchemaFilter = "(&(objectClass=attributeSchema)(|(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)(cn=ms-Mcs-AdmPwdExpirationTime)))"
                        $legacyResult = Invoke-LDAPSearch -Filter $legacySchemaFilter -SearchBase $schemaDN -Properties 'cn' -SizeLimit 1
                        if ($legacyResult) { $lapsLegacySchemaPresent = $true }

                        # Check for Windows LAPS Native schema attribute
                        $nativeSchemaFilter = "(&(objectClass=attributeSchema)(|(lDAPDisplayName=msLAPS-PasswordExpirationTime)(cn=msLAPS-PasswordExpirationTime)))"
                        $nativeResult = Invoke-LDAPSearch -Filter $nativeSchemaFilter -SearchBase $schemaDN -Properties 'cn' -SizeLimit 1
                        if ($nativeResult) { $windowsLAPSSchemaPresent = $true }
                    } catch {
                        Write-Log "[Get-LAPSPermissions] Schema query error: $($_.Exception.Message)"
                    }
                }

                # Fallback: check computer objects
                if (-not $lapsLegacySchemaPresent -and -not $windowsLAPSSchemaPresent) {
                    $legacyCheck = Get-DomainComputer -LDAPFilter "(ms-Mcs-AdmPwdExpirationTime=*)" -ResultLimit 1 @connectionParams
                    if ($legacyCheck) { $lapsLegacySchemaPresent = $true }

                    $nativeCheck = Get-DomainComputer -LDAPFilter "(msLAPS-PasswordExpirationTime=*)" -ResultLimit 1 @connectionParams
                    if ($nativeCheck) { $windowsLAPSSchemaPresent = $true }
                }

                # Cache schema info for other LAPS modules
                $Script:LAPSSchemaInfo = @{
                    LegacyPresent = $lapsLegacySchemaPresent
                    NativePresent = $windowsLAPSSchemaPresent
                }
            }

            if (-not $lapsLegacySchemaPresent -and -not $windowsLAPSSchemaPresent) {
                Show-Line "No LAPS schema found" -Class Note
                return
            }

            # Get all enabled computers and group by OU (only properties needed for filtering and grouping)
            # -Enabled filters server-side, Test-AccountActivity -IsActive uses $Script:DefaultInactiveDays
            $allComputers = @(Get-DomainComputer -Enabled -Properties "distinguishedName","lastLogonTimestamp" @connectionParams | Test-AccountActivity -IsActive)

            $computersByOU = @{}
            foreach ($computer in $allComputers) {
                $dn = $computer.distinguishedName
                if ($dn -match '^CN=[^,]+,(.+)$') {
                    $ouDN = $Matches[1]
                    if (-not $computersByOU.ContainsKey($ouDN)) {
                        $computersByOU[$ouDN] = 0
                    }
                    $computersByOU[$ouDN]++
                }
            }

            Write-Log "[Get-LAPSPermissions] Found $(@($computersByOU.Keys).Count) unique OUs with computers"

            # Analyze permissions for each OU
            $ouPermissionsResults = @()
            $filteredFindings = @()
            $allowedSeverities = if ($IncludePrivileged) { @('Critical', 'High', 'Medium', 'Info') } else { @('Critical', 'High', 'Medium') }

            $totalOUs = $computersByOU.Keys.Count
            $currentIndex = 0
            foreach ($ouDN in $computersByOU.Keys) {
                $currentIndex++
                if ($totalOUs -gt $Script:ProgressThreshold) { Show-Progress -Activity "Checking LAPS permissions" -Current $currentIndex -Total $totalOUs -ObjectName $ouDN }
                $computerCount = $computersByOU[$ouDN]
                Write-Log "[Get-LAPSPermissions] Analyzing OU: $ouDN ($computerCount computers)"

                try {
                    # Get-OUPermissions uses session context automatically
                    $ouPerms = Get-OUPermissions -DistinguishedName $ouDN -CheckType 'LAPS'

                    if ($ouPerms -and $ouPerms.Findings) {
                        $legacyReaders = @()
                        $nativeReaders = @()

                        foreach ($finding in $ouPerms.Findings) {
                            $principal = $finding.Principal
                            $sid = $finding.SID
                            $severity = $finding.Severity

                            # Match Legacy LAPS (ms-Mcs-AdmPwd)
                            if ($finding.Right -match 'ms-Mcs-AdmPwd') {
                                if ($sid -notin @($legacyReaders | ForEach-Object { $_.SID })) {
                                    $legacyReaders += [PSCustomObject]@{
                                        Principal = $principal
                                        SID = $sid
                                        Severity = $severity
                                    }
                                }
                            }
                            # Match Windows LAPS (msLAPS-*) - includes EncryptedPassword, EncryptedPasswordHistory, Password, etc.
                            # Also match "All Properties" which covers all LAPS types
                            elseif ($finding.Right -match 'msLAPS-' -or $finding.Right -match 'All Properties') {
                                if ($sid -notin @($nativeReaders | ForEach-Object { $_.SID })) {
                                    $nativeReaders += [PSCustomObject]@{
                                        Principal = $principal
                                        SID = $sid
                                        Severity = $severity
                                    }
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
                                MatchedReaders = $matchedReaders
                                LegacyReaders = $legacyReaders
                                NativeReaders = $nativeReaders
                            }
                        }

                        $ouPermissionsResults += [PSCustomObject]@{
                            OU = $ouDN
                            ComputerCount = $computerCount
                            LegacyReaders = $legacyReaders
                            NativeReaders = $nativeReaders
                        }
                    }
                } catch {
                    Write-Log "[Get-LAPSPermissions] Failed to query permissions for OU '$ouDN': $_"
                }
            }
            if ($totalOUs -gt $Script:ProgressThreshold) { Show-Progress -Activity "Checking LAPS permissions" -Completed }

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
                                IsExchangeService = $isExchange
                                IsPrivilegedAccount = $isPriv
                            }
                        }
                        # Only add OU if not already in the list (deduplicate)
                        $ouEntry = "$($finding.OU) ($($finding.ComputerCount) computers)"
                        if ($targetHash[$sid].OUs -notcontains $ouEntry) {
                            $targetHash[$sid].OUs += $ouEntry
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

                        if ($adObject) {
                            $adObject | Add-Member -NotePropertyName 'dangerousRights' -NotePropertyValue "LAPS Password Read" -Force
                            $adObject | Add-Member -NotePropertyName 'affectedOUs' -NotePropertyValue $readerInfo.OUs -Force
                            $adObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LAPSPermission' -Force
                            Show-Object $adObject
                        } else {
                            $resolvedName = if ($isWellKnownSID) { ConvertFrom-SID -SID $sid } else { $readerInfo.Principal }
                            $fallbackObject = [PSCustomObject]@{
                                sAMAccountName = $resolvedName
                                objectSid = $sid
                                dangerousRights = "LAPS Password Read"
                                affectedOUs = $readerInfo.OUs
                            }
                            $fallbackObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LAPSPermission' -Force
                            Show-Object $fallbackObject
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
                            $adObject | Add-Member -NotePropertyName 'dangerousRights' -NotePropertyValue "LAPS Password Read" -Force
                            $adObject | Add-Member -NotePropertyName 'affectedOUs' -NotePropertyValue $readerInfo.OUs -Force
                            $adObject | Add-Member -NotePropertyName 'dangerousRightsSeverity' -NotePropertyValue 'Hint' -Force
                            $adObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LAPSPermission' -Force
                            Show-Object $adObject
                        } else {
                            $resolvedName = if ($isWellKnownSID) { ConvertFrom-SID -SID $sid } else { $readerInfo.Principal }
                            $fallbackObject = [PSCustomObject]@{
                                sAMAccountName = $resolvedName
                                objectSid = $sid
                                dangerousRights = "LAPS Password Read"
                                affectedOUs = $readerInfo.OUs
                                dangerousRightsSeverity = 'Hint'
                            }
                            $fallbackObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LAPSPermission' -Force
                            Show-Object $fallbackObject
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
                            $adObject | Add-Member -NotePropertyName 'dangerousRights' -NotePropertyValue "LAPS Password Read" -Force
                            $adObject | Add-Member -NotePropertyName 'affectedOUs' -NotePropertyValue $readerInfo.OUs -Force
                            $adObject | Add-Member -NotePropertyName 'dangerousRightsSeverity' -NotePropertyValue 'Hint' -Force
                            $adObject | Add-Member -NotePropertyName '_isExchangeGroup' -NotePropertyValue $true -Force
                            $adObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LAPSPermission' -Force
                            Show-Object $adObject
                        } else {
                            $resolvedName = if ($isWellKnownSID) { ConvertFrom-SID -SID $sid } else { $readerInfo.Principal }
                            $fallbackObject = [PSCustomObject]@{
                                sAMAccountName = $resolvedName
                                objectSid = $sid
                                dangerousRights = "LAPS Password Read"
                                affectedOUs = $readerInfo.OUs
                                dangerousRightsSeverity = 'Hint'
                            }
                            $fallbackObject | Add-Member -NotePropertyName '_isExchangeGroup' -NotePropertyValue $true -Force
                            $fallbackObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LAPSPermission' -Force
                            Show-Object $fallbackObject
                        }
                    }
                }

                # If no non-Exchange findings were displayed (and Exchange is hidden without -IncludePrivileged)
                if ($allReaderSIDs.Keys.Count -eq 0 -and $privilegedReaderSIDs.Keys.Count -eq 0 -and (-not $IncludePrivileged -or $exchangeReaderSIDs.Keys.Count -eq 0)) {
                    Show-Line "No non-privileged accounts with LAPS read access found in $(@($computersByOU.Keys).Count) analyzed OU(s)" -Class Secure
                }

            } else {
                Show-Line "No non-privileged accounts with LAPS read access found in $(@($computersByOU.Keys).Count) analyzed OU(s)" -Class Secure
            }

        } catch {
            Write-Log "[Get-LAPSPermissions] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-LAPSPermissions] Check completed"
    }
}
