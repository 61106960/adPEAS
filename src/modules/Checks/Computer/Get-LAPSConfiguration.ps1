function Get-LAPSConfiguration {
    <#
    .SYNOPSIS
    Analyzes Local Administrator Password Solution (LAPS) deployment and coverage.

    .DESCRIPTION
    Analyzes LAPS deployment status focusing on:
    - Schema detection (Legacy LAPS vs. Windows LAPS Native)
    - Deployment coverage (% of computers with LAPS)
    - Computers without LAPS protection grouped by OU
    - GPO configuration analysis (AdminAccountName)

    LAPS Versions Supported:
    - Legacy LAPS: Original Microsoft LAPS (ms-Mcs-* attributes)
    - Windows LAPS Native: Built-in since Server 2022/Win11 (msLAPS-* attributes)

    Related Checks:
    - Get-LAPSCredentialAccess (Creds): Can YOUR account read LAPS passwords?
    - Get-LAPSPermissions (Rights): WHO has LAPS read rights per OU?

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-LAPSConfiguration

    .EXAMPLE
    Get-LAPSConfiguration -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Computer
    Author: Alexander Sturz (@_61106960_)
    Reference:
    - LAPS Legacy: https://www.microsoft.com/en-us/download/details.aspx?id=46899
    - Windows LAPS: https://learn.microsoft.com/en-us/windows-server/identity/laps/
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    begin {
        Write-Log "[Get-LAPSConfiguration] Starting check"

        # Properties needed for internal calculations only
        $ComputerProperties = @(
            'distinguishedName',
            'sAMAccountName',
            'lastLogonTimestamp',
            'ms-Mcs-AdmPwdExpirationTime',
            'msLAPS-PasswordExpirationTime'
        )
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            # ===== Step 1: Schema Detection =====
            Show-SubHeader "Checking for LAPS schema attributes..." -ObjectType "LAPSConfiguration"

            $lapsLegacySchemaPresent = $false
            $windowsLAPSSchemaPresent = $false

            $ldapServer = $Script:LDAPContext.Server
            $schemaDN = $Script:LDAPContext.SchemaNamingContext

            Write-Log "[Get-LAPSConfiguration] Server: $ldapServer, Schema DN: $schemaDN"

            # Method 1: Schema query using Invoke-LDAPSearch with Schema Partition
            if ($schemaDN) {
                try {
                    # Test Legacy LAPS schema attribute
                    $legacySchemaFilter = "(&(objectClass=attributeSchema)(|(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)(cn=ms-Mcs-AdmPwdExpirationTime)))"
                    $legacyResult = Invoke-LDAPSearch -Filter $legacySchemaFilter -SearchBase $schemaDN -Properties 'cn' -SizeLimit 1
                    if ($legacyResult) {
                        $lapsLegacySchemaPresent = $true
                        Write-Log "[Get-LAPSConfiguration] LAPS Legacy schema attribute found"
                    }

                    # Test Windows LAPS Native schema attribute
                    $nativeSchemaFilter = "(&(objectClass=attributeSchema)(|(lDAPDisplayName=msLAPS-PasswordExpirationTime)(cn=msLAPS-PasswordExpirationTime)))"
                    $nativeResult = Invoke-LDAPSearch -Filter $nativeSchemaFilter -SearchBase $schemaDN -Properties 'cn' -SizeLimit 1
                    if ($nativeResult) {
                        $windowsLAPSSchemaPresent = $true
                        Write-Log "[Get-LAPSConfiguration] Windows LAPS Native schema attribute found"
                    }
                } catch {
                    Write-Log "[Get-LAPSConfiguration] Schema query error: $($_.Exception.Message)"
                }
            }

            # Method 2: Fallback - check if any computer has LAPS attributes (minimal query)
            if (-not $lapsLegacySchemaPresent -and -not $windowsLAPSSchemaPresent) {
                Write-Log "[Get-LAPSConfiguration] Schema query returned no results, checking computer objects"

                # Only fetch distinguishedName - we just need to know if any object exists
                $legacyCheck = Get-DomainComputer -LDAPFilter "(ms-Mcs-AdmPwdExpirationTime=*)" -Properties 'distinguishedName' -ResultLimit 1 @PSBoundParameters
                if ($legacyCheck) {
                    $lapsLegacySchemaPresent = $true
                    Write-Log "[Get-LAPSConfiguration] LAPS Legacy detected via computer attribute"
                }

                $nativeCheck = Get-DomainComputer -LDAPFilter "(msLAPS-PasswordExpirationTime=*)" -Properties 'distinguishedName' -ResultLimit 1 @PSBoundParameters
                if ($nativeCheck) {
                    $windowsLAPSSchemaPresent = $true
                    Write-Log "[Get-LAPSConfiguration] Windows LAPS Native detected via computer attribute"
                }
            }

            # Store schema info for other LAPS modules
            $Script:LAPSSchemaInfo = @{
                LegacyPresent = $lapsLegacySchemaPresent
                NativePresent = $windowsLAPSSchemaPresent
            }

            Write-Log "[Get-LAPSConfiguration] Detection result: Legacy=$lapsLegacySchemaPresent, Native=$windowsLAPSSchemaPresent"

            # ===== No LAPS Schema Found =====
            if (-not $lapsLegacySchemaPresent -and -not $windowsLAPSSchemaPresent) {
                Show-Line "No LAPS schema found - LAPS is not deployed" -Class "Finding"

                # Get active computers grouped by OU (uses $Script:DefaultInactiveDays)
                $allComputers = @(Get-DomainComputer -Enabled -Properties $ComputerProperties @PSBoundParameters | Test-AccountActivity -IsActive)

                # Group by OU - store computer names
                $computersByOU = @{}
                foreach ($computer in $allComputers) {
                    $dn = $computer.distinguishedName
                    if ($dn -match '^CN=[^,]+,(.+)$') {
                        $ouDN = $Matches[1]
                        if (-not $computersByOU.ContainsKey($ouDN)) {
                            $computersByOU[$ouDN] = @()
                        }
                        $computerName = $computer.sAMAccountName -replace '\$$', ''
                        $computersByOU[$ouDN] += $computerName
                    }
                }

                Show-Line "$($allComputers.Count) computers (100%) without LAPS protection" -Class "Finding"

                # Output each OU as structured object for proper tooltip support
                foreach ($ouEntry in ($computersByOU.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending)) {
                    $lapsFinding = [PSCustomObject]@{
                        ouName = $ouEntry.Key
                        computerCount = $ouEntry.Value.Count
                        lapsUnprotectedComputers = ($ouEntry.Value -join ", ")
                    }
                    $lapsFinding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LAPSConfiguration' -Force
                    Show-Object $lapsFinding
                }
                return
            }

            # Report schema versions - schema presence is a positive indicator (Note = green)
            if ($lapsLegacySchemaPresent -and $windowsLAPSSchemaPresent) {
                Show-Line "Both LAPS Legacy and Windows LAPS Native schemas present" -Class "Note"
            } elseif ($lapsLegacySchemaPresent) {
                Show-Line "LAPS Legacy schema present" -Class "Note"
            } elseif ($windowsLAPSSchemaPresent) {
                Show-Line "Windows LAPS Native schema present" -Class "Note"
            }

            # ===== Step 2: Enumerate Computers and Calculate Coverage =====
            Show-SubHeader "Analyzing LAPS deployment coverage..." -ObjectType "LAPSConfiguration"

            # Query 1: All enabled computers (for statistics)
            $allEnabledComputers = @(Get-DomainComputer -Enabled -Properties $ComputerProperties @PSBoundParameters)

            # Query 2: Active computers (enabled + recent logon) - uses $Script:DefaultInactiveDays
            $activeComputers = @($allEnabledComputers | Test-AccountActivity -IsActive)

            # Query 3: Computers WITH LAPS (LDAP-side filter) - much faster than client-side attribute check
            $computersWithLAPSRaw = @(Get-DomainComputer -Enabled -LAPS -Properties $ComputerProperties @PSBoundParameters)
            $computersWithLAPS = @($computersWithLAPSRaw | Test-AccountActivity -IsActive)

            # Categorize LAPS computers by type
            $computersWithLegacyLAPS = @()
            $computersWithWindowsLAPS = @()
            $computersWithBothLAPS = @()

            foreach ($computer in $computersWithLAPS) {
                $hasLegacyLAPS = $null -ne $computer.'ms-Mcs-AdmPwdExpirationTime'
                $hasWindowsLAPS = $null -ne $computer.'msLAPS-PasswordExpirationTime'

                if ($hasLegacyLAPS -and $hasWindowsLAPS) {
                    $computersWithBothLAPS += $computer
                } elseif ($hasLegacyLAPS) {
                    $computersWithLegacyLAPS += $computer
                } else {
                    $computersWithWindowsLAPS += $computer
                }
            }

            # Computers without LAPS = active computers minus those with LAPS
            $lapsComputerDNs = @{}
            foreach ($c in $computersWithLAPS) {
                $lapsComputerDNs[$c.distinguishedName] = $true
            }
            $computersWithoutLAPS = @($activeComputers | Where-Object { -not $lapsComputerDNs.ContainsKey($_.distinguishedName) })

            # Calculate statistics
            $activeCount = $activeComputers.Count
            $inactiveCount = $allEnabledComputers.Count - $activeCount

            $withLegacyLAPS = $computersWithLegacyLAPS.Count
            $withWindowsLAPS = $computersWithWindowsLAPS.Count
            $withBothLAPS = $computersWithBothLAPS.Count
            $withoutLAPS = $computersWithoutLAPS.Count

            $withAnyLAPS = $withLegacyLAPS + $withWindowsLAPS + $withBothLAPS
            $lapsCoverage = if ($activeCount -gt 0) { [math]::Round(($withAnyLAPS / $activeCount) * 100, 1) } else { 0 }
            $withoutLAPSPercent = if ($activeCount -gt 0) { [math]::Round(($withoutLAPS / $activeCount) * 100, 1) } else { 0 }

            # Output statistics - compact summary lines
            $inactiveInfo = if ($inactiveCount -gt 0) { " ($inactiveCount inactive excluded)" } else { "" }
            Show-Line "Found $activeCount active computers$inactiveInfo" -Class "Hint"

            # Build LAPS breakdown
            if ($withAnyLAPS -gt 0) {
                $lapsBreakdown = @()
                if ($withLegacyLAPS -gt 0) { $lapsBreakdown += "$withLegacyLAPS Legacy" }
                if ($withWindowsLAPS -gt 0) { $lapsBreakdown += "$withWindowsLAPS Native" }
                if ($withBothLAPS -gt 0) { $lapsBreakdown += "$withBothLAPS both" }
                $breakdownText = if ($lapsBreakdown.Count -gt 0) { " (" + ($lapsBreakdown -join ", ") + ")" } else { "" }
                Show-Line "$withAnyLAPS computers ($lapsCoverage%) with LAPS protection$breakdownText" -Class "Note"
            }

            # Highlight computers without LAPS
            if ($withoutLAPS -gt 0) {
                Show-Line "$withoutLAPS computers ($withoutLAPSPercent%) without LAPS protection" -Class "Finding"

                # Group by OU - store computer names instead of count
                $computersWithoutLAPSByOU = @{}
                $totalComputers = @($computersWithoutLAPS).Count
                $currentIndex = 0
                foreach ($computer in $computersWithoutLAPS) {
                    $currentIndex++
                    if ($totalComputers -gt $Script:ProgressThreshold) { Show-Progress -Activity "Checking LAPS configuration" -Current $currentIndex -Total $totalComputers -ObjectName $computer.name }
                    $dn = $computer.distinguishedName
                    if ($dn -match '^CN=[^,]+,(.+)$') {
                        $ouDN = $Matches[1]
                        if (-not $computersWithoutLAPSByOU.ContainsKey($ouDN)) {
                            $computersWithoutLAPSByOU[$ouDN] = @()
                        }
                        # Use sAMAccountName for computer name
                        $computerName = $computer.sAMAccountName -replace '\$$', ''
                        $computersWithoutLAPSByOU[$ouDN] += $computerName
                    }
                }
                if ($totalComputers -gt $Script:ProgressThreshold) { Show-Progress -Activity "Checking LAPS configuration" -Completed }

                # Output each OU as structured object for proper tooltip support
                foreach ($ouEntry in ($computersWithoutLAPSByOU.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending)) {
                    $lapsFinding = [PSCustomObject]@{
                        ouName = $ouEntry.Key
                        computerCount = $ouEntry.Value.Count
                        lapsUnprotectedComputers = ($ouEntry.Value -join ", ")
                    }
                    $lapsFinding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LAPSConfiguration' -Force
                    Show-Object $lapsFinding
                }
            } else {
                Show-Line "All computers (100%) have LAPS protection" -Class "Secure"
            }

            # ===== Step 3: GPO Configuration (Legacy LAPS AdminAccountName) =====
            if ($lapsLegacySchemaPresent) {
                Write-Log "[Get-LAPSConfiguration] Querying GPOs for LAPS AdminAccountName"
                try {
                    $lapsGPOSettings = Get-LAPSGPOConfig

                    if ($lapsGPOSettings -is [hashtable] -and $lapsGPOSettings.Count -gt 0) {
                        $uniqueAccounts = @($lapsGPOSettings.Values | Select-Object -Unique)

                        if ($uniqueAccounts.Count -eq 1) {
                            $lapsAdminAccount = $uniqueAccounts[0]
                            Show-Line "LAPS Legacy GPO AdminAccountName: '$lapsAdminAccount'" -Class "Hint"
                        } elseif ($uniqueAccounts.Count -gt 1) {
                            $accountList = ($uniqueAccounts | Sort-Object) -join "', '"
                            Show-Line "LAPS Legacy GPO: Multiple AdminAccountNames: '$accountList' (varies by OU)" -Class "Hint"
                        }
                    } elseif ((Test-SysvolAccessible) -eq $false) {
                        Show-Line "Skipped - SYSVOL not accessible" -Class Hint
                    }
                } catch {
                    Write-Log "[Get-LAPSConfiguration] Failed to query LAPS GPO settings: $_"
                }
            }

        } catch {
            Write-Log "[Get-LAPSConfiguration] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-LAPSConfiguration] Check completed"
    }
}

