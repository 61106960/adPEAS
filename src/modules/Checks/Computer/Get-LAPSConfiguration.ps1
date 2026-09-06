# PasswordComplexity value -> human readable meaning
# Reference: https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings
$Script:LAPSPasswordComplexityMap = @{
    1 = 'Large letters'
    2 = 'Large + small letters'
    3 = 'Large + small letters + numbers'
    4 = 'Large + small letters + numbers + special'
    5 = 'Large + small letters + numbers + special (improved readability)'
    6 = 'Passphrase (long words)'
    7 = 'Passphrase (short words)'
    8 = 'Passphrase (short words with unique prefixes)'
}

<#
.SYNOPSIS
    Builds a display object for the LAPS settings of a single GPO.

.DESCRIPTION
    Converts the raw metadata hashtable produced by Get-LAPSGPOConfig into a rendered object
    for Show-Object. Raw registry values are decoded into human-readable strings so the
    finding triggers in adPEAS-FindingDefinitions.ps1 can colour them and attach tooltips.

    Only settings actually present in this GPO are added as attributes - an absent setting
    means the Windows LAPS default applies, which is not the same as it being set to 0/empty.

.PARAMETER GPOName
    Display name of the GPO.

.PARAMETER Metadata
    The per-GPO metadata hashtable from Get-LAPSGPOConfig (field name -> value, plus GPOGUID).

.PARAMETER Generation
    'Windows LAPS' or 'LAPS Legacy'.

.PARAMETER GPOLinkage
    Hashtable from Get-GPOLinkage (GPO GUID -> linked OUs), used to show where the GPO applies.

.OUTPUTS
    PSCustomObject tagged as ObjectType 'LAPSGPOConfig'.

.NOTES
    Internal helper function
#>
function New-LAPSGPOConfigObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$GPOName,

        [Parameter(Mandatory=$true)]
        [hashtable]$Metadata,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Windows LAPS', 'LAPS Legacy')]
        [string]$Generation,

        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [hashtable]$GPOLinkage
    )

    $isNative = ($Generation -eq 'Windows LAPS')
    $accountField = if ($isNative) { 'AdministratorAccountName' } else { 'AdminAccountName' }

    $obj = [PSCustomObject][ordered]@{
        GPOName     = $GPOName
        LAPSVersion = $Generation
    }

    # Managed account - absent means LAPS manages the built-in local Administrator (RID 500)
    $managedAccount = if ($Metadata.ContainsKey($accountField)) {
        [string]$Metadata[$accountField]
    } else {
        'Administrator (built-in, RID 500)'
    }
    $obj | Add-Member -NotePropertyName 'ManagedAccount' -NotePropertyValue $managedAccount -Force

    if ($isNative) {
        # BackupDirectory: 0=Disabled, 1=Microsoft Entra ID only, 2=Active Directory
        if ($Metadata.ContainsKey('BackupDirectory')) {
            $backupText = switch ([int]$Metadata['BackupDirectory']) {
                0       { 'Disabled - password is not escrowed anywhere' }
                1       { 'Microsoft Entra ID only - password is not escrowed to this Active Directory' }
                2       { 'Active Directory' }
                default { "Unknown ($($Metadata['BackupDirectory']))" }
            }
            $obj | Add-Member -NotePropertyName 'BackupDirectory' -NotePropertyValue $backupText -Force
        }

        # ADPasswordEncryptionEnabled=0 -> password lands in plaintext msLAPS-Password
        if ($Metadata.ContainsKey('ADPasswordEncryptionEnabled')) {
            $encText = if ([int]$Metadata['ADPasswordEncryptionEnabled'] -eq 0) {
                'Disabled - password is stored UNENCRYPTED in msLAPS-Password'
            } else {
                'Enabled'
            }
            $obj | Add-Member -NotePropertyName 'PasswordEncryption' -NotePropertyValue $encText -Force
        }

        if ($Metadata.ContainsKey('ADPasswordEncryptionPrincipal')) {
            $obj | Add-Member -NotePropertyName 'EncryptionPrincipal' -NotePropertyValue ([string]$Metadata['ADPasswordEncryptionPrincipal']) -Force
        }
    }

    if ($Metadata.ContainsKey('PasswordComplexity')) {
        $complexityValue = [int]$Metadata['PasswordComplexity']
        $complexityText = if ($Script:LAPSPasswordComplexityMap.ContainsKey($complexityValue)) {
            "$complexityValue ($($Script:LAPSPasswordComplexityMap[$complexityValue]))"
        } else {
            [string]$complexityValue
        }
        $obj | Add-Member -NotePropertyName 'PasswordComplexity' -NotePropertyValue $complexityText -Force
    }

    foreach ($numericField in @('PasswordLength', 'PassphraseLength', 'PasswordAgeDays')) {
        if ($Metadata.ContainsKey($numericField)) {
            $obj | Add-Member -NotePropertyName $numericField -NotePropertyValue $Metadata[$numericField] -Force
        }
    }

    # Domain controllers have no local SAM, so the built-in Administrator LAPS manages
    # everywhere else does not exist there. The DSRM account is the one thing LAPS can hold
    # on a DC, and only this setting turns it on.
    if ($isNative -and $Metadata.ContainsKey('BackupDsrmPassword')) {
        $dsrmText = if ([int]$Metadata['BackupDsrmPassword'] -eq 0) {
            'Disabled - the DSRM password on domain controllers is not managed'
        } else {
            'Enabled - the DSRM password on domain controllers is managed and escrowed'
        }
        $obj | Add-Member -NotePropertyName 'DsrmPasswordBackup' -NotePropertyValue $dsrmText -Force
    }

    if ($isNative -and $Metadata.ContainsKey('PasswordExpirationProtectionEnabled')) {
        $expText = if ([int]$Metadata['PasswordExpirationProtectionEnabled'] -eq 0) {
            'Disabled - password max-age is not enforced'
        } else {
            'Enabled'
        }
        $obj | Add-Member -NotePropertyName 'ExpirationProtection' -NotePropertyValue $expText -Force
    }

    # GPO links - without these it is not visible where the settings actually apply.
    # An unlinked GPO is reported explicitly rather than by an absent row: LAPS settings in a
    # GPO that is linked nowhere apply to nothing, which is easy to miss otherwise. A failed
    # linkage lookup must not be reported as "not linked".
    $gpoGuid = if ($Metadata.ContainsKey('GPOGUID')) { $Metadata['GPOGUID'] } else { $null }
    $linkedOUs = @()
    if ($gpoGuid -and $GPOLinkage -and $GPOLinkage.ContainsKey($gpoGuid)) {
        $linkedOUs = @($GPOLinkage[$gpoGuid])
    }

    if ($linkedOUs.Count -gt 0) {
        $obj | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $linkedOUs -Force
    } elseif ($null -eq $GPOLinkage) {
        $obj | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue 'Unknown - GPO linkage could not be resolved' -Force
    } else {
        $obj | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue 'Not linked - these settings apply nowhere' -Force
    }
    $obj | Add-Member -NotePropertyName 'LinkedOUCount' -NotePropertyValue $linkedOUs.Count -Force

    if ($gpoGuid) {
        $obj | Add-Member -NotePropertyName 'GPOGUID' -NotePropertyValue $gpoGuid -Force
    }

    $obj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LAPSGPOConfig' -Force

    return $obj
}

<#
.SYNOPSIS
    Builds the display objects for all GPOs that deploy LAPS settings.

.DESCRIPTION
    Resolves GPO linkage once and converts the Legacy and Native metadata tables from
    Get-LAPSGPOConfig into rendered objects. A GPO configuring both LAPS generations yields
    one object per generation, because the two are administered independently and Windows
    LAPS ignores the legacy policy root when its own root has any setting.

.PARAMETER LAPSGPOSettings
    The hashtable returned by Get-LAPSGPOConfig (keys 'Legacy' and 'Native').

.OUTPUTS
    Array of PSCustomObject tagged as ObjectType 'LAPSGPOConfig', Windows LAPS first.

.NOTES
    Internal helper function
#>
function Get-LAPSGPOConfigObjects {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$LAPSGPOSettings
    )

    $gpoLinkage = $null
    try {
        $gpoLinkage = Get-GPOLinkage
    } catch {
        Write-Log "[Get-LAPSGPOConfigObjects] Failed to resolve GPO linkage: $_"
    }

    $objects = @()

    if ($LAPSGPOSettings.Native) {
        foreach ($gpoName in ($LAPSGPOSettings.Native.Keys | Sort-Object)) {
            $objects += New-LAPSGPOConfigObject -GPOName $gpoName -Metadata $LAPSGPOSettings.Native[$gpoName] `
                -Generation 'Windows LAPS' -GPOLinkage $gpoLinkage
        }
    }

    if ($LAPSGPOSettings.Legacy) {
        foreach ($gpoName in ($LAPSGPOSettings.Legacy.Keys | Sort-Object)) {
            $objects += New-LAPSGPOConfigObject -GPOName $gpoName -Metadata $LAPSGPOSettings.Legacy[$gpoName] `
                -Generation 'LAPS Legacy' -GPOLinkage $gpoLinkage
        }
    }

    return $objects
}

<#
.SYNOPSIS
    Joins computer names for one OU row, capped.

.DESCRIPTION
    The unprotected computers are listed per OU as one string. Unbounded, a flat domain
    with thirty thousand machines in one OU puts all thirty thousand names into a single
    field, which the console wraps for pages and the HTML report carries in full - and the
    reader learns nothing from name twelve thousand that name twelve did not already say.

    The count beside it stays exact, so the number to act on is never the truncated one.

.PARAMETER Name
    The computer names, already stripped of the trailing dollar sign.

.PARAMETER Limit
    How many to name before summarising the rest.

.OUTPUTS
    String.

.NOTES
    Internal helper function
#>
function Format-LAPSComputerList {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Name,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1, 10000)]
        [int]$Limit = 50
    )

    $names = @($Name | Where-Object { $_ })
    if ($names.Count -le $Limit) { return ($names -join ', ') }

    $shown = $names[0..($Limit - 1)] -join ', '
    return ($shown + ', ... and ' + ($names.Count - $Limit) + ' more')
}

function Get-LAPSConfiguration {
    <#
    .SYNOPSIS
    Analyzes Local Administrator Password Solution (LAPS) deployment and coverage.

    .DESCRIPTION
    Analyzes LAPS deployment status focusing on:
    - Schema detection (Legacy LAPS vs. Windows LAPS Native)
    - GPO configuration analysis (managed account name, password policy, backup/encryption settings)
    - Deployment coverage (% of computers with LAPS)
    - Computers without LAPS protection grouped by OU
    - Computers whose LAPS password stopped rotating: the attribute exists, so coverage
      counts them as protected, but the expiration time lies in the past and the local
      administrator password is as old as the day rotation stopped

    Domain controllers are not part of the coverage question. A DC has no local SAM, so the
    built-in Administrator LAPS manages everywhere else does not exist there; Legacy LAPS
    never touched one, and Windows LAPS reaches one only through the DSRM account, and only
    when BackupDsrmPassword is on. They are counted and reported separately, including
    whether a GPO configures that setting.

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

            # One definition of "does this domain run LAPS", shared with
            # Get-LAPSCredentialAccess and Get-LAPSPermissions and cached for the session.
            $lapsSchema = Get-LAPSSchemaPresence @PSBoundParameters
            $lapsLegacySchemaPresent = $lapsSchema.LegacyPresent
            $windowsLAPSSchemaPresent = $lapsSchema.NativePresent

            Write-Log "[Get-LAPSConfiguration] Detection result: Legacy=$lapsLegacySchemaPresent, Native=$windowsLAPSSchemaPresent"

            # ===== GPO Configuration (LAPS managed account name) =====
            # Fetched here (before the schema branch) because a GPO can configure the LAPS
            # AdminAccountName/AdministratorAccountName setting even when the schema was never
            # extended - that is itself a critical misconfiguration (LAPS "deployed" via GPO but
            # completely non-functional) and needs the same GPO/SYSVOL scan either way.
            $lapsGPOSettings = $null
            try {
                $lapsGPOSettings = Get-LAPSGPOConfig
            } catch {
                Write-Log "[Get-LAPSConfiguration] Failed to query LAPS GPO settings: $_"
            }
            $lapsGPOHasLegacy = $lapsGPOSettings -is [hashtable] -and $lapsGPOSettings.Legacy -and $lapsGPOSettings.Legacy.Count -gt 0
            $lapsGPOHasNative = $lapsGPOSettings -is [hashtable] -and $lapsGPOSettings.Native -and $lapsGPOSettings.Native.Count -gt 0

            # ===== Domain Controllers are not part of the coverage question =====
            #
            # A domain controller has no local SAM, so the built-in Administrator account
            # LAPS manages on every other machine does not exist there. Legacy LAPS never
            # touched a DC at all, and Windows LAPS reaches one only through the DSRM
            # account, and only when BackupDsrmPassword is turned on. Counting DCs in the
            # denominator meant every single domain reported its domain controllers as
            # unprotected and put OU=Domain Controllers in the list of exposed OUs - a
            # finding no domain could ever clear.
            #
            # They are taken out of the coverage numbers and reported on their own terms
            # below. A failed lookup leaves the set empty, which puts the DCs back into the
            # coverage numbers - the old behaviour, and better than dropping real machines
            # because one query did not answer.
            $domainControllerDNs = @{}
            $domainControllerCount = 0
            $domainControllerLookupFailed = $false
            try {
                foreach ($dc in @(Get-DomainComputer -DomainController -Properties 'distinguishedName' @PSBoundParameters)) {
                    if (-not $dc.distinguishedName) { continue }
                    $domainControllerDNs["$($dc.distinguishedName)".ToLowerInvariant()] = $true
                }
                $domainControllerCount = $domainControllerDNs.Count
            } catch {
                $domainControllerLookupFailed = $true
                Write-Log "[Get-LAPSConfiguration] Could not enumerate Domain Controllers: $_" -Level Error
            }

            # ===== No LAPS Schema Found =====
            if (-not $lapsLegacySchemaPresent -and -not $windowsLAPSSchemaPresent) {
                if ($lapsGPOHasLegacy -or $lapsGPOHasNative) {
                    Show-Line "LAPS GPO settings found, but the LAPS schema is NOT present in AD - LAPS is configured but completely non-functional!" -Class "Finding"

                    foreach ($gpoConfigObject in @(Get-LAPSGPOConfigObjects -LAPSGPOSettings $lapsGPOSettings)) {
                        Show-Object $gpoConfigObject
                    }
                } else {
                    Show-Line "No LAPS schema found - LAPS is not deployed" -Class "Finding"
                }

                # Get active computers grouped by OU (uses $Script:DefaultInactiveDays)
                $allComputers = @(Get-DomainComputer -Enabled -Properties $ComputerProperties @PSBoundParameters |
                    Test-AccountActivity -IsActive |
                    Where-Object { -not $domainControllerDNs.ContainsKey("$($_.distinguishedName)".ToLowerInvariant()) })

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
                        lapsUnprotectedComputers = (Format-LAPSComputerList -Name $ouEntry.Value)
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

            # ===== Step 2: GPO Configuration (LAPS managed account name + policy metadata) =====
            # $lapsGPOSettings was already fetched above (before the schema branch). Shown before
            # the coverage numbers because it explains WHY coverage looks the way it does (account
            # name, encryption, backup target) rather than as an afterthought once the reader
            # already has a coverage percentage in mind.
            if ($lapsGPOSettings -is [hashtable]) {
                if ($lapsGPOHasLegacy -or $lapsGPOHasNative) {
                    Show-SubHeader "Analyzing LAPS configuration deployed via GPO..." -ObjectType "LAPSGPOConfig"

                    $gpoConfigObjects = @(Get-LAPSGPOConfigObjects -LAPSGPOSettings $lapsGPOSettings)

                    Show-Line "Found $($gpoConfigObjects.Count) GPO(s) deploying LAPS settings" -Class "Hint"

                    foreach ($gpoConfigObject in $gpoConfigObjects) {
                        Show-Object $gpoConfigObject
                    }
                } else {
                    if ((Test-SysvolAccessible) -eq $false) {
                        Show-Line "Skipped - SYSVOL not accessible" -Class Hint
                    } else {
                        Show-Line "No LAPS-related GPO settings found in SYSVOL - LAPS may be managed via Intune/CSP or local policy instead of GPO" -Class "Hint"
                    }
                }
            }

            # ===== Step 3: Enumerate Computers and Calculate Coverage =====
            Show-SubHeader "Analyzing LAPS deployment coverage..." -ObjectType "LAPSConfiguration"

            # Query 1: All enabled computers (for statistics), domain controllers removed
            $allEnabledComputers = @(Get-DomainComputer -Enabled -Properties $ComputerProperties @PSBoundParameters |
                Where-Object { -not $domainControllerDNs.ContainsKey("$($_.distinguishedName)".ToLowerInvariant()) })

            # Query 2: Active computers (enabled + recent logon) - uses $Script:DefaultInactiveDays
            $activeComputers = @($allEnabledComputers | Test-AccountActivity -IsActive)

            # Query 3: Computers WITH LAPS (LDAP-side filter) - much faster than client-side attribute check
            $computersWithLAPSRaw = @(Get-DomainComputer -Enabled -LAPS -Properties $ComputerProperties @PSBoundParameters |
                Where-Object { -not $domainControllerDNs.ContainsKey("$($_.distinguishedName)".ToLowerInvariant()) })
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

            # The domain controllers, on their own terms rather than as unprotected machines
            if ($domainControllerLookupFailed) {
                Show-Line "Domain Controllers could not be enumerated - they are counted as ordinary computers below, which will understate LAPS coverage" -Class "Note"
            } elseif ($domainControllerCount -gt 0) {
                $dsrmConfigured = $false
                if ($lapsGPOSettings -is [hashtable] -and $lapsGPOSettings.Native) {
                    foreach ($nativeGpo in $lapsGPOSettings.Native.Values) {
                        if ($nativeGpo -is [hashtable] -and $nativeGpo.ContainsKey('BackupDsrmPassword') -and
                            ([int]$nativeGpo['BackupDsrmPassword']) -ne 0) {
                            $dsrmConfigured = $true
                            break
                        }
                    }
                }

                if ($dsrmConfigured) {
                    Show-Line "$domainControllerCount Domain Controller(s) excluded from the coverage figures - a DC has no local Administrator to manage, and a GPO does configure DSRM password backup for them" -Class "Note"
                } else {
                    Show-Line "$domainControllerCount Domain Controller(s) excluded from the coverage figures - a DC has no local Administrator to manage, and no GPO configures DSRM password backup (BackupDsrmPassword) for them" -Class "Hint"
                }
            }

            # Build LAPS breakdown
            if ($withAnyLAPS -gt 0) {
                $lapsBreakdown = @()
                if ($withLegacyLAPS -gt 0) { $lapsBreakdown += "$withLegacyLAPS Legacy" }
                if ($withWindowsLAPS -gt 0) { $lapsBreakdown += "$withWindowsLAPS Native" }
                if ($withBothLAPS -gt 0) { $lapsBreakdown += "$withBothLAPS both" }
                $breakdownText = if ($lapsBreakdown.Count -gt 0) { " (" + ($lapsBreakdown -join ", ") + ")" } else { "" }
                Show-Line "$withAnyLAPS computers ($lapsCoverage%) with LAPS protection$breakdownText" -Class "Note"
            }

            # ===== LAPS passwords that never rotated =====
            #
            # Coverage counts a machine as protected the moment the expiration attribute
            # exists. It says nothing about whether the password behind it was ever changed.
            # An expiration time in the past means the client did not rotate when it was due:
            # the CSE is broken, the policy was removed, or the machine has been off. The
            # password is as old as it was on the day it stopped rotating, and if it leaked
            # once it is still valid - which is exactly what LAPS exists to prevent.
            #
            # The grace period covers the ordinary case of a machine that was simply off for
            # a while; past that, nothing is rotating.
            $staleGraceDays = 30
            $staleCutoff = (Get-Date).AddDays(-$staleGraceDays)
            $staleLAPSComputers = @()

            foreach ($computer in $computersWithLAPS) {
                # Whichever generation last wrote wins: a machine migrated from Legacy to
                # Windows LAPS keeps the old attribute, and judging by the older of the two
                # would report every migrated machine as stale.
                $expiry = $null
                $generation = $null
                foreach ($attr in @('ms-Mcs-AdmPwdExpirationTime', 'msLAPS-PasswordExpirationTime')) {
                    $value = $computer.$attr
                    if ($value -isnot [DateTime]) { continue }
                    if ($null -eq $expiry -or $value -gt $expiry) {
                        $expiry = $value
                        $generation = if ($attr -eq 'ms-Mcs-AdmPwdExpirationTime') { 'LAPS Legacy' } else { 'Windows LAPS' }
                    }
                }

                if ($null -eq $expiry -or $expiry -ge $staleCutoff) { continue }

                $daysOverdue = [math]::Floor(((Get-Date) - $expiry).TotalDays)
                $staleObject = [PSCustomObject]@{
                    Name              = ($computer.sAMAccountName -replace '\$$', '')
                    distinguishedName = $computer.distinguishedName
                    lapsGeneration    = $generation
                    passwordExpiredOn = (Format-adPEASDate $expiry 'yyyy-MM-dd')
                    daysOverdue       = $daysOverdue
                    lapsPasswordStale = "The LAPS password was due for rotation $daysOverdue days ago and has not been changed since. The local administrator password on this machine is at least that old."
                }
                $staleObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LAPSStalePassword' -Force
                $staleLAPSComputers += $staleObject
            }

            if ($staleLAPSComputers.Count -gt 0) {
                Show-Line "$($staleLAPSComputers.Count) computer(s) have LAPS but their password stopped rotating - counted as protected above, and they are not" -Class "Finding"
                foreach ($staleObject in ($staleLAPSComputers | Sort-Object daysOverdue -Descending)) {
                    Show-Object $staleObject
                }
            } elseif ($withAnyLAPS -gt 0) {
                Show-Line "Every computer with LAPS rotated its password on schedule" -Class "Secure"
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
                        lapsUnprotectedComputers = (Format-LAPSComputerList -Name $ouEntry.Value)
                    }
                    $lapsFinding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LAPSConfiguration' -Force
                    Show-Object $lapsFinding
                }
            } else {
                Show-Line "All computers (100%) have LAPS protection" -Class "Secure"
            }

        } catch {
            Write-Log "[Get-LAPSConfiguration] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-LAPSConfiguration] Check completed"
    }
}

