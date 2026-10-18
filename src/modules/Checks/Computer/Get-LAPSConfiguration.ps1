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
        [hashtable]$GPOLinkage,

        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [hashtable]$GPOStatusMap
    )

    $isNative = ($Generation -eq 'Windows LAPS')
    $accountField = if ($isNative) { 'AdministratorAccountName' } else { 'AdminAccountName' }

    # Read before the object is built so both can take a fixed position next to the name.
    # The GUID is the GPO's folder under SYSVOL and the only reliable way to find the
    # policy again - display names are neither unique nor a path.
    $gpoGuid = if ($Metadata.ContainsKey('GPOGUID')) { $Metadata['GPOGUID'] } else { $null }
    $gpoPath = if ($Metadata.ContainsKey('GPOPath')) { $Metadata['GPOPath'] } else { $null }
    $sourceFile = if ($Metadata.ContainsKey('SourceFile')) { $Metadata['SourceFile'] } else { $null }

    $obj = [PSCustomObject][ordered]@{
        GPOName     = $GPOName
        GPOGUID     = $gpoGuid
        GPOPath     = $gpoPath
        SourceFile  = $sourceFile
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

    # Windows LAPS calls it PasswordExpirationProtectionEnabled, Legacy LAPS
    # PwdExpirationProtectionEnabled. Same setting, same consequence, and the row was
    # gated on the native generation - so a legacy policy that turns it off said nothing.
    $expirationField = if ($isNative) { 'PasswordExpirationProtectionEnabled' } else { 'PwdExpirationProtectionEnabled' }
    if ($Metadata.ContainsKey($expirationField)) {
        $expText = if ([int]$Metadata[$expirationField] -eq 0) {
            'Disabled - password max-age is not enforced'
        } else {
            'Enabled'
        }
        $obj | Add-Member -NotePropertyName 'ExpirationProtection' -NotePropertyValue $expText -Force
    }

    # The central switch of Legacy LAPS. 0 is LAPS switched off by policy while the schema
    # and the computer attributes stay in place - every password the clients last wrote
    # remains in the directory and stops rotating, and nothing else in the report says so.
    if (-not $isNative -and $Metadata.ContainsKey('AdmPwdEnabled')) {
        $stateText = if ([int]$Metadata['AdmPwdEnabled'] -eq 0) {
            'Disabled - LAPS is switched off by this policy, and passwords already stored stop rotating'
        } else {
            'Enabled'
        }
        $obj | Add-Member -NotePropertyName 'lapsPolicyState' -NotePropertyValue $stateText -Force
    }

    # Windows LAPS can reset the password after the session that used it: 0 none,
    # 1 reset, 3 reset and log the account off, 5 reset and reboot. With 0 a password
    # that was used once stays valid until the rotation interval runs out.
    if ($isNative -and $Metadata.ContainsKey('PostAuthenticationActions')) {
        $postAuthText = switch ([int]$Metadata['PostAuthenticationActions']) {
            0       { 'Disabled - the password is not reset after the session that used it' }
            1       { 'Reset the password' }
            3       { 'Reset the password and log off the managed account' }
            5       { 'Reset the password and reboot' }
            default { "Unknown ($($Metadata['PostAuthenticationActions']))" }
        }
        $obj | Add-Member -NotePropertyName 'PostAuthActions' -NotePropertyValue $postAuthText -Force
    }

    # GPO links - without these it is not visible where the settings actually apply.
    # An unlinked GPO is reported explicitly rather than by an absent row: LAPS settings in a
    # GPO that is linked nowhere apply to nothing, which is easy to miss otherwise. A failed
    # linkage lookup must not be reported as "not linked".
    $linkedOUs = @()
    if ($gpoGuid -and $GPOLinkage -and $GPOLinkage.ContainsKey($gpoGuid)) {
        $linkedOUs = @($GPOLinkage[$gpoGuid])
    }

    # A resolved-to-none linkage goes in as the empty array, which the LinkedOUs transformer
    # renders as "Not linked". Only the unresolved case needs a string of its own.
    if ($linkedOUs.Count -eq 0 -and $null -eq $GPOLinkage) {
        $obj | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue 'Unknown - linkage could not be resolved' -Force
    } else {
        $obj | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $linkedOUs -Force

        # The statement, on an attribute of this check's own, for the case where the
        # lookup succeeded and found nothing. LAPS_GPO_NOT_LINKED hangs off it.
        #
        # It cannot hang off LinkedOUs: twelve check modules write that attribute, and a
        # card reading "The LAPS settings in this GPO apply to no computer at all" would
        # attach itself to printer driver policies and SMB signing policies too - which is
        # why both LinkedOUs triggers are SeverityOnly, and why the card was unreachable.
        #
        # Guarded on the lookup having worked. A failed one is the other branch above, and
        # inferring "applies nowhere" from a query that did not answer is the mistake this
        # whole distinction exists to avoid - its remediation ("link the GPO or delete it")
        # can send a reader to touch a policy that was linked all along.
        if ($linkedOUs.Count -eq 0) {
            $obj | Add-Member -NotePropertyName 'lapsGpoNotLinked' -NotePropertyValue (
                'This GPO carries LAPS policy settings and is linked to no OU, domain or site, so the settings apply to no computer at all.'
            ) -Force
        }
    }

    # The other half of "does this policy reach a machine". LAPS is a computer policy, so
    # a GPO whose computer configuration is switched off carries every setting above into
    # the report while delivering none of them - and the links can be perfectly healthy
    # while that is true. flags was never read here; Get-DomainGPO decodes it, and
    # Get-GPOEffectiveStatus answers $null when the policy does apply, so the row exists
    # only when there is something to say. GPO_NOT_CURRENTLY_EFFECTIVE hangs off it.
    $gpoStatus = Get-GPOEffectiveStatus `
        -StatusEntry $(if ($GPOStatusMap -and $gpoGuid) { $GPOStatusMap[$gpoGuid] } else { $null }) `
        -Scope 'Machine' `
        -Link $(if ($null -eq $GPOLinkage) { $null } else { $linkedOUs })
    if ($gpoStatus) {
        $obj | Add-Member -NotePropertyName 'GPOStatus' -NotePropertyValue $gpoStatus -Force
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

    # Read once for the whole batch, like the linkage above it. An empty map is the
    # honest answer to a failed lookup: Get-GPOEffectiveStatus then says nothing rather
    # than reporting a policy as ineffective on the strength of a query that did not
    # answer - the same distinction the linkage block makes.
    $gpoStatusMap = @{}
    try {
        $gpoStatusMap = Get-GPOStatusMap -GPO (Get-DomainGPO)
    } catch {
        Write-Log "[Get-LAPSGPOConfigObjects] Failed to read the GPO status: $_"
    }

    $objects = @()

    # The tables are keyed by GPO GUID, because display names are not unique and the key
    # used to decide which of two same-named policies survived. The name a reader sees
    # comes out of the metadata; the key is the fallback for a record that has none, and
    # the sort is still by name so the report reads in the same order as before.
    foreach ($generation in @('Windows LAPS', 'LAPS Legacy')) {
        $table = if ($generation -eq 'Windows LAPS') { $LAPSGPOSettings.Native } else { $LAPSGPOSettings.Legacy }
        if (-not $table) { continue }

        $keys = @($table.Keys | Sort-Object -Property @{ Expression = {
            if ($table[$_].ContainsKey('GPOName') -and $table[$_]['GPOName']) { [string]$table[$_]['GPOName'] } else { [string]$_ }
        } }, @{ Expression = { [string]$_ } })

        foreach ($gpoKey in $keys) {
            $metadata = $table[$gpoKey]
            $displayName = if ($metadata.ContainsKey('GPOName') -and $metadata['GPOName']) {
                [string]$metadata['GPOName']
            } else {
                [string]$gpoKey
            }
            $objects += New-LAPSGPOConfigObject -GPOName $displayName -Metadata $metadata `
                -Generation $generation -GPOLinkage $gpoLinkage -GPOStatusMap $gpoStatusMap
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

<#
.SYNOPSIS
    Says on which domain controllers Windows LAPS manages the DSRM password.

.DESCRIPTION
    A domain controller has no local account for LAPS to manage, but it has the Directory
    Services Restore Mode account: the local administrator of the mode a domain controller
    is restored in, its password set at promotion and checked against no password policy.
    Nothing changes that password afterwards unless someone resets it by hand, or Windows
    LAPS manages it - on Windows Server 2019 and later domain controllers, in a domain at
    functional level 2016 or higher, once a policy turns on BackupDsrmPassword with
    password encryption.

    Read from the domain controllers, not from the policy: a policy says what was meant to
    happen, the DC what did. Where Windows LAPS manages the DSRM password it keeps
    msLAPS-PasswordExpirationTime on the DC's computer object, as on every computer it
    manages, and the attribute is not confidential. An expiration time more than the grace
    period in the past means nothing rotates the password any more - the rotation stalled,
    or the attribute was left behind when a LAPS-managed server was promoted. 0, the
    request for an immediate rotation, and values that are no date say nothing about age
    and count as managed, as they count as protected in the coverage figures.

    Notes, not findings: an unmanaged DSRM password is the state of every domain that never
    set this up, and the directory says nothing about how old or how strong it is.

    Returns the rows of the dsrmPassword line of the coverage summary, and nothing where
    no domain controller was read.

.PARAMETER DomainController
    The domain controllers, with sAMAccountName and msLAPS-PasswordExpirationTime.

.PARAMETER GraceDays
    How far an expiration time may lie in the past before the password counts as no
    longer rotated - the grace the computers get.

.PARAMETER EraStart
    Expiration times before this are no rotation date - the bound the computers get.

.NOTES
    Internal helper function
#>
function Get-DSRMPasswordManagement {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [object[]]$DomainController,

        [Parameter(Mandatory=$true)]
        [int]$GraceDays,

        [Parameter(Mandatory=$true)]
        [DateTime]$EraStart
    )

    $total = @($DomainController).Count
    if ($total -eq 0) { return }

    $cutoff = (Get-Date).AddDays(-$GraceDays)
    $unmanaged = @()
    $notRotated = @()
    foreach ($dc in $DomainController) {
        $name = if ($dc.sAMAccountName) {
            "$($dc.sAMAccountName)" -replace '\$$', ''
        } else {
            ("$($dc.distinguishedName)" -split ',')[0] -replace '^CN=', ''
        }
        $expiry = $dc.'msLAPS-PasswordExpirationTime'
        if ($null -eq $expiry) {
            $unmanaged += $name
        } elseif ($expiry -is [DateTime] -and $expiry -ge $EraStart -and $expiry -lt $cutoff) {
            $notRotated += $name
        }
    }

    $rows = @()
    if (@($unmanaged).Count -gt 0) {
        $rows += "Not managed by Windows LAPS on $(@($unmanaged).Count) of $total domain controller(s): $(Format-LAPSComputerList -Name $unmanaged)"
    }
    if (@($notRotated).Count -gt 0) {
        $rows += "No longer rotated by Windows LAPS on $(@($notRotated).Count) of $total domain controller(s) - expired more than $GraceDays days ago: $(Format-LAPSComputerList -Name $notRotated)"
    }
    if ($rows.Count -eq 0) {
        $rows += "Managed by Windows LAPS on all $total domain controller(s)"
    }
    return $rows
}

<#
.SYNOPSIS
    Builds the coverage summary of Get-LAPSConfiguration - one object for what the
    section measured.

.DESCRIPTION
    The figures were loose lines: how many computers were active and which were left out,
    how many have LAPS and of which generation, whether the passwords rotate, how many have
    none, and what the domain controllers show about their DSRM password. None of them had
    a card behind it in the report, the line that announced the unprotected OUs read
    "1 computers", and the DSRM line came after every object of the section.

    Each figure is a row now, and only rows that apply are added. The objects that name
    machines - the passwords that stopped rotating, the computers without LAPS per OU -
    still follow the summary.

.PARAMETER ActiveCount
    The active computers the figures are measured against, domain controllers left out.

.PARAMETER Excluded
    What was left out of that count, e.g. "1 inactive", "2 domain controllers".

.PARAMETER DomainControllerLookupFailed
    The domain controllers could not be read, so they are counted as ordinary computers.

.PARAMETER NoSchema
    Neither LAPS schema is present, so no computer can carry a LAPS attribute.

.PARAMETER ProtectedCount
    Active computers with a LAPS attribute.

.PARAMETER Breakdown
    The protected computers by generation, e.g. "3 Legacy, 1 Native".

.PARAMETER StaleCount
    Protected computers whose password stopped rotating.

.PARAMETER UndatedExpiry
    Protected computers whose expiration time is no rotation date.

.PARAMETER UnprotectedCount
    Active computers without a LAPS attribute.

.PARAMETER CoverageCaveat
    Set where a Windows LAPS policy escrows the password outside Active Directory: a
    missing attribute then does not mean an unmanaged password.

.PARAMETER DsrmRow
    The rows from Get-DSRMPasswordManagement.

.NOTES
    Internal helper function
#>
function New-LAPSCoverageSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$ActiveCount,

        [Parameter(Mandatory=$false)]
        [AllowEmptyCollection()]
        [string[]]$Excluded = @(),

        [switch]$DomainControllerLookupFailed,

        [switch]$NoSchema,

        [int]$ProtectedCount = 0,

        [string]$Breakdown,

        [int]$StaleCount = 0,

        [Parameter(Mandatory=$false)]
        [AllowEmptyCollection()]
        [string[]]$UndatedExpiry = @(),

        [int]$UnprotectedCount = 0,

        [string]$CoverageCaveat,

        [Parameter(Mandatory=$false)]
        [AllowEmptyCollection()]
        [string[]]$DsrmRow = @()
    )

    $noun = if ($ActiveCount -eq 1) { 'computer' } else { 'computers' }
    $share = {
        param([int]$Part)
        [math]::Round(($Part / $ActiveCount) * 100, 1)
    }

    $summary = [PSCustomObject]@{
        activeComputers = $ActiveCount
    }
    if (@($Excluded).Count -gt 0) {
        $summary | Add-Member -NotePropertyName 'excludedFromCount' -NotePropertyValue (@($Excluded) -join ', ') -Force
    }
    if ($DomainControllerLookupFailed) {
        $summary | Add-Member -NotePropertyName 'domainControllerLookup' -NotePropertyValue 'Domain Controllers could not be enumerated - counted as ordinary computers, so LAPS coverage is understated' -Force
    }

    # 0 of 0 is not 100 per cent: with no active computer left - every machine inactive in
    # a lab or a domain being decommissioned, or a domain whose only computers are its
    # domain controllers - nothing was measured, and saying so is the whole statement.
    if ($ActiveCount -eq 0) {
        $summary | Add-Member -NotePropertyName 'lapsProtected' -NotePropertyValue 'Not evaluated - no active computer to measure' -Force
    }
    elseif ($NoSchema) {
        $summary | Add-Member -NotePropertyName 'lapsProtected' -NotePropertyValue "0 of $ActiveCount $noun (0%) - the LAPS schema is not present in Active Directory" -Force
    }
    else {
        $protectedText = "$ProtectedCount of $ActiveCount $noun ($(& $share $ProtectedCount)%)"
        if ($Breakdown) { $protectedText += ": $Breakdown" }
        $summary | Add-Member -NotePropertyName 'lapsProtected' -NotePropertyValue $protectedText -Force
    }

    # Coverage counts a machine as protected the moment the expiration attribute exists;
    # whether the password behind it rotates is the next question, asked of those only.
    if ($ProtectedCount -gt 0) {
        $rotation = if ($StaleCount -gt 0) {
            "Stopped on $StaleCount of the $ProtectedCount - counted as protected above, and they are not"
        } elseif (@($UndatedExpiry).Count -gt 0) {
            # The machines named in lapsExpiryNotADate were not assessed, so the row says
            # what was.
            'Every computer whose LAPS expiration time is a date rotated its password on schedule'
        } else {
            'Every computer with LAPS rotated its password on schedule'
        }
        $summary | Add-Member -NotePropertyName 'lapsRotation' -NotePropertyValue $rotation -Force
    }
    if (@($UndatedExpiry).Count -gt 0) {
        $summary | Add-Member -NotePropertyName 'lapsExpiryNotADate' -NotePropertyValue "$(Format-LAPSComputerList -Name $UndatedExpiry -Limit 10) - the expiration time is not a rotation date (0 = rotation requested)" -Force
    }

    if ($ActiveCount -gt 0) {
        if ($UnprotectedCount -gt 0) {
            # "Without LAPS protection" is a claim the attributes cannot support when a
            # policy escrows elsewhere. Which machines are in that policy's scope is not
            # knowable from here, so the count stays and the row says what it counts.
            $unprotectedText = "$UnprotectedCount of $ActiveCount $noun ($(& $share $UnprotectedCount)%)"
            if ($CoverageCaveat) { $unprotectedText += ' carry no LAPS attribute in Active Directory' }
            $summary | Add-Member -NotePropertyName 'lapsUnprotected' -NotePropertyValue $unprotectedText -Force
            if ($CoverageCaveat) {
                $summary | Add-Member -NotePropertyName 'lapsBackupOutsideAD' -NotePropertyValue $CoverageCaveat -Force
            }
        }
        else {
            $summary | Add-Member -NotePropertyName 'lapsUnprotected' -NotePropertyValue 'None - every active computer has LAPS' -Force
        }
    }

    if (@($DsrmRow).Count -gt 0) {
        $summary | Add-Member -NotePropertyName 'dsrmPassword' -NotePropertyValue @($DsrmRow) -Force
    }

    $summary | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LAPSCoverage' -Force
    return $summary
}

<#
.SYNOPSIS
    Shows the computers without LAPS, one object per OU.

.DESCRIPTION
    The per-OU objects of the coverage section, after its summary: which OU, how many,
    and which machines. Where a Windows LAPS policy escrows outside Active Directory each
    object carries lapsBackupOutsideAD, which hands it to LAPS_COVERAGE_NOT_IN_AD instead
    of the finding that says the passwords are not managed.

.PARAMETER Computer
    The computers without a LAPS attribute.

.PARAMETER CoverageCaveat
    Set where a Windows LAPS policy escrows the password outside Active Directory.

.NOTES
    Internal helper function
#>
function Show-LAPSUnprotectedByOU {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [object[]]$Computer,

        [Parameter(Mandatory=$false)]
        [string]$CoverageCaveat
    )

    $byOU = @{}
    $total = @($Computer).Count
    $currentIndex = 0
    foreach ($machine in $Computer) {
        $currentIndex++
        if ($total -gt $Script:ProgressThreshold) { Show-Progress -Activity "Checking LAPS configuration" -Current $currentIndex -Total $total -ObjectName $machine.name }
        if ("$($machine.distinguishedName)" -match '^CN=[^,]+,(.+)$') {
            $ouDN = $Matches[1]
            if (-not $byOU.ContainsKey($ouDN)) { $byOU[$ouDN] = @() }
            $byOU[$ouDN] += ($machine.sAMAccountName -replace '\$$', '')
        }
    }
    if ($total -gt $Script:ProgressThreshold) { Show-Progress -Activity "Checking LAPS configuration" -Completed }
    if ($byOU.Count -eq 0) { return }

    $class = if ($CoverageCaveat) { 'Hint' } else { 'Finding' }
    $what = if ($CoverageCaveat) { 'without a LAPS attribute in Active Directory' } else { 'without LAPS protection' }
    Show-Line "Found $total computer(s) $what, by OU:" -Class $class

    foreach ($ouEntry in ($byOU.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending)) {
        $lapsFinding = [PSCustomObject]@{
            ouName = $ouEntry.Key
            computerCount = $ouEntry.Value.Count
            lapsUnprotectedComputers = (Format-LAPSComputerList -Name $ouEntry.Value)
        }
        # Read by the Custom trigger on lapsUnprotectedComputers.
        if ($CoverageCaveat) {
            $lapsFinding | Add-Member -NotePropertyName 'lapsBackupOutsideAD' -NotePropertyValue $CoverageCaveat -Force
        }
        $lapsFinding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LAPSConfiguration' -Force
        Show-Object $lapsFinding -Class $class
    }
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
    when BackupDsrmPassword is on. Their count travels in the population line, alongside the
    inactive machines - what a reader needs is how many were left out, not a sentence about
    why, which is the same on every run of every domain.

    Whether BackupDsrmPassword is configured is a Windows LAPS policy setting rather than a
    coverage figure, and it is reported where the other policy settings are: on the GPO
    object in the section above, as DsrmPasswordBackup. Whether Windows LAPS actually
    manages a domain controller's DSRM password is read from the domain controller, and is
    the last line of the coverage section.

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

    .PARAMETER OPSEC
    Skips the check. It is the loudest one in the Computer module: every enabled computer,
    a second query for the LAPS-carrying ones, the domain controllers, and a full SYSVOL
    walk over every Registry.pol. Its two siblings already abstain under -OPSEC and say so
    in the report; this one ran at full volume without a line.

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
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$OPSEC
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
            # Built explicitly rather than splatting $PSBoundParameters: that carries
            # every bound parameter, and neither Ensure-LDAPConnection nor
            # Get-LAPSSchemaPresence nor Get-DomainComputer has a parameter named OPSEC.
            # The binding error would land in this function's own try/catch and the check
            # would report nothing at all - silently, which is how it was found elsewhere.
            $connectionParams = @{}
            if ($PSBoundParameters.ContainsKey('Domain'))     { $connectionParams['Domain'] = $Domain }
            if ($PSBoundParameters.ContainsKey('Server'))     { $connectionParams['Server'] = $Server }
            if ($PSBoundParameters.ContainsKey('Credential')) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            # The loudest check in the module: every enabled computer, a second query for
            # the ones carrying LAPS, the domain controllers, and a SYSVOL walk over every
            # Registry.pol. Its two siblings abstain under -OPSEC and say so; this one ran
            # at full volume without a word.
            if ($OPSEC) {
                Show-Line "OPSEC mode: Skipping LAPS configuration check (would query every computer and walk SYSVOL)" -Class "Hint"
                return
            }

            # ===== Step 1: Schema Detection =====
            Show-SubHeader "Checking for LAPS schema attributes..." -ObjectType "LAPSConfiguration"

            # One definition of "does this domain run LAPS", shared with
            # Get-LAPSCredentialAccess and Get-LAPSPermissions and cached for the session.
            $lapsSchema = Get-LAPSSchemaPresence @connectionParams
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

            # Where Windows LAPS escrows the password it manages. BackupDirectory 2 is
            # Active Directory, 1 is Microsoft Entra ID, 0 is disabled.
            #
            # The coverage figure further down is computed from AD attributes alone, and
            # these settings were read for the GPO section above and then never consulted
            # again. With BackupDirectory 1 the password IS managed and IS rotated - it
            # just goes to Entra ID, so by design no msLAPS attribute appears in AD. A
            # hybrid-joined fleet therefore read as 0 per cent coverage, with one red
            # finding per OU saying the local administrator passwords are unmanaged, and a
            # remediation ("deploy LAPS") that was already done.
            $lapsEntraPolicies = @()
            if ($lapsGPOHasNative) {
                foreach ($nativeEntry in $lapsGPOSettings.Native.GetEnumerator()) {
                    if ($nativeEntry.Value -isnot [hashtable]) { continue }
                    if (-not $nativeEntry.Value.ContainsKey('BackupDirectory')) { continue }
                    $backupTarget = 0
                    if (-not [int]::TryParse([string]$nativeEntry.Value['BackupDirectory'], [ref]$backupTarget)) { continue }
                    if ($backupTarget -eq 2) { continue }
                    # The table is keyed by GPO GUID, so the display name travels in the
                    # record. Reading the key here would put a GUID in the sentence.
                    $entryName = if ($nativeEntry.Value.ContainsKey('GPOName') -and $nativeEntry.Value['GPOName']) {
                        [string]$nativeEntry.Value['GPOName']
                    } else {
                        [string]$nativeEntry.Key
                    }
                    $lapsEntraPolicies += [PSCustomObject]@{
                        GPOName = $entryName
                        Target  = if ($backupTarget -eq 1) { 'Microsoft Entra ID' } else { 'nowhere - backup is disabled' }
                    }
                }
            }

            $coverageCaveat = $null
            if (@($lapsEntraPolicies).Count -gt 0) {
                $policyList = @($lapsEntraPolicies | ForEach-Object { "$($_.GPOName) -> $($_.Target)" }) -join '; '
                $coverageCaveat = "A Windows LAPS policy in this domain backs the password up outside Active Directory ($policyList). A computer in its scope keeps no msLAPS attribute here by design, so whether its local administrator password is managed cannot be read from Active Directory."
            }

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
            $domainControllers = @()
            $domainControllerCount = 0
            $domainControllerLookupFailed = $false
            try {
                # The name and the Windows LAPS expiration time are for the DSRM line at the
                # end of the coverage section. No DC is shown as an object.
                foreach ($dc in @(Get-DomainComputer -DomainController -Properties 'distinguishedName', 'sAMAccountName', 'msLAPS-PasswordExpirationTime' @connectionParams)) {
                    if (-not $dc.distinguishedName) { continue }
                    $domainControllerDNs["$($dc.distinguishedName)".ToLowerInvariant()] = $true
                    $domainControllers += $dc
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
                        Show-Object $gpoConfigObject -Class Finding
                    }
                } else {
                    Show-Line "No LAPS schema found - LAPS is not deployed" -Class "Finding"
                }

                # Get active computers grouped by OU (uses $Script:DefaultInactiveDays)
                $allComputers = @(Get-DomainComputer -Enabled -Properties $ComputerProperties @connectionParams |
                    Test-AccountActivity -IsActive |
                    Where-Object { -not $domainControllerDNs.ContainsKey("$($_.distinguishedName)".ToLowerInvariant()) })

                # The same summary as with a schema, so a reader compares like with like:
                # every active computer unprotected, because none can carry an attribute.
                $noSchemaSummary = New-LAPSCoverageSummary -ActiveCount $allComputers.Count -NoSchema `
                    -UnprotectedCount $allComputers.Count -CoverageCaveat $coverageCaveat `
                    -DomainControllerLookupFailed:$domainControllerLookupFailed
                $noSchemaClass = if ($allComputers.Count -eq 0) { 'Note' } elseif ($coverageCaveat) { 'Hint' } else { 'Finding' }
                Show-Line "Found LAPS deployment coverage:" -Class $noSchemaClass
                Show-Object $noSchemaSummary -Class $noSchemaClass

                Show-LAPSUnprotectedByOU -Computer $allComputers -CoverageCaveat $coverageCaveat
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
                        Show-Object $gpoConfigObject -Class Hint
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
            $allEnabledComputers = @(Get-DomainComputer -Enabled -Properties $ComputerProperties @connectionParams |
                Where-Object { -not $domainControllerDNs.ContainsKey("$($_.distinguishedName)".ToLowerInvariant()) })

            # Query 2: Active computers (enabled + recent logon) - uses $Script:DefaultInactiveDays
            $activeComputers = @($allEnabledComputers | Test-AccountActivity -IsActive)

            # Query 3: Computers WITH LAPS (LDAP-side filter) - much faster than client-side attribute check
            $computersWithLAPSRaw = @(Get-DomainComputer -Enabled -LAPS -Properties $ComputerProperties @connectionParams |
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

            # The shares are worked out by New-LAPSCoverageSummary, which divides only where
            # there is an active computer to divide by.
            $withAnyLAPS = $withLegacyLAPS + $withWindowsLAPS + $withBothLAPS

            # What was measured and what was left out of it. The domain controllers once
            # took a line of their own carrying a sentence about why a DC is excluded; the
            # count is the part a reader needs, and the reason is the same on every run of
            # every domain. A failed domain controller lookup still needs saying: the DCs
            # are then counted as ordinary computers, which understates the coverage
            # figure. The DSRM backup policy setting is on the GPO object above; what the
            # domain controllers themselves show about their DSRM password is the last row
            # of the summary.
            $excluded = @()
            if ($inactiveCount -gt 0) { $excluded += "$inactiveCount inactive" }
            if (-not $domainControllerLookupFailed -and $domainControllerCount -gt 0) {
                $dcNoun = if ($domainControllerCount -eq 1) { 'domain controller' } else { 'domain controllers' }
                $excluded += "$domainControllerCount $dcNoun"
            }

            $lapsBreakdown = @()
            if ($withLegacyLAPS -gt 0) { $lapsBreakdown += "$withLegacyLAPS Legacy" }
            if ($withWindowsLAPS -gt 0) { $lapsBreakdown += "$withWindowsLAPS Native" }
            if ($withBothLAPS -gt 0) { $lapsBreakdown += "$withBothLAPS both" }

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

            # An expiration attribute that is present but is not a date: 0, which is the
            # documented way to request an immediate rotation, Int64::MaxValue, or a value
            # LAPS never wrote. None of them says anything about the age of the password,
            # and none is evidence of a stalled rotation - which is what reporting it as
            # overdue would claim. Named on the summary instead of dropped, because the
            # machine counts as protected there.
            $undatedExpiry = @()
            $lapsEraStart = [DateTime]'2015-01-01'

            foreach ($computer in $computersWithLAPS) {
                # Whichever generation last wrote wins: a machine migrated from Legacy to
                # Windows LAPS keeps the old attribute, and judging by the older of the two
                # would report every migrated machine as stale.
                $expiry = $null
                $generation = $null
                $carriesExpiryValue = $false
                foreach ($attr in @('ms-Mcs-AdmPwdExpirationTime', 'msLAPS-PasswordExpirationTime')) {
                    $value = $computer.$attr
                    if ($null -eq $value) { continue }
                    $carriesExpiryValue = $true
                    if ($value -isnot [DateTime]) { continue }
                    if ($null -eq $expiry -or $value -gt $expiry) {
                        $expiry = $value
                        $generation = if ($attr -eq 'ms-Mcs-AdmPwdExpirationTime') { 'LAPS Legacy' } else { 'Windows LAPS' }
                    }
                }

                if ($null -eq $expiry) {
                    if ($carriesExpiryValue) { $undatedExpiry += ($computer.sAMAccountName -replace '\$$', '') }
                    continue
                }

                # Nothing from before LAPS existed can be a rotation deadline. A four-digit
                # "days overdue" beside a real finding of forty days costs the whole section
                # its credibility, and the real finding is what gets lost.
                if ($expiry -lt $lapsEraStart) {
                    $undatedExpiry += ($computer.sAMAccountName -replace '\$$', '')
                    continue
                }

                if ($expiry -ge $staleCutoff) { continue }

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

            # ===== The domain controllers' DSRM passwords =====
            # Left out of the figures above because a DC has no local account for LAPS to
            # manage - but it has a DSRM account, and that one Windows LAPS can manage. A
            # failed lookup leaves the list empty and has its own row; with no domain
            # controller read, there is no DSRM row.
            $dsrmRows = @(Get-DSRMPasswordManagement -DomainController $domainControllers `
                -GraceDays $staleGraceDays -EraStart $lapsEraStart)

            # ===== The summary, then the machines it counts =====
            $summaryParams = @{
                ActiveCount                  = $activeCount
                Excluded                     = $excluded
                DomainControllerLookupFailed = $domainControllerLookupFailed
                ProtectedCount               = $withAnyLAPS
                Breakdown                    = ($lapsBreakdown -join ', ')
                StaleCount                   = $staleLAPSComputers.Count
                UndatedExpiry                = $undatedExpiry
                UnprotectedCount             = $withoutLAPS
                CoverageCaveat               = $coverageCaveat
                DsrmRow                      = $dsrmRows
            }
            $coverageSummary = New-LAPSCoverageSummary @summaryParams
            $coverageClass = if ($staleLAPSComputers.Count -gt 0 -or ($withoutLAPS -gt 0 -and -not $coverageCaveat)) {
                'Finding'
            } elseif ($withoutLAPS -gt 0) {
                'Hint'
            } elseif ($activeCount -eq 0) {
                'Note'
            } else {
                'Secure'
            }
            Show-Line "Found LAPS deployment coverage:" -Class $coverageClass
            Show-Object $coverageSummary -Class $coverageClass

            if ($staleLAPSComputers.Count -gt 0) {
                Show-Line "Found $($staleLAPSComputers.Count) computer(s) whose LAPS password stopped rotating:" -Class "Finding"
                foreach ($staleObject in ($staleLAPSComputers | Sort-Object daysOverdue -Descending)) {
                    Show-Object $staleObject -Class Finding
                }
            }

            if ($withoutLAPS -gt 0) {
                Show-LAPSUnprotectedByOU -Computer $computersWithoutLAPS -CoverageCaveat $coverageCaveat
            }

        } catch {
            # Say so on the console, not only in the log - an aborted check is otherwise
            # indistinguishable from a domain with nothing to report: the output just
            # stopped, and no line said the coverage figure was never computed.
            Write-Log "[Get-LAPSConfiguration] Error: $_" -Level Error
            Show-Line "Error during check - the LAPS configuration could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-LAPSConfiguration] Check completed"
    }
}

