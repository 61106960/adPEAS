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
    object in the section above, as DsrmPasswordBackup.

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
            $domainControllerCount = 0
            $domainControllerLookupFailed = $false
            try {
                foreach ($dc in @(Get-DomainComputer -DomainController -Properties 'distinguishedName' @connectionParams)) {
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
                        Show-Object $gpoConfigObject -Class Finding
                    }
                } else {
                    Show-Line "No LAPS schema found - LAPS is not deployed" -Class "Finding"
                }

                # Get active computers grouped by OU (uses $Script:DefaultInactiveDays)
                $allComputers = @(Get-DomainComputer -Enabled -Properties $ComputerProperties @connectionParams |
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

                if ($coverageCaveat) {
                    Show-Line "$($allComputers.Count) computers carry no LAPS attribute in Active Directory, and the schema here cannot hold one" -Class "Hint"
                    Show-Line $coverageCaveat -Class "Note"
                } else {
                    Show-Line "$($allComputers.Count) computers (100%) without LAPS protection" -Class "Finding"
                }

                # Output each OU as structured object for proper tooltip support
                foreach ($ouEntry in ($computersByOU.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending)) {
                    $lapsFinding = [PSCustomObject]@{
                        ouName = $ouEntry.Key
                        computerCount = $ouEntry.Value.Count
                        lapsUnprotectedComputers = (Format-LAPSComputerList -Name $ouEntry.Value)
                    }
                    if ($coverageCaveat) {
                        $lapsFinding | Add-Member -NotePropertyName 'lapsBackupOutsideAD' -NotePropertyValue $coverageCaveat -Force
                    }
                    $lapsFinding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LAPSConfiguration' -Force
                    Show-Object $lapsFinding -Class $(if ($coverageCaveat) { 'Hint' } else { 'Finding' })
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

            $withAnyLAPS = $withLegacyLAPS + $withWindowsLAPS + $withBothLAPS
            $lapsCoverage = if ($activeCount -gt 0) { [math]::Round(($withAnyLAPS / $activeCount) * 100, 1) } else { 0 }
            $withoutLAPSPercent = if ($activeCount -gt 0) { [math]::Round(($withoutLAPS / $activeCount) * 100, 1) } else { 0 }

            # Output statistics - one line for what was measured and what was left out of
            # it. The domain controllers used to take a line of their own carrying a
            # sentence about why a DC is excluded; the count is the part a reader needs,
            # and the reason is the same on every run of every domain.
            $excluded = @()
            if ($inactiveCount -gt 0) { $excluded += "$inactiveCount inactive excluded" }
            if (-not $domainControllerLookupFailed -and $domainControllerCount -gt 0) {
                $dcNoun = if ($domainControllerCount -eq 1) { 'domain controller' } else { 'domain controllers' }
                $excluded += "$domainControllerCount $dcNoun excluded"
            }
            $excludedInfo = if ($excluded.Count -gt 0) { " (" + ($excluded -join ', ') + ")" } else { "" }
            Show-Line "Found $activeCount active computers$excludedInfo" -Class "Hint"

            # A failed domain controller lookup still needs saying: the DCs are then counted
            # as ordinary computers below, which understates the coverage figure rather than
            # leaving it out of it. The DSRM backup state used to be reported here as well
            # and is not any more - it is a Windows LAPS policy setting rather than a
            # coverage figure, and it belongs to the GPO section above if anywhere.
            if ($domainControllerLookupFailed) {
                Show-Line "Domain Controllers could not be enumerated - counted as ordinary computers, so LAPS coverage is understated" -Class "Note"
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

            # An expiration attribute that is present but is not a date: 0, which is the
            # documented way to request an immediate rotation, Int64::MaxValue, or a value
            # LAPS never wrote. None of them says anything about the age of the password,
            # and none is evidence of a stalled rotation - which is what reporting it as
            # overdue would claim. Named at the end instead of dropped, because the machine
            # counted as protected in the coverage figure above.
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

            if ($staleLAPSComputers.Count -gt 0) {
                Show-Line "$($staleLAPSComputers.Count) computer(s) have LAPS but their password stopped rotating - counted as protected above, and they are not" -Class "Finding"
                foreach ($staleObject in ($staleLAPSComputers | Sort-Object daysOverdue -Descending)) {
                    Show-Object $staleObject -Class Finding
                }
            } elseif ($withAnyLAPS -gt 0 -and @($undatedExpiry).Count -eq 0) {
                Show-Line "Every computer with LAPS rotated its password on schedule" -Class "Secure"
            } elseif ($withAnyLAPS -gt 0) {
                # The machines named below were not assessed, so the sentence says what was.
                Show-Line "Every computer whose LAPS expiration time is a date rotated on schedule" -Class "Secure"
            }

            if (@($undatedExpiry).Count -gt 0) {
                Show-Line "LAPS expiration time is not a rotation date (0 = rotation requested) on: $(Format-LAPSComputerList -Name $undatedExpiry -Limit 10)" -Class "Note"
            }

            # Highlight computers without LAPS
            if ($withoutLAPS -gt 0) {
                # "Without LAPS protection" is a claim the AD attributes cannot support
                # when a policy escrows elsewhere. Which machines are in that policy's
                # scope is not knowable from here, so the count stays as it is and the
                # sentence says what it is a count OF.
                if ($coverageCaveat) {
                    Show-Line "$withoutLAPS of $activeCount computers ($withoutLAPSPercent%) carry no LAPS attribute in Active Directory" -Class "Hint"
                    Show-Line $coverageCaveat -Class "Note"
                } else {
                    Show-Line "$withoutLAPS computers ($withoutLAPSPercent%) without LAPS protection" -Class "Finding"
                }

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
                    # Read by the Custom trigger on lapsUnprotectedComputers, which hands
                    # the row to LAPS_COVERAGE_NOT_IN_AD instead of the finding that says
                    # the passwords are not managed.
                    if ($coverageCaveat) {
                        $lapsFinding | Add-Member -NotePropertyName 'lapsBackupOutsideAD' -NotePropertyValue $coverageCaveat -Force
                    }
                    $lapsFinding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LAPSConfiguration' -Force
                    Show-Object $lapsFinding -Class $(if ($coverageCaveat) { 'Hint' } else { 'Finding' })
                }
            } elseif ($activeCount -eq 0) {
                # 0 of 0 is not 100 per cent. Coverage divides by the active computers, and
                # with none of them left - every machine inactive in a lab or a domain being
                # decommissioned, or a domain whose only computers are its domain controllers
                # - $withoutLAPS is 0 for the same reason the numerator is, and the check
                # fell into the branch below and certified a clean domain from a scan that
                # measured no machine at all.
                Show-Line "No active computer to measure - LAPS coverage was not evaluated" -Class "Note"
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

