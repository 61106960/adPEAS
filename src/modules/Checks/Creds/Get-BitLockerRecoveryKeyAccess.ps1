function Get-BitLockerRecoveryKeyAccess {
    <#
    .SYNOPSIS
    Tests which BitLocker recovery keys the current user can read from Active Directory.

    .DESCRIPTION
    BitLocker recovery information is escrowed in AD as separate child objects
    (objectClass=msFVE-RecoveryInformation) below each computer object - NOT as an
    attribute on the computer object itself. The 48-digit recovery password lives in the
    msFVE-RecoveryPassword attribute, whose read access is gated by a control access
    right / ACL.

    This check performs a SINGLE domain-wide, server-side filtered subtree query:

        (&(objectClass=msFVE-RecoveryInformation)(msFVE-RecoveryPassword=*))

    The presence filter (msFVE-RecoveryPassword=*) is ACL-gated: the DC only returns
    recovery objects whose password the bound user is actually allowed to read - the
    exact same mechanism used for Legacy LAPS (ms-Mcs-AdmPwd=*) in Get-LAPSCredentialAccess.
    This keeps the result set limited to readable keys from the start, instead of
    enumerating every computer account.

    Performance:
    - Schema short-circuit: if BitLocker recovery escrow is not used in the domain, the
      expensive domain-wide query is skipped entirely (cached in $Script:BitLockerSchemaInfo).
    - Single paged subtree query (paging handled by Invoke-LDAPSearch).
    - Computer name is derived from the recovery object's parent DN (no extra LDAP queries).

    A second section answers who else may read them (Show-BitLockerRecoveryDelegation):
    the delegated reads of msFVE-RecoveryPassword on the containers holding computers, and
    whether the confidential flag on the attribute lets each of them work today.

    Related Checks:
    - Get-LAPSCredentialAccess (Creds): Which LAPS passwords can the current user read?

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .PARAMETER IncludePrivileged
    Also list privileged principals that hold a delegated read of the recovery passwords
    (shown as yellow/Hint severity). Domain Admins read them by default, so they are hidden
    unless asked for.

    .EXAMPLE
    Get-BitLockerRecoveryKeyAccess

    .EXAMPLE
    Get-BitLockerRecoveryKeyAccess -IncludePrivileged

    .EXAMPLE
    Get-BitLockerRecoveryKeyAccess -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Creds
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
        Write-Log "[Get-BitLockerRecoveryKeyAccess] Starting check"
    }

    process {
        try {
            # Connection parameters only, never @PSBoundParameters: -IncludePrivileged would
            # be splatted into Ensure-LDAPConnection and Get-DomainObject, which have no
            # parameter of that name, and the binding error ends the check before its first
            # line of output.
            $connectionParams = @{}
            if ($Domain)     { $connectionParams['Domain']     = $Domain }
            if ($Server)     { $connectionParams['Server']     = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            Show-SubHeader "Testing BitLocker recovery key read access for current user..." -ObjectType "BitLockerRecoveryKey"

            # ===== Step 1: Schema / feasibility short-circuit (cached) =====
            # Many environments do not escrow BitLocker recovery keys to AD. Detect this once
            # and cache it so we never run the expensive domain-wide query needlessly.
            $bitLockerPresent = $false

            if ($Script:BitLockerSchemaInfo) {
                $bitLockerPresent = $Script:BitLockerSchemaInfo.Present
                Write-Log "[Get-BitLockerRecoveryKeyAccess] Using cached schema info: Present=$bitLockerPresent"
            } else {
                $schemaDN = $Script:LDAPContext.SchemaNamingContext

                # Method 1: Schema partition query for the msFVE-RecoveryInformation class
                if ($schemaDN) {
                    try {
                        $schemaFilter = "(&(objectClass=classSchema)(|(lDAPDisplayName=msFVE-RecoveryInformation)(cn=ms-FVE-RecoveryInformation)))"
                        $schemaResult = @(Get-DomainObject -LDAPFilter $schemaFilter -SearchBase $schemaDN -Properties 'cn' -ResultLimit 1 @connectionParams)
                        if ($schemaResult.Count -gt 0) {
                            $bitLockerPresent = $true
                            Write-Log "[Get-BitLockerRecoveryKeyAccess] msFVE-RecoveryInformation schema class found"
                        }
                    } catch {
                        Write-Log "[Get-BitLockerRecoveryKeyAccess] Schema query error: $($_.Exception.Message)"
                    }
                }

                # Method 2: Fallback - check if any recovery object exists (minimal query)
                if (-not $bitLockerPresent) {
                    $existsCheck = @(Get-DomainObject -LDAPFilter "(objectClass=msFVE-RecoveryInformation)" -Properties 'distinguishedName' -ResultLimit 1 @connectionParams)
                    if ($existsCheck.Count -gt 0) {
                        $bitLockerPresent = $true
                        Write-Log "[Get-BitLockerRecoveryKeyAccess] msFVE-RecoveryInformation objects detected"
                    }
                }

                # Cache result for repeated calls within the same session
                $Script:BitLockerSchemaInfo = @{ Present = $bitLockerPresent }
            }

            if (-not $bitLockerPresent) {
                Show-Line "BitLocker recovery escrow is not used in this domain (no msFVE-RecoveryInformation objects found)" -Class "Note"
                return
            }

            # ===== Step 2: Single ACL-gated subtree query for readable recovery keys =====
            # The (msFVE-RecoveryPassword=*) presence filter only matches objects whose
            # password the bound user is permitted to read (ACL-based attribute return).
            Write-Log "[Get-BitLockerRecoveryKeyAccess] Querying for readable BitLocker recovery keys"

            $recoveryProperties = @(
                'msFVE-RecoveryPassword',
                'msFVE-RecoveryGuid',
                'msFVE-VolumeGuid',
                'whenCreated'
            )

            $recoveryObjects = @(Get-DomainObject -LDAPFilter "(&(objectClass=msFVE-RecoveryInformation)(msFVE-RecoveryPassword=*))" -Properties $recoveryProperties -Raw @connectionParams)

            Write-Log "[Get-BitLockerRecoveryKeyAccess] Found $($recoveryObjects.Count) readable recovery key(s)"

            # ===== Step 3: Output =====
            # The presence filter is ACL-gated, so a returned object is normally a readable
            # one. Trust it only as far as the value that actually arrives: an object that
            # comes back without the recovery password is not a readable key, and listing
            # it as one hands the reader a row with a blank password and an access claim
            # that is not true.
            $withheldObjects = @($recoveryObjects | Where-Object {
                [string]::IsNullOrWhiteSpace([string]$_.'msFVE-RecoveryPassword')
            })
            $recoveryObjects = @($recoveryObjects | Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_.'msFVE-RecoveryPassword')
            })

            if ($withheldObjects.Count -gt 0) {
                Write-Log "[Get-BitLockerRecoveryKeyAccess] $($withheldObjects.Count) recovery object(s) returned without a readable password"
            }

            if ($recoveryObjects.Count -gt 0) {
                Show-Line "Found $($recoveryObjects.Count) readable BitLocker recovery key(s):" -Class "Hint"

                $totalObjects = $recoveryObjects.Count
                $currentIndex = 0
                foreach ($recoveryObject in $recoveryObjects) {
                    $currentIndex++
                    if ($totalObjects -gt $Script:ProgressThreshold) { Show-Progress -Activity "Checking BitLocker recovery key access" -Current $currentIndex -Total $totalObjects -ObjectName $recoveryObject.distinguishedName }

                    # Derive computer name + parent DN from the recovery object's DN.
                    # Recovery object DN: CN=<datetime>{guid},CN=<COMPUTERNAME>,OU=...,DC=...
                    # The msFVE CN value never contains commas, so stripping the first RDN is safe.
                    $recoveryDN = [string]$recoveryObject.distinguishedName
                    $parentDN = $recoveryDN -replace '^CN=[^,]+,', ''
                    $computerName = if ($parentDN -match '^CN=([^,]+),') { $Matches[1] } else { $parentDN }
                    $recoveryObject | Add-Member -NotePropertyName 'ComputerName' -NotePropertyValue $computerName -Force
                    # Replace the noisy recovery-object DN with the parent computer DN for display
                    $recoveryObject | Add-Member -NotePropertyName 'distinguishedName' -NotePropertyValue $parentDN -Force

                    # Convert recovery/volume GUID byte arrays to readable GUID strings
                    foreach ($guidAttr in @('msFVE-RecoveryGuid', 'msFVE-VolumeGuid')) {
                        $guidValue = $recoveryObject.$guidAttr
                        if ($guidValue -is [byte[]] -and $guidValue.Length -eq 16) {
                            try {
                                $guidObj = New-Object System.Guid -ArgumentList (,$guidValue)
                                $recoveryObject | Add-Member -NotePropertyName $guidAttr -NotePropertyValue $guidObj.ToString() -Force
                            } catch {
                                Write-Log "[Get-BitLockerRecoveryKeyAccess] Failed to convert $guidAttr for '$parentDN': $($_.Exception.Message)"
                            }
                        }
                    }

                    # Format whenCreated (raw generalized time, e.g. 20240115103045.0Z)
                    $whenCreatedRaw = [string]$recoveryObject.whenCreated
                    if ($whenCreatedRaw -match '^(\d{14})') {
                        try {
                            $escrowTime = [datetime]::ParseExact($Matches[1], 'yyyyMMddHHmmss', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal)
                            $recoveryObject | Add-Member -NotePropertyName 'whenCreated' -NotePropertyValue ((Format-adPEASDate $escrowTime 'yyyy-MM-dd HH:mm:ss') + ' UTC') -Force
                        } catch {
                            # Leave raw value if parsing fails
                        }
                    }

                    $recoveryObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'BitLockerRecoveryKey' -Force
                    Show-Object $recoveryObject -Class Hint
                }
                if ($totalObjects -gt $Script:ProgressThreshold) { Show-Progress -Activity "Checking BitLocker recovery key access" -Completed }
            } else {
                Show-Line "No readable BitLocker recovery keys found" -Class "Secure"
            }

            # These volumes do have a recovery key escrowed, the directory just did not hand
            # it over. That is a different fact from "no BitLocker escrow here".
            if ($withheldObjects.Count -gt 0) {
                Show-Line "$($withheldObjects.Count) escrowed recovery key(s) exist that this account may not read" -Class "Note"
            }

            # ===== Step 4: who else may read the recovery passwords =====
            # Steps 2 and 3 answer for the account running the scan. A scan run as an
            # ordinary user ends there with "No readable BitLocker recovery keys found",
            # whatever a helpdesk group may read - which is what the remediation of a
            # readable key tells the reader to review. Its own try: a failure here must not
            # read as a clean delegation, and must not take the answer above with it.
            try {
                Show-BitLockerRecoveryDelegation -IncludePrivileged:$IncludePrivileged -ConnectionParams $connectionParams
            } catch {
                Write-Log "[Get-BitLockerRecoveryKeyAccess] Delegation analysis failed: $_" -Level Error
                Show-Line "Error during the delegation analysis - who may read the recovery passwords could not be evaluated: $_" -Class Finding
            }

        } catch {
            Write-Log "[Get-BitLockerRecoveryKeyAccess] Error: $_" -Level Error
            Show-Line "Error during check - BitLocker recovery key access could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-BitLockerRecoveryKeyAccess] Check completed"
    }
}

<#
.SYNOPSIS
    Reports principals that can read the BitLocker recovery passwords below the computers.

.DESCRIPTION
    Step 4 of Get-BitLockerRecoveryKeyAccess. Steps 1 to 3 answer which recovery passwords
    the account running the scan may read; this answers who else may.

    Scoped to the containers that hold computer objects, disabled ones included: a recovery
    password stays valid for its disk when the computer account is disabled, and a retired
    disk is where it gets used. Not scoped to the recovery objects themselves, because the
    account running a scan normally cannot see them: the shipped default security descriptor
    of msFVE-RecoveryInformation grants the object to Domain Admins and SYSTEM only
    (learn.microsoft.com, adschema), so for anybody else a search does not return it. A
    container's DACL already carries what it inherits from above, so one read per container
    answers for every computer below it; the documented cost is that an ACE set directly on
    one computer or on one recovery object is not seen.

    The attribute is confidential, so a read takes READ_PROPERTY and CONTROL_ACCESS, and both
    halves have to reach the same recovery object. They are therefore combined per container
    before anything is decided - a read delegated on one container and control access on
    another reads nothing on either:

      READ_PROPERTY and CONTROL_ACCESS, or full control   live today              Finding
      READ_PROPERTY only, attribute confidential           dormant until the flag
                                                            is cleared              Hint
      READ_PROPERTY only, attribute not confidential       live today              Finding
      READ_PROPERTY only, schema unreadable                cannot be decided       Hint
      CONTROL_ACCESS only                                  reads nothing           not listed

    The dormant case is reported rather than dropped because the delegation is still there:
    clearing the flag makes every one of them live at once.

    Privileged principals are hidden unless -IncludePrivileged; Domain Admins read every
    recovery password by default.

.PARAMETER IncludePrivileged
    Also report privileged principals, as Hint rather than Finding.

.PARAMETER ConnectionParams
    Domain/Server/Credential hashtable, passed through unchanged.
#>
function Show-BitLockerRecoveryDelegation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [switch]$IncludePrivileged,

        [Parameter(Mandatory=$false)]
        [hashtable]$ConnectionParams = @{}
    )

    Show-SubHeader "Analyzing who may read BitLocker recovery passwords..." -ObjectType "BitLockerRecoveryPermission"

    # Parent container per computer, with a count for the row. The pattern strips exactly
    # one RDN, and an escaped comma inside it (CN=PC\, Lab) does not end it.
    $computersByContainer = @{}
    foreach ($computer in @(Get-DomainComputer -Properties 'distinguishedName' @ConnectionParams)) {
        $computerDN = [string]$computer.distinguishedName
        if ($computerDN -match '^[A-Za-z][A-Za-z0-9-]*=(?:[^,\\]|\\.)+,(.+)$') {
            $containerDN = $Matches[1]
            if (-not $computersByContainer.ContainsKey($containerDN)) { $computersByContainer[$containerDN] = 0 }
            $computersByContainer[$containerDN]++
        }
    }

    if ($computersByContainer.Count -eq 0) {
        Show-Line "No computer object found - there is no container whose recovery passwords could be delegated" -Class Note
        return
    }

    # Info is what Get-OUPermissions assigns a privileged principal.
    $allowedSeverities = if ($IncludePrivileged) { @('Critical', 'High', 'Medium', 'Info') } else { @('Critical', 'High', 'Medium') }

    # Per principal, and within it per container - see the description for why the halves
    # are not combined across containers.
    $byPrincipal = @{}

    # Counted rather than assumed, so the closing note only claims privileged holders when
    # there are some.
    $suppressedPrivileged = @{}

    # A container whose descriptor could not be read produces no finding either, and must
    # not be counted as examined.
    $unreadContainers = @()

    $totalContainers = $computersByContainer.Keys.Count
    $currentIndex = 0

    foreach ($containerDN in @($computersByContainer.Keys)) {
        $currentIndex++
        if ($totalContainers -gt $Script:ProgressThreshold) {
            Show-Progress -Activity "Checking BitLocker recovery delegations" -Current $currentIndex -Total $totalContainers -ObjectName $containerDN
        }

        try {
            $perms = Get-OUPermissions -DistinguishedName $containerDN -CheckType 'BitLocker'
        }
        catch {
            $unreadContainers += $containerDN
            Write-Log "[Get-BitLockerRecoveryKeyAccess] Failed to read permissions for '$containerDN': $($_.Exception.Message)"
            continue
        }

        if (-not $perms -or $perms.Read -eq $false) { $unreadContainers += $containerDN }

        if (-not $perms -or -not $perms.Findings) { continue }

        foreach ($aclFinding in @($perms.Findings)) {
            $sid = [string]$aclFinding.SID
            if ([string]::IsNullOrEmpty($sid)) { continue }

            if ($aclFinding.Severity -notin $allowedSeverities) {
                if ($aclFinding.Severity -eq 'Info') { $suppressedPrivileged[$sid] = $true }
                continue
            }

            if (-not $byPrincipal.ContainsKey($sid)) {
                $byPrincipal[$sid] = [PSCustomObject]@{
                    Principal    = $aclFinding.Principal
                    Containers   = @{}
                    IsPrivileged = ($aclFinding.Severity -eq 'Info')
                }
            }

            $containers = $byPrincipal[$sid].Containers
            if (-not $containers.ContainsKey($containerDN)) {
                $containers[$containerDN] = [PSCustomObject]@{
                    Read          = $false
                    ControlAccess = $false
                    Rights        = New-Object System.Collections.Generic.List[string]
                }
            }

            $state = $containers[$containerDN]
            if ($aclFinding.GrantsRead -eq $true)          { $state.Read = $true }
            if ($aclFinding.GrantsControlAccess -eq $true) { $state.ControlAccess = $true }
            if (-not $state.Rights.Contains([string]$aclFinding.Right)) {
                $state.Rights.Add([string]$aclFinding.Right)
            }
        }
    }
    if ($totalContainers -gt $Script:ProgressThreshold) {
        Show-Progress -Activity "Checking BitLocker recovery delegations" -Completed
    }

    $readContainers = $totalContainers - @($unreadContainers).Count
    $coverageIncomplete = Show-OUPermissionsCoverageNote -UnreadOUs $unreadContainers -TotalOUs $totalContainers

    # The schema is asked only when a read without control access needs judging.
    $needsSchema = $false
    foreach ($principalEntry in $byPrincipal.Values) {
        foreach ($state in $principalEntry.Containers.Values) {
            if ($state.Read -and -not $state.ControlAccess) { $needsSchema = $true }
        }
    }
    $confidential = $null
    if ($needsSchema) {
        $confidential = (Get-BitLockerRecoveryConfidentiality @ConnectionParams).Confidential
    }

    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($sid in @($byPrincipal.Keys | Sort-Object)) {
        $entry = $byPrincipal[$sid]

        # One verdict per container. Control access satisfies the stricter of the two schema
        # states, so with both halves present the flag does not enter into it - not even when
        # it could not be read. Read alone is tested with -eq $false rather than -not: $null
        # is falsy, and an unread schema must not count as "not confidential".
        $verdicts = @()
        foreach ($containerDN in @($entry.Containers.Keys | Sort-Object)) {
            $state = $entry.Containers[$containerDN]
            $verdict = $null
            if ($state.Read -and $state.ControlAccess) {
                $verdict = 'live'
            } elseif ($state.Read) {
                if ($confidential -eq $false) {
                    $verdict = 'live'
                } elseif ($confidential -eq $true) {
                    $verdict = 'dormant'
                } else {
                    $verdict = 'unknown'
                }
            }
            if ($verdict) {
                $verdicts += [PSCustomObject]@{ Container = $containerDN; Verdict = $verdict; Rights = $state.Rights }
            }
        }

        # Control access alone reads nothing: the recovery object grants no read to anybody
        # but Domain Admins and SYSTEM unless a delegation adds one.
        if ($verdicts.Count -eq 0) {
            Write-Log "[Get-BitLockerRecoveryKeyAccess] $($entry.Principal) holds control access but no read of the recovery objects - not listed"
            continue
        }

        $isLive    = @($verdicts | Where-Object { $_.Verdict -eq 'live' }).Count -gt 0
        $isUnknown = @($verdicts | Where-Object { $_.Verdict -eq 'unknown' }).Count -gt 0

        $readableText = 'No - blocked by the confidential flag on msFVE-RecoveryPassword, live the moment it is cleared'
        if ($isLive) {
            $readableText = 'Yes - the principal can read these recovery passwords today'
        } elseif ($isUnknown) {
            $readableText = 'Unknown - the schema could not be read, so whether the confidential flag blocks the read is open'
        }

        # A container whose verdict differs from the row's says so. When they all agree the
        # row already says it once.
        $mixed = @($verdicts | ForEach-Object { $_.Verdict } | Sort-Object -Unique).Count -gt 1
        $rights = New-Object System.Collections.Generic.List[string]
        $containerTexts = New-Object System.Collections.Generic.List[string]
        foreach ($item in $verdicts) {
            foreach ($right in $item.Rights) {
                if (-not $rights.Contains($right)) { $rights.Add($right) }
            }
            $suffix = ''
            if ($mixed -and $item.Verdict -eq 'dormant') { $suffix = ', blocked by the confidential flag' }
            if ($mixed -and $item.Verdict -eq 'unknown') { $suffix = ', not decidable - the schema could not be read' }
            $containerTexts.Add("$($item.Container) ($($computersByContainer[$item.Container]) computer(s)$suffix)")
        }

        # A privileged principal reads the recovery passwords anyway, so its right is expected
        # rather than wrong; a dormant or undecidable one is a warning. Everything else is live.
        $isFinding = (-not $entry.IsPrivileged) -and $isLive

        # PrivilegedPrincipal, not PrivilegedAccount: a pattern-less trigger on that name
        # (PRIVILEGED_ACCOUNT_AFFECTED) matches every value, "No" included, and would put a
        # red "privileged account affected" card on exactly the rows that are not.
        $row = [PSCustomObject]@{
            sAMAccountName      = $(if ($entry.Principal) { $entry.Principal } else { ConvertFrom-SID -SID $sid })
            objectSid           = $sid
            dangerousRights     = (@($rights) -join ', ')
            ReadableToday       = $readableText
            PrivilegedPrincipal = $(if ($entry.IsPrivileged) { 'Yes' } else { 'No' })
            affectedOUs         = @($containerTexts)
        }
        if (-not $isFinding) {
            $row | Add-Member -NotePropertyName 'dangerousRightsSeverity' -NotePropertyValue 'Hint' -Force
        }
        $row | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'BitLockerRecoveryPermission' -Force
        $row | Add-Member -NotePropertyName '_IsFinding' -NotePropertyValue $isFinding -Force

        $rows.Add($row)
    }

    if ($rows.Count -eq 0) {
        # "Nobody" and "nobody except the principals filtered out" are different statements.
        if ($suppressedPrivileged.Count -gt 0) {
            Show-Line ("No non-privileged principal holds a delegated read of the BitLocker recovery passwords, but " +
                       "$($suppressedPrivileged.Count) privileged one(s) hold a right on them - use -IncludePrivileged to see them") -Class Note
        } elseif ($readContainers -le 0) {
            Show-Line ("The delegations on the $totalContainers container(s) holding computers were not evaluated - " +
                       "no security descriptor could be read") -Class Note
        } else {
            $delegationClass = 'Secure'
            if ($coverageIncomplete) { $delegationClass = 'Note' }
            Show-Line ("No principal holds a delegated read of the BitLocker recovery passwords on the $readContainers " +
                       "container(s) holding computers") -Class $delegationClass
        }
        return
    }

    $findingRows = @($rows | Where-Object { $_._IsFinding })
    $hintRows    = @($rows | Where-Object { -not $_._IsFinding })

    if ($findingRows.Count -gt 0) {
        Show-Line ("Found $($findingRows.Count) non-privileged principal(s) who can read BitLocker recovery " +
                   "passwords") -Class Finding -FindingId 'BITLOCKER_RECOVERY_DELEGATED'
        foreach ($row in $findingRows) { Show-Object $row -Class Finding }
    }

    if ($hintRows.Count -gt 0) {
        Show-Line ("Found $($hintRows.Count) further delegated read(s) of the BitLocker recovery passwords that " +
                   "do not work today or belong to a privileged principal") -Class Hint -FindingId 'BITLOCKER_RECOVERY_DELEGATED'
        foreach ($row in $hintRows) { Show-Object $row -Class Hint }
    }

    if ($suppressedPrivileged.Count -gt 0) {
        Show-Line ("$($suppressedPrivileged.Count) privileged principal(s) hold a right on the recovery passwords " +
                   "and are not listed - they read them regardless. Use -IncludePrivileged to see them") -Class Note
    }
}

<#
.SYNOPSIS
    Reads whether msFVE-RecoveryPassword is marked confidential in the schema.

.DESCRIPTION
    searchFlags bit 7 - fCONFIDENTIAL, value 128. The schema ships the attribute with
    searchFlags 0x298, the flag included (learn.microsoft.com, adschema), so a reader needs
    CONTROL_ACCESS as well as READ_PROPERTY. The flag can be cleared, and a cleared flag turns
    every plain read of a recovery object into a read of its recovery password.

    Three-valued on purpose: $null when the schema could not be read, which the caller must
    report as neither verdict. An attribute whose searchFlags are absent counts as not
    confidential - absent is 0, and assuming the stricter state would report an exposed forest
    as protected.

.PARAMETER Domain
    Passed through to Get-DomainObject.

.PARAMETER Server
    Passed through to Get-DomainObject.

.PARAMETER Credential
    Passed through to Get-DomainObject.

.OUTPUTS
    [PSCustomObject] with Confidential - $true, $false, or $null when the schema could not be
    read.
#>
function Get-BitLockerRecoveryConfidentiality {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    $CredParams = @{}
    if ($Domain)     { $CredParams['Domain']     = $Domain }
    if ($Server)     { $CredParams['Server']     = $Server }
    if ($Credential) { $CredParams['Credential'] = $Credential }

    $unknown = [PSCustomObject]@{ Confidential = $null }

    $schemaDN = $null
    if ($Script:LDAPContext) { $schemaDN = $Script:LDAPContext.SchemaNamingContext }
    if ([string]::IsNullOrWhiteSpace($schemaDN)) {
        Write-Log "[Get-BitLockerRecoveryConfidentiality] No SchemaNamingContext - answer stays unknown"
        return $unknown
    }

    # cn as well as lDAPDisplayName: the schema object is ms-FVE-RecoveryPassword, the
    # attribute msFVE-RecoveryPassword.
    $filter = '(&(objectClass=attributeSchema)' +
              '(|(lDAPDisplayName=msFVE-RecoveryPassword)(cn=ms-FVE-RecoveryPassword)))'

    try {
        $attribute = @(Get-DomainObject -LDAPFilter $filter -SearchBase $schemaDN `
            -Properties 'lDAPDisplayName', 'cn', 'searchFlags' @CredParams)[0]
    }
    catch {
        Write-Log "[Get-BitLockerRecoveryConfidentiality] Schema query failed: $($_.Exception.Message)"
        return $unknown
    }

    if (-not $attribute) {
        Write-Log "[Get-BitLockerRecoveryConfidentiality] msFVE-RecoveryPassword not found in the schema"
        return $unknown
    }

    $flags = 0
    if ($null -ne $attribute.searchFlags) { $flags = [int]$attribute.searchFlags }
    return [PSCustomObject]@{ Confidential = (($flags -band 128) -ne 0) }
}
