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

    Related Checks:
    - Get-LAPSCredentialAccess (Creds): Which LAPS passwords can the current user read?

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-BitLockerRecoveryKeyAccess

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
        [System.Management.Automation.PSCredential]$Credential
    )

    begin {
        Write-Log "[Get-BitLockerRecoveryKeyAccess] Starting check"
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
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
                        $schemaResult = @(Get-DomainObject -LDAPFilter $schemaFilter -SearchBase $schemaDN -Properties 'cn' -ResultLimit 1 @PSBoundParameters)
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
                    $existsCheck = @(Get-DomainObject -LDAPFilter "(objectClass=msFVE-RecoveryInformation)" -Properties 'distinguishedName' -ResultLimit 1 @PSBoundParameters)
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

            $recoveryObjects = @(Get-DomainObject -LDAPFilter "(&(objectClass=msFVE-RecoveryInformation)(msFVE-RecoveryPassword=*))" -Properties $recoveryProperties -Raw @PSBoundParameters)

            Write-Log "[Get-BitLockerRecoveryKeyAccess] Found $($recoveryObjects.Count) readable recovery key(s)"

            # ===== Step 3: Output =====
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
                            $recoveryObject | Add-Member -NotePropertyName 'whenCreated' -NotePropertyValue ($escrowTime.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC') -Force
                        } catch {
                            # Leave raw value if parsing fails
                        }
                    }

                    $recoveryObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'BitLockerRecoveryKey' -Force
                    Show-Object $recoveryObject
                }
                if ($totalObjects -gt $Script:ProgressThreshold) { Show-Progress -Activity "Checking BitLocker recovery key access" -Completed }
            } else {
                Show-Line "No readable BitLocker recovery keys found" -Class "Secure"
            }

        } catch {
            Write-Log "[Get-BitLockerRecoveryKeyAccess] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-BitLockerRecoveryKeyAccess] Check completed"
    }
}
