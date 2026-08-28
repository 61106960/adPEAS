<#
.SYNOPSIS
    Extracts LAPS policy metadata (account name, password policy, backup/encryption settings)
    from Group Policy Objects.

.DESCRIPTION
    Parses GPO Registry.pol files to find LAPS settings, for both LAPS generations:
    - Legacy LAPS:    Software\Policies\Microsoft Services\AdmPwd
    - Windows LAPS:   Software\Microsoft\Windows\CurrentVersion\Policies\LAPS

    These GPO settings are readable independently of LAPS password read permissions - they
    disclose the managed account name and password policy even when the password itself is
    not accessible to the current user, and can reveal misconfigurations (e.g. encryption
    disabled, backup target disabled) before ever enumerating a single computer object.

.PARAMETER DomainController
    Domain Controller to query. Uses current domain if not specified.

.EXAMPLE
    Get-LAPSGPOConfig
    Returns: @{
        Legacy = @{ "Default Domain Policy" = @{ AdminAccountName = "Administrator"; PasswordLength = 14 } }
        Native = @{ "LAPS Custom" = @{ AdministratorAccountName = "LocalAdmin"; ADPasswordEncryptionEnabled = 1 } }
    }

.OUTPUTS
    Hashtable with two keys, 'Legacy' and 'Native', each a hashtable of GPO Name -> metadata
    hashtable (only the fields actually configured in that GPO are present).

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function Get-LAPSGPOConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$DomainController
    )

    begin {
        Write-Log "[Get-LAPSGPOConfig] Starting LAPS GPO analysis"
    }

    process {
        # Internal helper - caller must ensure LDAP connection exists
        # UNIFIED: Check for LdapConnection (works for both LDAP and LDAPS)
        if (-not $Script:LdapConnection) {
            Show-NoSessionError -Context "Get-LAPSGPOConfig"
            Write-Log "[Get-LAPSGPOConfig] No LDAP connection - returning null"
            return $null
        }

        try {

            # Get all GPOs to build GUID-to-Name mapping
            Write-Log "[Get-LAPSGPOConfig] Querying GPOs for LAPS settings"

            $GPOFilter = "(objectClass=groupPolicyContainer)"
            $GPOs = Invoke-LDAPSearch -Filter $GPOFilter -Properties @("displayName", "cn")

            $LAPSGPOSettings = @{ Legacy = @{}; Native = @{} }

            if (-not $GPOs -or $GPOs.Count -eq 0) {
                Write-Log "[Get-LAPSGPOConfig] No GPOs found"
                return $LAPSGPOSettings
            }

            # Build GPO GUID-to-Name mapping
            $gpoGuidToName = @{}
            foreach ($GPO in $GPOs) {
                if ($GPO.cn) {
                    $gpoGuidToName[$GPO.cn.ToUpper()] = $GPO.displayName
                }
            }

            Write-Log "[Get-LAPSGPOConfig] Built mapping for $($gpoGuidToName.Count) GPOs"

            $Script:lapsGPOResults = @{ Legacy = @{}; Native = @{} }

            # Uses the shared SYSVOL file cache (Get-CachedSYSVOLFiles, in Invoke-SMBAccess.ps1)
            # instead of a self-built path from gPCFileSysPath. That attribute stores the domain
            # DFS namespace path (\\domain\SYSVOL\...), which is a DIFFERENT SMB target than the
            # DC hostname (\\dc01.domain\SYSVOL\...) Invoke-SMBAccess actually authenticates
            # against - a client that can reach one may not be able to reach the other, and the
            # mismatch fails silently (empty result, no error). Get-CachedSYSVOLFiles also shares
            # its single SYSVOL walk with Get-GPORegistrySettings instead of scanning it twice.
            Invoke-SMBAccess -Description "Scanning GPO Registry.pol for LAPS settings" -ScriptBlock {
                try {
                    $polFiles = @(Get-CachedSYSVOLFiles -Filter "Registry.pol")

                    if ($polFiles.Count -eq 0) {
                        Write-Log "[Get-LAPSGPOConfig] No Registry.pol files found in SYSVOL"
                        return
                    }

                    Write-Log "[Get-LAPSGPOConfig] Found $($polFiles.Count) Registry.pol files"

                    foreach ($polFile in $polFiles) {
                        # Extract GPO GUID from path: \Policies\{GUID}\Machine\Registry.pol
                        if ($polFile.FullName -match '\\Policies\\(\{[^}]+\})\\') {
                            $gpoGuid = $Matches[1].ToUpper()
                            $gpoName = $gpoGuidToName[$gpoGuid]

                            if (-not $gpoName) {
                                Write-Log "[Get-LAPSGPOConfig] Unknown GPO GUID: $gpoGuid, skipping"
                                continue
                            }

                            Write-Log "[Get-LAPSGPOConfig] Checking GPO '$gpoName' at: $($polFile.FullName)"

                            try {
                                $Metadata = Get-LAPSMetadataFromPol -PolFilePath $polFile.FullName

                                # Carry the GUID so callers can resolve GPO links (Get-GPOLinkage)
                                if ($Metadata.Legacy) {
                                    $Metadata.Legacy['GPOGUID'] = $gpoGuid
                                    $Script:lapsGPOResults.Legacy[$gpoName] = $Metadata.Legacy
                                    Write-Log "[Get-LAPSGPOConfig] Found Legacy LAPS settings in GPO '$gpoName': $($Metadata.Legacy.Keys -join ', ')"
                                }
                                if ($Metadata.Native) {
                                    $Metadata.Native['GPOGUID'] = $gpoGuid
                                    $Script:lapsGPOResults.Native[$gpoName] = $Metadata.Native
                                    Write-Log "[Get-LAPSGPOConfig] Found Windows LAPS settings in GPO '$gpoName': $($Metadata.Native.Keys -join ', ')"
                                }
                            } catch {
                                Write-Log "[Get-LAPSGPOConfig] Failed to parse Registry.pol for GPO '$gpoName': $_"
                            }
                        }
                    }
                } catch {
                    Write-Log "[Get-LAPSGPOConfig] Error during recursive search: $_"
                }
            }

            $LAPSGPOSettings = $Script:lapsGPOResults

            Write-Log "[Get-LAPSGPOConfig] Found LAPS settings in $($LAPSGPOSettings.Legacy.Count) Legacy and $($LAPSGPOSettings.Native.Count) Native GPO(s)"
            return $LAPSGPOSettings

        } catch {
            Write-Log "[Get-LAPSGPOConfig] Error: $_"
            return @{ Legacy = @{}; Native = @{} }
        }
    }

    end {
        Write-Log "[Get-LAPSGPOConfig] LAPS GPO analysis completed"
    }
}

# Legacy LAPS fields tracked from Software\Policies\Microsoft Services\AdmPwd
$Script:LAPSLegacyMetadataFields = @('AdminAccountName', 'PasswordComplexity', 'PasswordLength', 'PasswordAgeDays')

# Windows LAPS fields tracked from Software\Microsoft\Windows\CurrentVersion\Policies\LAPS
# Reference: https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings
$Script:LAPSNativeMetadataFields = @(
    'AdministratorAccountName', 'PasswordComplexity', 'PasswordLength', 'PassphraseLength',
    'PasswordAgeDays', 'BackupDirectory', 'ADPasswordEncryptionEnabled',
    'ADPasswordEncryptionPrincipal', 'PasswordExpirationProtectionEnabled'
)

<#
.SYNOPSIS
    Extracts LAPS metadata (account name, password policy, backup/encryption settings) from a
    single Registry.pol file.

.DESCRIPTION
    Uses the shared binary PReg parser (Parse-PRegRecords, in Parse-RegistryPol.ps1) instead
    of text/regex searching - Registry.pol is a binary format where the Type/Size DWORD
    fields can contain arbitrary byte values, including embedded nulls that break a naive
    "search for the next null terminator" approach.

    Only fields explicitly set in this GPO are included - a field being absent means it falls
    back to the Windows LAPS default for that setting, not that it was set to zero/empty.
    Conversely, a present field can legitimately be 0 (e.g. ADPasswordEncryptionEnabled=0,
    BackupDirectory=0/Disabled) - both are security-relevant and must not be treated as "unset".

.PARAMETER PolFilePath
    Full path to Registry.pol file

.OUTPUTS
    Hashtable @{ Legacy = <hashtable|null>; Native = <hashtable|null> }
    Legacy/Native are $null when this GPO has no settings for that LAPS generation, otherwise
    a hashtable of FieldName -> value (string or int, whichever the registry type produced).

.NOTES
    Internal helper function
#>
function Get-LAPSMetadataFromPol {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$PolFilePath
    )

    $result = @{ Legacy = $null; Native = $null }

    try {
        $records = Parse-PRegRecords -PolFilePath $PolFilePath -Hive 'Machine'

        $legacyData = @{}
        $nativeData = @{}

        foreach ($record in $records) {
            # DWORD values land in ValueInt, REG_SZ/REG_EXPAND_SZ in ValueString - never
            # collapse 0/empty-string via truthiness, both are meaningful configured values
            $value = $null
            if ($null -ne $record.ValueString) { $value = $record.ValueString }
            elseif ($null -ne $record.ValueInt) { $value = $record.ValueInt }
            if ($null -eq $value) { continue }

            if ($record.Key -ieq 'Software\Policies\Microsoft Services\AdmPwd' -and $record.ValueName -in $Script:LAPSLegacyMetadataFields) {
                $legacyData[$record.ValueName] = $value
            }
            elseif ($record.Key -ieq 'Software\Microsoft\Windows\CurrentVersion\Policies\LAPS' -and $record.ValueName -in $Script:LAPSNativeMetadataFields) {
                $nativeData[$record.ValueName] = $value
            }
        }

        if ($legacyData.Count -gt 0) { $result.Legacy = $legacyData }
        if ($nativeData.Count -gt 0) { $result.Native = $nativeData }

        if (-not $result.Legacy -and -not $result.Native) {
            Write-Log "[Get-LAPSMetadataFromPol] No LAPS setting found in Registry.pol"
        }

        return $result

    } catch {
        Write-Log "[Get-LAPSMetadataFromPol] Error parsing Registry.pol: $_"
        return $result
    }
}
