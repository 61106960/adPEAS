<#
.SYNOPSIS
    Extracts LAPS Legacy AdminAccountName from Group Policy Objects.

.DESCRIPTION
    Parses GPO Registry.pol files to find LAPS Legacy configuration.
    Looks for: Software\Policies\Microsoft Services\AdmPwd\AdminAccountName

    Returns the configured admin account name, or "Administrator" (default) if not found.

.PARAMETER DomainController
    Domain Controller to query. Uses current domain if not specified.

.EXAMPLE
    Get-LAPSGPOConfig
    Returns: @{ "Default Domain Policy" = "Administrator"; "LAPS Custom" = "LocalAdmin" }

.OUTPUTS
    Hashtable with GPO Name as key and AdminAccountName as value

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
            $GPOs = Invoke-LDAPSearch -Filter $GPOFilter -Properties @("displayName", "gPCFileSysPath", "cn")

            $LAPSGPOSettings = @{}

            if (-not $GPOs -or $GPOs.Count -eq 0) {
                Write-Log "[Get-LAPSGPOConfig] No GPOs found"
                return $LAPSGPOSettings
            }

            # Build GPO GUID-to-Name mapping and determine SYSVOL base path
            $gpoGuidToName = @{}
            $sysvolBasePath = $null

            foreach ($GPO in $GPOs) {
                $gpoName = $GPO.displayName
                $gpoPath = $GPO.gPCFileSysPath
                $gpoCN = $GPO.cn

                if ($gpoCN) {
                    $gpoGuidToName[$gpoCN.ToUpper()] = $gpoName
                }

                # Extract SYSVOL base path from first GPO that has one
                if (-not $sysvolBasePath -and $gpoPath) {
                    # Extract \\server\SYSVOL\domain\Policies from full path
                    if ($gpoPath -match '^(\\\\[^\\]+\\[^\\]+\\[^\\]+\\Policies)') {
                        $sysvolBasePath = $Matches[1]
                    }
                }
            }

            if (-not $sysvolBasePath) {
                Write-Log "[Get-LAPSGPOConfig] Could not determine SYSVOL path"
                return $LAPSGPOSettings
            }

            Write-Log "[Get-LAPSGPOConfig] Built mapping for $($gpoGuidToName.Count) GPOs"
            Write-Log "[Get-LAPSGPOConfig] SYSVOL base path: $sysvolBasePath"

            # Pre-resolve IP for hostname substitution when custom DNS is used
            $resolvedSmbIP = $null
            if ($Script:LDAPContext -and $Script:LDAPContext['DnsServer'] -and $Script:LDAPContext['ServerIP']) {
                $resolvedSmbIP = $Script:LDAPContext['ServerIP']
                Write-Log "[Get-LAPSGPOConfig] Using resolved IP for SMB access: $resolvedSmbIP"

                # Replace hostname with IP in SYSVOL path
                if ($sysvolBasePath -match '^\\\\([^\\]+)\\') {
                    $uncHost = $Matches[1]
                    $ipTest = $null
                    if (-not [System.Net.IPAddress]::TryParse($uncHost, [ref]$ipTest)) {
                        $sysvolBasePath = $sysvolBasePath -replace "^\\\\[^\\]+\\", "\\$resolvedSmbIP\"
                        Write-Log "[Get-LAPSGPOConfig] Converted UNC hostname to IP: $uncHost -> $resolvedSmbIP"
                    }
                }
            }

            $Script:lapsGPOResults = @{}

            # PERFORMANCE FIX: Single recursive search for all Registry.pol files
            # This avoids per-GPO SMB timeout delays by scanning SYSVOL once
            Invoke-SMBAccess -Description "Scanning GPO Registry.pol for LAPS settings" -ScriptBlock {
                Write-Log "[Get-LAPSGPOConfig] Starting recursive search for Registry.pol files in: $sysvolBasePath"

                try {
                    # Single recursive search - finds all Registry.pol files at once
                    $polFiles = Get-ChildItem -Path $sysvolBasePath -Filter "Registry.pol" -Recurse -ErrorAction SilentlyContinue

                    if (-not $polFiles -or $polFiles.Count -eq 0) {
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
                                $AdminAccountName = Parse-RegistryPolForLAPS -PolFilePath $polFile.FullName

                                if ($AdminAccountName) {
                                    $Script:lapsGPOResults[$gpoName] = $AdminAccountName
                                    Write-Log "[Get-LAPSGPOConfig] Found LAPS setting in GPO '$gpoName': AdminAccountName = '$AdminAccountName'"
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

            Write-Log "[Get-LAPSGPOConfig] Found LAPS settings in $($LAPSGPOSettings.Count) GPO(s)"
            return $LAPSGPOSettings

        } catch {
            Write-Log "[Get-LAPSGPOConfig] Error: $_"
            return @{}
        }
    }

    end {
        Write-Log "[Get-LAPSGPOConfig] LAPS GPO analysis completed"
    }
}

<#
.SYNOPSIS
    Parses a Registry.pol file for LAPS AdminAccountName setting.

.DESCRIPTION
    Parses GPO Registry.pol (PReg format) and searches for:
    Key: Software\Policies\Microsoft Services\AdmPwd
    Value: AdminAccountName

.PARAMETER PolFilePath
    Full path to Registry.pol file

.OUTPUTS
    String - AdminAccountName if found, null otherwise

.NOTES
    Internal helper function
    PReg format: https://docs.microsoft.com/en-us/previous-versions/windows/desktop/policy/registry-policy-file-format
#>
function Parse-RegistryPolForLAPS {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$PolFilePath
    )

    try {
        # Read file as bytes
        $FileBytes = [System.IO.File]::ReadAllBytes($PolFilePath)

        # Check PReg header (0x50, 0x52, 0x65, 0x67 = "PReg")
        if ($FileBytes.Length -lt 8) {
            Write-Log "[Parse-RegistryPolForLAPS] File too small to be valid Registry.pol"
            return $null
        }

        if ([System.Text.Encoding]::ASCII.GetString($FileBytes[0..3]) -ne "PReg") {
            Write-Log "[Parse-RegistryPolForLAPS] Invalid PReg header"
            return $null
        }

        # Convert to string for searching (Unicode)
        $FileString = [System.Text.Encoding]::Unicode.GetString($FileBytes)

        # Search for LAPS Legacy registry key pattern
        # Key: Software\Policies\Microsoft Services\AdmPwd
        # Value: AdminAccountName

        # Pattern 1: Exact LAPS path with AdminAccountName
        if ($FileString -match 'Software\\Policies\\Microsoft Services\\AdmPwd.*?AdminAccountName.*?\x00([^\x00]+)\x00') {
            $AdminAccountName = $Matches[1]
            Write-Log "[Parse-RegistryPolForLAPS] Found AdminAccountName: '$AdminAccountName'"
            return $AdminAccountName
        }

        # Pattern 2: More flexible search (in case of encoding issues)
        if ($FileString -match 'AdmPwd.*?AdminAccountName') {
            # Found the key, try to extract value
            $StartIndex = $FileString.IndexOf("AdminAccountName")
            if ($StartIndex -gt 0) {
                # Look for next string value after AdminAccountName (skip separators and type/size fields)
                # PReg format has: Value name, then ; then type (4 bytes) then ; then size (4 bytes) then ; then data
                $SubString = $FileString.Substring($StartIndex)

                # Find the data portion (after third semicolon)
                $SemicolonCount = 0
                $DataStart = -1
                for ($i = 0; $i -lt $SubString.Length; $i++) {
                    if ($SubString[$i] -eq ';') {
                        $SemicolonCount++
                        if ($SemicolonCount -eq 3) {
                            $DataStart = $i + 2  # Skip semicolon and next byte
                            break
                        }
                    }
                }

                if ($DataStart -gt 0 -and $DataStart -lt $SubString.Length) {
                    # Extract string until next ] or null terminator
                    $EndIndex = $SubString.IndexOf(']', $DataStart)
                    if ($EndIndex -eq -1) { $EndIndex = $SubString.IndexOf([char]0x5D, $DataStart) }
                    if ($EndIndex -eq -1) { $EndIndex = $SubString.Length }

                    $ValueString = $SubString.Substring($DataStart, $EndIndex - $DataStart)
                    # Clean up (remove null characters and control chars)
                    $ValueString = $ValueString -replace '[\x00-\x1F\x5D]', ''
                    $ValueString = $ValueString.Trim()

                    if ($ValueString.Length -gt 0 -and $ValueString.Length -lt 50) {
                        Write-Log "[Parse-RegistryPolForLAPS] Extracted AdminAccountName: '$ValueString'"
                        return $ValueString
                    }
                }
            }
        }

        Write-Log "[Parse-RegistryPolForLAPS] No LAPS AdminAccountName found in Registry.pol"
        return $null

    } catch {
        Write-Log "[Parse-RegistryPolForLAPS] Error parsing Registry.pol: $_"
        return $null
    }
}
