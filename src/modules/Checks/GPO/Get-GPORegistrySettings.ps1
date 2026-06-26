function Get-GPORegistrySettings {
    <#
    .SYNOPSIS
    Detects security-relevant registry values deployed via Group Policy that enable attacks.

    .DESCRIPTION
    Analyzes Group Policy Objects for registry values that, when actively set, enable or
    facilitate credential theft, lateral movement, privilege escalation, or defense evasion.

    Both GPO registry delivery mechanisms are parsed from SYSVOL:
      - Administrative Templates -> Registry.pol  (PReg binary format)
      - Group Policy Preferences -> Registry.xml  (XML format)

    Matched values are defined centrally in adPEAS-RegistryKeys.ps1
    ($Script:DangerousRegistryKeys). Only POSITIVELY SET values are reported - absence of a
    hardening value is never reported as a finding, because GPO parsing cannot distinguish
    "not configured in this GPO" from "secure".

    Examples of detected settings: WDigest cleartext caching, the Zerologon/OneLogon
    VulnerableChannelAllowList, AlwaysInstallElevated, RDP Restricted Admin, UAC disabled,
    Point and Print (PrintNightmare), WSUS-over-HTTP, and explicitly disabled defenses.

    Note: this check sees only what is DEPLOYED via GPO. Values set locally/directly on a
    host (no Remote Registry) are out of scope by design.

    Requires SMB access to \\domain\SYSVOL.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-GPORegistrySettings

    .EXAMPLE
    Get-GPORegistrySettings -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: GPO
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
        Write-Log "[Get-GPORegistrySettings] Starting check"
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            $Script:_gpoRegMatches = [System.Collections.ArrayList]::new()

            Show-SubHeader "Searching for vulnerable registry settings deployed via GPO..." -ObjectType "GPORegistrySetting"

            $gpos = Get-DomainGPO @PSBoundParameters

            if (-not $gpos) {
                Show-Line "No GPOs found in domain" -Class Note
                return
            }

            $gpoLinkage = Get-GPOLinkage

            # Build GPO GUID to name mapping
            $gpoNameMap = @{}
            foreach ($gpo in $gpos) {
                $gpoNameMap[$gpo.Name] = $gpo.DisplayName
            }

            # Track SYSVOL access status (exception in Clear-SessionState - cleaned up inline below)
            $Script:sysvolAccessible = $false

            # SYSVOL Access with Credential Support
            Invoke-SMBAccess -Description "Scanning GPO registry configuration files" -ScriptBlock {
                $sysvolPath = "\\$($Script:LDAPContext.Server)\SYSVOL\$($Script:LDAPContext.Domain)\Policies"

                if (-not (Test-Path $sysvolPath)) {
                    return
                }

                $Script:sysvolAccessible = $true

                # Single cached SYSVOL listing for both delivery mechanisms
                $regFiles = @(Get-CachedSYSVOLFiles -Filter @("Registry.pol", "Registry.xml"))

                if ($regFiles.Count -eq 0) {
                    Write-Log "[Get-GPORegistrySettings] No Registry.pol/Registry.xml files found in SYSVOL"
                    return
                }

                Write-Log "[Get-GPORegistrySettings] Found $($regFiles.Count) registry configuration file(s)"

                $totalFiles = $regFiles.Count
                $currentIndex = 0
                foreach ($file in $regFiles) {
                    $currentIndex++
                    if ($totalFiles -gt $Script:ProgressThreshold) { Show-Progress -Activity "Scanning GPO registry settings" -Current $currentIndex -Total $totalFiles -ObjectName $file.Name }

                    # Extract GPO GUID from path: ...\Policies\{GUID}\...
                    if ($file.FullName -notmatch '\\Policies\\(\{[^}]+\})\\') {
                        continue
                    }
                    $gpoGUID = $Matches[1]
                    $gpoName = if ($gpoNameMap.ContainsKey($gpoGUID)) { $gpoNameMap[$gpoGUID] } else { $gpoGUID }

                    try {
                        $records = @()
                        if ($file.Name -ieq 'Registry.pol') {
                            # Machine\Registry.pol -> HKLM, User\Registry.pol -> HKCU
                            $hive = if ($file.FullName -match '\\Machine\\') { 'HKLM' } else { 'HKCU' }
                            $records = @(Parse-PRegRecords -PolFilePath $file.FullName -Hive $hive)
                            $source = 'Registry.pol'
                        } else {
                            $hive = 'HKLM/HKCU'
                            $records = @(Parse-RegistryXml -XmlFilePath $file.FullName)
                            $source = 'Registry.xml'
                        }
                        if ($records.Count -gt 0) {
                            Write-Log "[Get-GPORegistrySettings] Analyzing GPO '$gpoName' - $source ($hive): $($records.Count) registry value(s)"
                        }

                        foreach ($record in $records) {
                            $entry = Test-DangerousRegistryRecord -Record $record
                            if ($entry) {
                                [void]$Script:_gpoRegMatches.Add([PSCustomObject]@{
                                    GPOGUID = $gpoGUID
                                    GPOName = $gpoName
                                    Source  = $source
                                    Entry   = $entry
                                    Record  = $record
                                })
                            }
                        }
                    } catch {
                        Write-Log "[Get-GPORegistrySettings] Error parsing $($file.FullName): $_"
                    }
                }
                if ($totalFiles -gt $Script:ProgressThreshold) { Show-Progress -Activity "Scanning GPO registry settings" -Completed }
            }

            # Retrieve results and clean up Script-scoped temp variables
            $rawMatches = @($Script:_gpoRegMatches)
            $sysvolAccessible = $Script:sysvolAccessible
            $Script:_gpoRegMatches = $null
            $Script:sysvolAccessible = $null

            if (-not $sysvolAccessible) {
                if ((Test-SysvolAccessible) -eq $false) {
                    Show-Line "Skipped - SYSVOL not accessible" -Class Hint
                } else {
                    Show-Line "SYSVOL access failed - cannot analyze GPO registry settings - SMB access failed (authentication/network issue)" -Class Finding
                }
                return
            }

            # Resolve findings (handles AlwaysInstallElevated two-hive correlation)
            $findings = @(Resolve-RegistryFindings -RawMatches $rawMatches)

            if ($findings.Count -gt 0) {
                Show-Line "Found $($findings.Count) vulnerable registry setting(s) deployed via GPO" -Class Hint

                foreach ($finding in $findings) {
                    $linkedOUs = @()
                    if ($gpoLinkage.ContainsKey($finding.GPOGUID)) {
                        $linkedOUs = $gpoLinkage[$finding.GPOGUID]
                    }
                    if ($linkedOUs.Count -gt 0) {
                        $finding | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $linkedOUs -Force
                    }
                    $finding | Add-Member -NotePropertyName 'LinkedOUCount' -NotePropertyValue $linkedOUs.Count -Force
                    $finding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPORegistrySetting' -Force
                    Show-Object $finding
                }
            } else {
                Show-Line "No vulnerable registry settings deployed via GPO" -Class Note
            }

        } catch {
            Write-Log "[Get-GPORegistrySettings] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-GPORegistrySettings] Check completed"
    }
}

# =============================================================================
# Helper: Evaluate one normalized registry record against the dangerous-key table
# =============================================================================
function Test-DangerousRegistryRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Record
    )

    $recKey = ($Record.Key -replace '^\\+', '').TrimEnd('\').ToLower()
    $recValueName = [string]$Record.ValueName
    $recHive = [string]$Record.Hive

    foreach ($entry in $Script:DangerousRegistryKeys) {
        if ($entry.Hive -ne $recHive) { continue }
        if (($entry.Key -replace '^\\+', '').TrimEnd('\').ToLower() -ne $recKey) { continue }
        if ($entry.ValueName.ToLower() -ne $recValueName.ToLower()) { continue }

        # Value name matched - now evaluate the dangerous condition
        $isMatch = $false
        switch ($entry.Match) {
            'Present' {
                $isMatch = $true
            }
            'Equals' {
                if ($null -ne $Record.ValueInt) { $isMatch = ([int64]$Record.ValueInt -eq [int64]$entry.MatchValue) }
            }
            'LessOrEqual' {
                if ($null -ne $Record.ValueInt) { $isMatch = ([int64]$Record.ValueInt -le [int64]$entry.MatchValue) }
            }
            'GreaterThan' {
                if ($null -ne $Record.ValueInt) { $isMatch = ([int64]$Record.ValueInt -gt [int64]$entry.MatchValue) }
            }
            'UrlNotHttps' {
                $sv = [string]$Record.ValueString
                if ($sv -and $sv.Trim().ToLower().StartsWith('http://')) { $isMatch = $true }
            }
        }

        if ($isMatch) {
            return $entry
        }
    }

    return $null
}

# =============================================================================
# Helper: Build display findings from raw matches (AlwaysInstallElevated correlation)
# =============================================================================
function Resolve-RegistryFindings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [array]$RawMatches
    )

    $findings = @()
    $aieMatches = @()

    foreach ($m in $RawMatches) {
        if ($m.Entry.Id -eq 'AIE_HKLM' -or $m.Entry.Id -eq 'AIE_HKCU') {
            $aieMatches += $m
            continue
        }
        $findings += (New-RegistryFinding -RegMatch $m)
    }

    # AlwaysInstallElevated is only exploitable when BOTH HKLM and HKCU are set to 1
    # within the same GPO. Single-hive matches are suppressed.
    $aieByGpo = $aieMatches | Group-Object -Property GPOGUID
    foreach ($group in $aieByGpo) {
        $ids = @($group.Group | ForEach-Object { $_.Entry.Id } | Sort-Object -Unique)
        if ($ids -contains 'AIE_HKLM' -and $ids -contains 'AIE_HKCU') {
            $hklmMatch = @($group.Group | Where-Object { $_.Entry.Id -eq 'AIE_HKLM' })[0]
            $finding = New-RegistryFinding -RegMatch $hklmMatch
            $finding.RegistryKey = 'HKLM+HKCU\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
            $finding.ConfiguredValue = '1 (both HKLM and HKCU)'
            $findings += $finding
        } else {
            Write-Log "[Get-GPORegistrySettings] AlwaysInstallElevated set in only one hive for GPO $($group.Name) - not exploitable, skipping"
        }
    }

    return $findings
}

# =============================================================================
# Helper: Construct a display object for a single match
# =============================================================================
function New-RegistryFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $RegMatch
    )

    $entry = $RegMatch.Entry
    $record = $RegMatch.Record

    # Human-readable configured value
    $configured = '(value present)'
    if ($null -ne $record.ValueInt) {
        $configured = [string]$record.ValueInt
    } elseif ($record.ValueString) {
        $configured = [string]$record.ValueString
    }

    return [PSCustomObject][ordered]@{
        GPOName           = $RegMatch.GPOName
        Source            = $RegMatch.Source
        RegistryKey       = "$($entry.Hive)\$($entry.Key)\$($entry.ValueName)"
        ConfiguredValue   = $configured
        VulnerabilityName = $entry.VulnerabilityName
        RiskReason        = $entry.RiskReason
        Severity          = $entry.Severity
        GPOGUID           = $RegMatch.GPOGUID
    }
}

# =============================================================================
# Parser: Registry.pol (PReg binary format)
# Format: "PReg" + version(4) + records of [key;value;type;size;data]
# Strings are null-terminated UTF-16LE; separators ';' '[' ']' are UTF-16LE literals.
# Ref: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/registry-policy-file-format
# =============================================================================
function Parse-PRegRecords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$PolFilePath,

        [Parameter(Mandatory=$true)]
        [string]$Hive
    )

    $records = @()

    try {
        $bytes = [System.IO.File]::ReadAllBytes($PolFilePath)
        if ($bytes.Length -lt 8) { return $records }
        if ([System.Text.Encoding]::ASCII.GetString($bytes, 0, 4) -ne 'PReg') {
            Write-Log "[Read-PRegRecords] Invalid PReg header: $PolFilePath"
            return $records
        }

        $pos = 8  # skip signature(4) + version(4)
        $len = $bytes.Length

        # Local reader for null-terminated UTF-16LE strings; advances $pos past terminator
        $readString = {
            param([ref]$p)
            $start = $p.Value
            while (($p.Value + 1) -lt $len) {
                if ($bytes[$p.Value] -eq 0 -and $bytes[$p.Value + 1] -eq 0) { break }
                $p.Value += 2
            }
            $strLen = $p.Value - $start
            $s = ''
            if ($strLen -gt 0) { $s = [System.Text.Encoding]::Unicode.GetString($bytes, $start, $strLen) }
            $p.Value += 2  # consume null terminator
            return $s
        }

        $openBracket = 0x5B   # [
        $semicolon   = 0x3B   # ;

        while ($pos -lt $len) {
            # Find next '[' (0x5B 0x00)
            if (-not ($bytes[$pos] -eq $openBracket -and ($pos + 1) -lt $len -and $bytes[$pos + 1] -eq 0)) {
                $pos += 2
                continue
            }
            $pos += 2

            $ref = [ref]$pos
            $key = (& $readString $ref)
            # expect ';'
            if (-not ($pos -lt $len -and $bytes[$pos] -eq $semicolon)) { break }
            $pos += 2

            $valueName = (& $readString $ref)
            if (-not ($pos -lt $len -and $bytes[$pos] -eq $semicolon)) { break }
            $pos += 2

            if (($pos + 4) -gt $len) { break }
            $type = [System.BitConverter]::ToUInt32($bytes, $pos)
            $pos += 4
            if (-not ($pos -lt $len -and $bytes[$pos] -eq $semicolon)) { break }
            $pos += 2

            if (($pos + 4) -gt $len) { break }
            $size = [System.BitConverter]::ToUInt32($bytes, $pos)
            $pos += 4
            if (-not ($pos -lt $len -and $bytes[$pos] -eq $semicolon)) { break }
            $pos += 2

            if (($pos + $size) -gt $len) { break }
            $data = New-Object byte[] $size
            if ($size -gt 0) { [System.Array]::Copy($bytes, $pos, $data, 0, $size) }
            $pos += $size

            # Decode value depending on registry type
            $valueInt = $null
            $valueString = $null
            switch ($type) {
                4  { if ($data.Length -ge 4) { $valueInt = [System.BitConverter]::ToUInt32($data, 0) } }      # REG_DWORD
                5  { if ($data.Length -ge 4) { $valueInt = [System.BitConverter]::ToUInt32($data, 0) } }      # REG_DWORD_BIG_ENDIAN (rare)
                11 { if ($data.Length -ge 8) { $valueInt = [System.BitConverter]::ToUInt64($data, 0) } }      # REG_QWORD
                1  { $valueString = [System.Text.Encoding]::Unicode.GetString($data).TrimEnd([char]0) }       # REG_SZ
                2  { $valueString = [System.Text.Encoding]::Unicode.GetString($data).TrimEnd([char]0) }       # REG_EXPAND_SZ
                7  { $valueString = ([System.Text.Encoding]::Unicode.GetString($data).TrimEnd([char]0)) }     # REG_MULTI_SZ
            }

            $records += [PSCustomObject]@{
                Hive        = $Hive
                Key         = $key
                ValueName   = $valueName
                Type        = $type
                ValueInt    = $valueInt
                ValueString = $valueString
            }

            # expect ']' - if not present, the loop's resync will find the next '['
        }
    } catch {
        Write-Log "[Read-PRegRecords] Error parsing $PolFilePath : $_"
    }

    return $records
}

# =============================================================================
# Parser: Registry.xml (Group Policy Preferences format)
# =============================================================================
function Parse-RegistryXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$XmlFilePath
    )

    $records = @()

    try {
        [xml]$xml = Get-Content -Path $XmlFilePath -ErrorAction Stop

        $regNodes = $xml.SelectNodes("//Registry")
        if (-not $regNodes) { return $records }

        foreach ($node in $regNodes) {
            $props = $node.Properties
            if (-not $props) { continue }

            # Normalize hive
            $hiveRaw = [string]$props.hive
            $hive = $null
            switch -Wildcard ($hiveRaw.ToUpper()) {
                'HKEY_LOCAL_MACHINE*' { $hive = 'HKLM' }
                'HKLM*'               { $hive = 'HKLM' }
                'HKEY_CURRENT_USER*'  { $hive = 'HKCU' }
                'HKCU*'               { $hive = 'HKCU' }
                default               { $hive = $hiveRaw }
            }

            $type = [string]$props.type
            $rawValue = [string]$props.value

            $valueInt = $null
            $valueString = $null
            if ($type -match 'DWORD|QWORD') {
                # GPP stores DWORD/QWORD values as hexadecimal in the XML value attribute
                $parsed = $null
                if ($rawValue -match '^[0-9A-Fa-f]+$') {
                    try { $parsed = [System.Convert]::ToInt64($rawValue, 16) } catch { $parsed = $null }
                }
                if ($null -eq $parsed -and $rawValue -match '^\d+$') {
                    try { $parsed = [System.Convert]::ToInt64($rawValue, 10) } catch { $parsed = $null }
                }
                $valueInt = $parsed
            } else {
                $valueString = $rawValue
            }

            $records += [PSCustomObject]@{
                Hive        = $hive
                Key         = [string]$props.key
                ValueName   = [string]$props.name
                Type        = $type
                ValueInt    = $valueInt
                ValueString = $valueString
            }
        }
    } catch {
        Write-Log "[Read-RegistryXmlRecords] Error parsing $XmlFilePath : $_"
    }

    return $records
}
