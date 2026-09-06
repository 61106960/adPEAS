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
    WSUS-over-HTTP, and explicitly disabled defenses. Point and Print has its own check
    (Get-GPOPointAndPrint) because its exploitability depends on a combination of values.

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

            # Which policies have a half switched off, indexed the way a SYSVOL path names
            # them. Get-DomainGPO decodes the flags attribute; nothing used to read it.
            $gpoStatusMap = Get-GPOStatusMap -GPO $gpos

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
                # Most severe first. Resolve-RegistryFindings appends the correlated
                # AlwaysInstallElevated findings after the loop, so without sorting a
                # Critical one landed behind the Medium ones in the console.
                $severityRank = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Info' = 4 }
                $findings = @($findings | Sort-Object -Property `
                    @{ Expression = { if ($severityRank.ContainsKey($_.Severity)) { $severityRank[$_.Severity] } else { 9 } } }, `
                    @{ Expression = { $_.GPOName } })

                # Red when at least one finding is a real vulnerability, yellow otherwise.
                # The announcement used to be Hint unconditionally, so even a Critical
                # AlwaysInstallElevated was introduced in yellow.
                $hasFinding = @($findings | Where-Object { $_.ConsoleClass -eq 'Finding' }).Count -gt 0
                $headerClass = if ($hasFinding) { 'Finding' } else { 'Hint' }
                Show-Line "Found $($findings.Count) vulnerable registry setting(s) deployed via GPO" -Class $headerClass

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

                    # A value in a policy whose relevant half is switched off, or that is
                    # linked nowhere, reaches no registry. The hive says which half: the
                    # Registry.pol under Machine writes HKLM, the one under User HKCU.
                    $ineffective = Get-GPOIneffectiveReason `
                        -StatusEntry $gpoStatusMap[$finding.GPOGUID] `
                        -Scope $(if ("$($finding.RegistryKey)" -like 'HKLM*') { 'Machine' } else { 'User' }) `
                        -LinkedOUCount $linkedOUs.Count
                    if ($ineffective) {
                        $finding | Add-Member -NotePropertyName 'GPONotEffective' -NotePropertyValue $ineffective -Force
                    }

                    # ConsoleClass is what the central table documents per entry. It was
                    # carried all the way here and then never used, so the Finding/Hint
                    # distinction the table defines had no effect on the output.
                    $rowClass = if ($finding.ConsoleClass) { [string]$finding.ConsoleClass } else { 'Standard' }
                    Show-Object $finding -Class $rowClass
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
            'BitSet' {
                # For a value that is a flag field rather than a setting, where one bit
                # among several carries the risk: Schannel's CertificateMappingMethods is
                # 0x1 subject/issuer, 0x2 issuer, 0x4 UPN, 0x8 subject, and only 0x4 is
                # ESC10. Equals would miss every combination that has the bit set next to
                # another one, which is how the value is normally written.
                if ($null -ne $Record.ValueInt) {
                    $isMatch = (([int64]$Record.ValueInt -band [int64]$entry.MatchValue) -eq [int64]$entry.MatchValue)
                }
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
        # Carried through so the caller can render the row in the class the central table
        # defines for it. Without it the field existed only in the table and nowhere else.
        ConsoleClass      = $entry.ConsoleClass
        GPOGUID           = $RegMatch.GPOGUID
    }
}


# =============================================================================
# Parsers (shared helpers, both also used by Get-GPOPointAndPrint)
#   Registry.pol (PReg binary) -> Parse-PRegRecords  in modules/Helpers/Parse-RegistryPol.ps1
#   Registry.xml (GPP XML)     -> Parse-RegistryXml  in modules/Helpers/Parse-RegistryXml.ps1
# =============================================================================
