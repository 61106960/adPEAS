function Get-GPOScriptPaths {
    <#
    .SYNOPSIS
    Detects Logon/Logoff/Startup/Shutdown scripts distributed via Group Policy.

    .DESCRIPTION
    Analyzes Group Policy Objects for script configurations in scripts.ini and psscripts.ini.
    These scripts are manually configured by administrators and execute automatically:
    - Startup/Shutdown scripts run as SYSTEM (Machine context)
    - Logon/Logoff scripts run in user context

    Focuses on:
    - Scripts running as SYSTEM (startup/shutdown) from UNC or writable paths
    - Scripts executing from network shares (credential exposure)
    - PowerShell scripts configured via psscripts.ini

    Requires SMB access to \\domain\SYSVOL.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-GPOScriptPaths

    .EXAMPLE
    Get-GPOScriptPaths -Domain "contoso.com" -Credential (Get-Credential)

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
        Write-Log "[Get-GPOScriptPaths] Starting check"
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            $domainFQDN = $Script:LDAPContext.Domain
            $Script:_gpoScriptFindings = [System.Collections.ArrayList]::new()

            Show-SubHeader "Searching for GPO-deployed scripts..." -ObjectType "GPOScriptPath"

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

            # Track SYSVOL access status
            $Script:sysvolAccessible = $false

            # SYSVOL Access with Credential Support
            Invoke-SMBAccess -Description "Scanning GPO script configuration files" -ScriptBlock {
                $sysvolPath = "\\$($Script:LDAPContext.Server)\SYSVOL\$domainFQDN\Policies"

                if (-not (Test-Path $sysvolPath)) {
                    return
                }

                $Script:sysvolAccessible = $true

                # Use cached SYSVOL file listing (no redundant SMB directory traversal)
                $scriptFiles = @(Get-CachedSYSVOLFiles -Filter @("scripts.ini", "psscripts.ini"))

                if ($scriptFiles.Count -eq 0) {
                    Write-Log "[Get-GPOScriptPaths] No script configuration files found in SYSVOL"
                    return
                }

                Write-Log "[Get-GPOScriptPaths] Found $($scriptFiles.Count) script configuration file(s)"

                $totalFiles = @($scriptFiles).Count
                $currentIndex = 0
                foreach ($file in $scriptFiles) {
                    $currentIndex++
                    if ($totalFiles -gt $Script:ProgressThreshold) { Show-Progress -Activity "Scanning GPO script paths" -Current $currentIndex -Total $totalFiles -ObjectName $file.Name }
                    # Extract GPO GUID from path: ...\Policies\{GUID}\Machine\Scripts\...
                    if ($file.FullName -match '\\Policies\\(\{[^}]+\})\\') {
                        $gpoGUID = $Matches[1]
                        $gpoName = if ($gpoNameMap.ContainsKey($gpoGUID)) { $gpoNameMap[$gpoGUID] } else { $gpoGUID }

                        # Determine context from path
                        $context = if ($file.FullName -match '\\Machine\\') { 'Machine' } else { 'User' }
                        $isPowerShell = $file.Name -eq 'psscripts.ini'

                        try {
                            Write-Log "[Get-GPOScriptPaths] Reading: $($file.FullName)"
                            $findings = Parse-ScriptIni -FilePath $file.FullName -GPOName $gpoName -GPOGUID $gpoGUID -Context $context -IsPowerShell $isPowerShell

                            if ($findings) {
                                $linkedOUs = @()
                                if ($gpoLinkage.ContainsKey($gpoGUID)) {
                                    $linkedOUs = $gpoLinkage[$gpoGUID]
                                }

                                foreach ($finding in $findings) {
                                    $finding | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $linkedOUs -Force
                                    $finding | Add-Member -NotePropertyName 'LinkedOUCount' -NotePropertyValue $linkedOUs.Count -Force
                                }

                                [void]$Script:_gpoScriptFindings.AddRange(@($findings))
                            }
                        } catch {
                            Write-Log "[Get-GPOScriptPaths] Error parsing $($file.FullName): $_"
                        }
                    }
                }
                if ($totalFiles -gt $Script:ProgressThreshold) { Show-Progress -Activity "Scanning GPO script paths" -Completed }
            }

            # Retrieve results and clean up Script-scoped temp variables
            $scriptFindings = @($Script:_gpoScriptFindings)
            $sysvolAccessible = $Script:sysvolAccessible
            $Script:_gpoScriptFindings = $null
            $Script:sysvolAccessible = $null

            if (-not $sysvolAccessible) {
                if ((Test-SysvolAccessible) -eq $false) {
                    Show-Line "Skipped - SYSVOL not accessible" -Class Hint
                } else {
                    Show-Line "SYSVOL access failed - cannot analyze GPO scripts - SMB access failed (authentication/network issue)" -Class Finding
                }
                return
            }

            if ($scriptFindings.Count -gt 0) {
                Show-Line "Found $($scriptFindings.Count) script(s) distributed via GPO" -Class Hint

                foreach ($finding in $scriptFindings) {
                    $finding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPOScriptPath' -Force
                    Show-Object $finding
                }
            } else {
                Show-Line "No scripts distributed via GPO" -Class Note
            }

        } catch {
            Write-Log "[Get-GPOScriptPaths] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-GPOScriptPaths] Check completed"
    }
}

# Helper Function: Parse scripts.ini / psscripts.ini
function Parse-ScriptIni {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [Parameter(Mandatory=$true)]
        [string]$GPOName,

        [Parameter(Mandatory=$true)]
        [string]$GPOGUID,

        [Parameter(Mandatory=$true)]
        [string]$Context,

        [Parameter(Mandatory=$true)]
        [bool]$IsPowerShell
    )

    try {
        $content = Get-Content -Path $FilePath -ErrorAction Stop
        $findings = @()

        # scripts.ini format:
        # [Startup]       or [Shutdown] (Machine context)
        # [Logon]         or [Logoff]   (User context)
        # 0CmdLine=\\server\share\script.bat
        # 0Parameters=-param1 value1
        # [next section...]

        $currentSection = $null
        $scripts = @{}  # Key: "section_index", Value: @{CmdLine=...; Parameters=...}

        foreach ($line in $content) {
            $trimmed = $line.Trim()

            # Skip empty lines and comments
            if ([string]::IsNullOrEmpty($trimmed) -or $trimmed.StartsWith(';')) {
                continue
            }

            # Section header
            if ($trimmed -match '^\[(.+)\]$') {
                $currentSection = $Matches[1]
                continue
            }

            # Script entry: <index>CmdLine=<path> or <index>Parameters=<args>
            if ($currentSection -and $trimmed -match '^(\d+)(CmdLine|Parameters)\s*=\s*(.*)$') {
                $index = $Matches[1]
                $property = $Matches[2]
                $value = $Matches[3]

                $key = "${currentSection}_${index}"
                if (-not $scripts.ContainsKey($key)) {
                    $scripts[$key] = @{
                        Section = $currentSection
                        Index = $index
                        CmdLine = ''
                        Parameters = ''
                    }
                }
                $scripts[$key][$property] = $value
            }
        }

        # Process collected scripts
        foreach ($entry in $scripts.Values) {
            $cmdLine = $entry.CmdLine
            $parameters = $entry.Parameters
            $section = $entry.Section

            if ([string]::IsNullOrEmpty($cmdLine)) {
                continue
            }

            # Resolve relative paths to full SYSVOL path
            # scripts.ini lives in .../Policies/{GUID}/Machine|User/Scripts/Scripts.ini
            # Relative scripts are stored in .../Policies/{GUID}/Machine|User/Scripts/<Section>/<script>
            if ($cmdLine -notmatch '^\\\\' -and $cmdLine -notmatch '^[A-Za-z]:\\') {
                $scriptsDir = Split-Path $FilePath -Parent
                $cmdLine = Join-Path (Join-Path $scriptsDir $section) $cmdLine
            }

            $fullCommand = if ($parameters) { "$cmdLine $parameters" } else { $cmdLine }

            # Determine script type from section name
            $scriptType = switch ($section) {
                'Startup'  { 'Startup' }
                'Shutdown' { 'Shutdown' }
                'Logon'    { 'Logon' }
                'Logoff'   { 'Logoff' }
                default    { $section }
            }

            # Execution context: Machine startup/shutdown = SYSTEM
            $runsAsSystem = ($Context -eq 'Machine' -and $scriptType -in @('Startup', 'Shutdown'))
            $scriptRunContext = if ($runsAsSystem) { 'SYSTEM' } else { 'User' }

            # Detect UNC paths
            $hasUNCPath = $fullCommand -match '\\\\[^\\]+\\'

            # Detect script type from file extension (always extension-based, even for psscripts.ini)
            $scriptExtension = if ($cmdLine -match '\.(\w+)$') { $Matches[1].ToLower() } else { 'unknown' }
            $scriptLanguage = switch ($scriptExtension) {
                'ps1'  { 'PowerShell' }
                'bat'  { 'Batch' }
                'cmd'  { 'Batch' }
                'vbs'  { 'VBScript' }
                'vbe'  { 'VBScript (Encoded)' }
                'wsf'  { 'Windows Script' }
                'js'   { 'JScript' }
                default { if ($IsPowerShell) { 'PowerShell' } else { 'Unknown' } }
            }

            $finding = [PSCustomObject]@{
                GPOName        = $GPOName
                GPOGUID        = $GPOGUID
                ScriptType     = $scriptType
                ScriptPath     = $cmdLine
                Parameters     = $parameters
                FullCommand    = $fullCommand
                ScriptLanguage = $scriptLanguage
                ExecutionContext = $scriptRunContext
                RunsAsSystem   = $runsAsSystem
                HasUNCPath     = $hasUNCPath
                IsPowerShell   = $IsPowerShell
            }

            $findings += $finding
        }

        return $findings
    } catch {
        Write-Log "[Parse-ScriptIni] Error parsing $FilePath : $_"
        return $null
    }
}
