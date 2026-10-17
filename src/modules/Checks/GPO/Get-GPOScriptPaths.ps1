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
    - Who may write a script that runs from outside the policy's own folder - NETLOGON,
      SYSVOL outside a GPO folder, a file share - read over SMB from the domain's own name
      and enabled computers of the domain (Set-GPOScriptWriteAccess)

    Requires SMB access to \\domain\SYSVOL.

    .PARAMETER OPSEC
    Connect to no host a policy names: the permissions of a script outside the policy
    store are then reported as not checked.

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
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeInactive,

        [Parameter(Mandatory=$false)]
        [switch]$OPSEC
    )

    begin {
        Write-Log "[Get-GPOScriptPaths] Starting check"
    }

    process {
        try {
            # Connection parameters only. -IncludeInactive and -OPSEC belong to this check and neither
            # callee below has a parameter by that name, so splatting $PSBoundParameters
            # failed to bind - a terminating error before any output, which looks like a
            # check that silently produced nothing.
            $connectionParams = @{}
            if ($Domain)     { $connectionParams['Domain']     = $Domain }
            if ($Server)     { $connectionParams['Server']     = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            $domainFQDN = $Script:LDAPContext.Domain
            $Script:_gpoScriptFindings = [System.Collections.ArrayList]::new()

            # The hosts and paths read for script permissions - see Get-UNCWriteAccess. Fresh
            # per run, cleared when the check ends.
            $Script:_uncWriteAccess = @{ Hosts = @{}; Paths = @{} }

            Show-SubHeader "Searching for GPO-deployed scripts..." -ObjectType "GPOScriptPath"

            $gpos = Get-DomainGPO @connectionParams

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
            $gpoPathMap = Get-GPOPathMap -GPO $gpos

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
                            $findings = Parse-ScriptIni -FilePath $file.FullName -GPOName $gpoName -GPOGUID $gpoGUID -GPOPath $gpoPathMap[([string]$gpoGUID).ToUpper()] -Context $context -IsPowerShell $isPowerShell

                            if ($findings) {
                                # $null-guarded, and three-valued. Get-GPOLinkage returns
                                # $null when the linkage could not be resolved at all, and
                                # calling .ContainsKey on that throws - inside a try/catch
                                # that logs and moves to the next file, so every finding was
                                # dropped and the check closed with "No scripts distributed
                                # via GPO". A transient LDAP failure therefore reported the
                                # quietest possible result as the truth.
                                #
                                # $null now means unresolved and @() means resolved-to-none;
                                # the LinkedOUs transformer renders the latter as "Not
                                # linked", and Get-GPOEffectiveStatus declines to judge the
                                # former rather than asserting the policy is linked nowhere.
                                $linkedOUs = $null
                                if ($null -ne $gpoLinkage) {
                                    $linkedOUs = @()
                                    if ($gpoLinkage.ContainsKey($gpoGUID)) {
                                        $linkedOUs = @($gpoLinkage[$gpoGUID])
                                    }
                                }

                                # Whether the GPO's half that carries this script is switched
                                # on at all. A startup script in a policy whose computer
                                # configuration is disabled used to read exactly like one
                                # that runs on every boot. Where it applies is LinkedOUs'
                                # subject and is not repeated here.
                                $gpoStatus = Get-GPOEffectiveStatus `
                                    -StatusEntry $gpoStatusMap[$gpoGUID] -Scope $context `
                                    -Link $linkedOUs

                                # "Not linked" is what the transformer makes of an empty list,
                                # and that would be a claim the failed lookup cannot support.
                                #
                                # Plain assignment, then an override. An "if" whose branch
                                # yields @() writes nothing to the output stream, so
                                # "$x = if (...) { ... } else { $empty }" lands $x as $null -
                                # and @() is precisely the value that means "linked nowhere".
                                $linkedOUsDisplay = $linkedOUs
                                if ($null -eq $linkedOUs) {
                                    $linkedOUsDisplay = 'Unknown - linkage could not be resolved'
                                }

                                # Whether those links put a domain controller in the
                                # policy's scope - a fact beside LinkedOUs, no verdict.
                                $gpoDCReach = Get-GPODomainControllerReach -Link $linkedOUs -GPOGUID $gpoGUID

                                foreach ($finding in $findings) {
                                    $finding | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $linkedOUsDisplay -Force
                                    $finding | Add-Member -NotePropertyName 'reachesDomainControllers' -NotePropertyValue $gpoDCReach -Force
                                    if ($gpoStatus) {
                                        $finding | Add-Member -NotePropertyName 'GPOStatus' -NotePropertyValue $gpoStatus -Force
                                    }
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
                # Who may write a script that runs from outside the policy store, where adPEAS
                # may connect - see Set-GPOScriptWriteAccess. Before the split below, which
                # reads the severities this sets.
                foreach ($finding in $scriptFindings) {
                    Set-GPOScriptWriteAccess -Finding $finding -OPSEC:$OPSEC
                }

                # A script named by a policy that is not linked or not enabled never runs.
                # Held back rather than dropped - see Show-GPOInactiveSummary. The scope
                # comes from the entry itself: a startup script depends on the computer
                # half, a logon script on the user half, and ExecutionContext already says
                # which.
                foreach ($finding in $scriptFindings) {
                    $finding | Add-Member -NotePropertyName '_ReachScope' `
                        -NotePropertyValue $(if ("$($finding.ScriptType)" -in @('Startup', 'Shutdown')) { 'Machine' } else { 'User' }) -Force
                }

                $split = Split-GPOFindingByReach -Finding $scriptFindings -GPOStatusMap $gpoStatusMap `
                    -GPOLinkage $gpoLinkage -ScopeProperty '_ReachScope'

                $shown = if ($IncludeInactive) { @($scriptFindings) } else { @($split.Active) }

                # Held-back policies first, then the headline for the active ones, then the
                # active ones - the "Found ..." line heads the finding objects, not the
                # dampening block.
                Show-GPOInactiveSummary -Unlinked $split.Unlinked -Disabled $split.Disabled `
                    -Dormant $split.Dormant -Listed:$IncludeInactive

                if (@($shown).Count -gt 0) {
                    Show-Line "Found $(@($shown).Count) script(s) distributed via GPO" -Class Hint
                } else {
                    Show-Line "No script is distributed by a policy that is linked and enabled" -Class Note
                }

                foreach ($finding in $shown) {
                    $finding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPOScriptPath' -Force

                    # This check announces everything as a hint and renders its rows in the
                    # default class, so a dormant one only needs the grey.
                    if (@($split.Inactive) -contains $finding) {
                        Show-Object $finding -Class Note
                    } else {
                        # The computed verdict decides the colour. Without it every script
                        # was printed at the default class, so a SYSTEM startup script
                        # pulled off a file share sat among the logon scripts in SYSVOL.
                        $scriptClass = if ($finding._Severity) { [string]$finding._Severity } else { 'Note' }
                        Show-Object $finding -Class $scriptClass
                    }
                }
            } else {
                # Logon scripts live in the GPO folders; an unreadable folder hides them
                # without a trace unless the coverage line names it.
                $null = Show-SYSVOLCoverageNote
                Show-Line "No scripts distributed via GPO" -Class Note
            }

        } catch {
            Write-Log "[Get-GPOScriptPaths] Error: $_" -Level Error
            Show-Line "Error during check - scripts deployed via GPO could not be evaluated: $_" -Class Finding
        } finally {
            $Script:_uncWriteAccess = $null
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

        # Optional: a GPO whose gPCFileSysPath the directory does not record yields an
        # empty string here, and an empty row is skipped rather than printed blank.
        [Parameter(Mandatory=$false)]
        [string]$GPOPath,

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

            # Hand-edited scripts.ini files quote paths that contain spaces. The quotes are
            # not part of the path, and leaving them on made an absolute path fail both
            # tests below, so it was rewritten as if it were relative and the extension
            # based language detection fell through to Unknown.
            $cmdLine = $cmdLine.Trim().Trim('"')

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

            # Where the script actually lives. A bare file name has been resolved into the
            # GPO's own Scripts folder above, so a path inside a Policies\{GUID} folder is
            # the policy store itself, and the GPO's permissions are what its folder's ACL
            # follows - the ones the GPO permission findings speak about. NETLOGON, and
            # SYSVOL outside a GPO folder, are not: that is the domain's scripts folder,
            # whose file permissions no GPO decides, and they used to be counted as the
            # policy store. Anything else is a file on a share or a local disk whose
            # permissions nobody here has seen.
            $pathIsInsidePolicyStore = ($cmdLine -match '(?i)\\Policies\\\{')
            $pathIsInSysvolShare = (-not $pathIsInsidePolicyStore) -and
                                   ($cmdLine -match '(?i)\\(SYSVOL|NETLOGON)\\')

            # And what that is worth. This check used to compute nothing: every script was
            # printed at the renderer's default class, and the only card a row could reach
            # was SCRIPTPATH_HARDCODED - a definition written about the scriptPath attribute
            # of a user account, which described the GPO's script as somebody's logon script
            # attribute being backdoored.
            #
            # NETLOGON is a hint under SYSTEM and a note otherwise: its default permissions
            # let administrators write, but they are not the GPO's and were not read.
            $scriptRisk = ''
            if ($pathIsInSysvolShare -and $runsAsSystem) {
                $scriptRisk = 'Runs as SYSTEM from NETLOGON or SYSVOL outside a GPO folder - the file permissions there decide who may change it, not the GPO permissions, and they were not checked'
            } elseif ($pathIsInSysvolShare) {
                $scriptRisk = 'Runs as the logged-on user from NETLOGON or SYSVOL outside a GPO folder - the file permissions there decide who may change it, not the GPO permissions, and they were not checked'
            } elseif (-not $pathIsInsidePolicyStore -and $runsAsSystem) {
                $scriptRisk = 'Runs as SYSTEM from a path outside the policy store - whoever may write that file executes code as SYSTEM on every machine in scope. The permissions of that path were not checked'
            } elseif (-not $pathIsInsidePolicyStore) {
                $scriptRisk = 'Runs as the logged-on user from a path outside the policy store - whoever may write that file executes code as every user in scope. The permissions of that path were not checked'
            } elseif ($runsAsSystem) {
                $scriptRisk = 'Runs as SYSTEM from the policy store, where the GPO permissions decide who may change it'
            } else {
                $scriptRisk = 'Runs as the logged-on user from the policy store, where the GPO permissions decide who may change it'
            }

            # A credential in the parameter line of a script that every machine or every user
            # runs, and that any authenticated user can read out of SYSVOL.
            $parameterCredential = ''
            if ($parameters -and $parameters -match '(?i)(^|[\s/-])(pass(word)?|pwd|secret|credential)\s*[:=]\s*\S|(?i)/user:\S+\s+\S') {
                $parameterCredential = 'The parameter line carries what looks like a credential, and every authenticated user can read this file out of SYSVOL'
            }

            $finding = [PSCustomObject]@{
                GPOName        = $GPOName
                GPOGUID        = $GPOGUID
                GPOPath        = $GPOPath
                # The .ini the entry was parsed from - not ScriptPath below, which is the
                # script that .ini points at.
                SourceFile     = Get-GPORelativePath -Path $FilePath
                ScriptType     = $scriptType
                ScriptPath     = $cmdLine
                Parameters     = $parameters
                FullCommand    = $fullCommand
                ScriptLanguage = $scriptLanguage
                ExecutionContext = $scriptRunContext
                RunsAsSystem   = $runsAsSystem
                HasUNCPath     = $hasUNCPath
                IsPowerShell   = $IsPowerShell
                InsidePolicyStore = $pathIsInsidePolicyStore
                scriptRisk     = $scriptRisk
                _Severity      = $(if ($pathIsInSysvolShare -and $runsAsSystem) { 'Hint' }
                                   elseif ($pathIsInSysvolShare) { 'Note' }
                                   elseif (-not $pathIsInsidePolicyStore -and $runsAsSystem) { 'Finding' }
                                   elseif (-not $pathIsInsidePolicyStore) { 'Hint' }
                                   else { 'Note' })
            }

            if ($parameterCredential) {
                $finding | Add-Member -NotePropertyName 'scriptParameterCredential' -NotePropertyValue $parameterCredential -Force
                $finding._Severity = 'Finding'
            }

            $findings += $finding
        }

        return $findings
    } catch {
        Write-Log "[Parse-ScriptIni] Error parsing $FilePath : $_"
        return $null
    }
}

<#
.SYNOPSIS
    Reads who may write a GPO script that runs from outside the policy store, and puts the
    answer into the script's verdict.

.DESCRIPTION
    Coverage item A9. A script in the policy's own Scripts folder follows the GPO's
    permissions, which the GPO permission checks report. One in NETLOGON, in SYSVOL outside
    a GPO folder or on a file share follows the NTFS permissions of the file and of the
    folder it is in, and Parse-ScriptIni could only say they were not checked.
    Get-UNCWriteAccess reads them where adPEAS may connect - the domain's own name and the
    enabled computers of the domain, never under -OPSEC - past the identity gates a GPO is
    judged by.

    Three outcomes:
      a principal beyond the administrators may write the script or its folder
        - a finding in either context, named in scriptPathPermissions: SYSTEM on every
          computer in scope, or every user in scope, administrators among them
      read in full, and only administrators and privileged accounts may write it
        - NETLOGON or SYSVOL: a note, those are the domain's administrators
        - another share: a hint, the administrators of that server decide what runs
      not read in full - the verdict Parse-ScriptIni wrote, with the reason

    A local path exists on each computer and is not read over the network; its verdict
    keeps Parse-ScriptIni's severity and says so. A credential in the parameter line stays
    a finding whatever the permissions say. The share permissions are not read - they apply
    on top of NTFS over the network and can only narrow what is reported.

.PARAMETER Finding
    One script as Parse-ScriptIni returns it.

.PARAMETER OPSEC
    Connect to nothing; the path is reported as not checked.
#>
function Set-GPOScriptWriteAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Finding,

        [Parameter(Mandatory = $false)]
        [switch]$OPSEC
    )

    if ($Finding.InsidePolicyStore) { return }

    $path = [string]$Finding.ScriptPath
    if ($path -notmatch '^\\\\[^\\]+\\[^\\]+') {
        if ($path -match '^[A-Za-z]:\\') {
            $Finding.scriptRisk = [string]$Finding.scriptRisk + ' - a local path exists on each computer and is not read over the network'
        }
        return
    }

    $inSysvolShare = ($path -match '(?i)\\(SYSVOL|NETLOGON)\\')
    $runsAs = 'the logged-on user'
    $reach = 'run code as every user in scope'
    if ([bool]$Finding.RunsAsSystem) {
        $runsAs = 'SYSTEM'
        $reach = 'run code as SYSTEM on every computer in scope'
    }
    $from = 'a path outside the policy store'
    if ($inSysvolShare) { $from = 'NETLOGON or SYSVOL outside a GPO folder' }

    $access = Get-UNCWriteAccess -Path @($path) -OPSEC:$OPSEC -Caller 'Get-GPOScriptPaths' -Runner 'the script'

    if (@($access.Writers).Count -gt 0) {
        $Finding | Add-Member -NotePropertyName 'scriptPathPermissions' -NotePropertyValue (@($access.Rows) -join "`n") -Force
        $Finding.scriptRisk = "Runs as $runsAs from $from - $(@($access.Writers) -join ', ') can change it by NTFS permission (see scriptPathPermissions), and so $reach. The share permissions, which can narrow this over the network, were not read"
        $Finding._Severity = 'Finding'
    } elseif (@($access.Unchecked).Count -gt 0) {
        $Finding.scriptRisk = [string]$Finding.scriptRisk + ', because ' + (@($access.Unchecked) -join '; ')
    } elseif ($inSysvolShare) {
        $Finding.scriptRisk = "Runs as $runsAs from $from - only the domain's administrators and privileged accounts may change it there"
        $Finding._Severity = 'Note'
    } else {
        $Finding.scriptRisk = "Runs as $runsAs from $from - only the administrators of that server and privileged accounts may change it, so they decide what runs"
        $Finding._Severity = 'Hint'
    }

    if ($Finding.PSObject.Properties['scriptParameterCredential']) { $Finding._Severity = 'Finding' }
}
