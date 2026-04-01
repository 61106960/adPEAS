function Get-GPOScheduledTasks {
    <#
    .SYNOPSIS
    Detects Scheduled Tasks distributed via Group Policy Preferences.

    .DESCRIPTION
    Analyzes Group Policy Objects for Scheduled Tasks (ScheduledTasks.xml).
    All Scheduled Tasks distributed via GPO are manually configured by administrators.

    Focuses on security-critical configurations:
    - Tasks running as SYSTEM or privileged accounts
    - Tasks executing from UNC paths (credential theft vector)
    - Tasks executing from world-writable locations (privilege escalation)
    - Command injection vulnerabilities

    Requires SMB access to \\domain\SYSVOL.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-GPOScheduledTasks

    .EXAMPLE
    Get-GPOScheduledTasks -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: GPO
    Author: Alexander Sturz (@_61106960_)
    Reference:
    - Group Policy Preferences: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn581922(v=ws.11)
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
        Write-Log "[Get-GPOScheduledTasks] Starting check"

        # Risky paths (world-writable or commonly exploitable by standard users)
        $Script:RiskyPaths = @(
            'C:\Temp',
            'C:\Windows\Temp',
            '%TEMP%',
            '%TMP%',
            'C:\Users\Public',
            'C:\Users\Default',
            'C:\ProgramData',
            'C:\Windows\Tasks',
            'C:\Windows\System32\spool\drivers',
            'C:\Windows\debug',
            'C:\Windows\tracing',
            'C:\Windows\System32\LogFiles',
            'C:\Windows\Registration\CRMLog',
            'C:\Windows\Installer',
            'C:\Windows\Downloaded Program Files',
            'C:\inetpub\wwwroot',
            'C:\inetpub\temp',
            'C:\Scripts',
            'C:\PerfLogs'
        )
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            $domainFQDN = $Script:LDAPContext.Domain
            $Script:_gpoScheduledTasks = [System.Collections.ArrayList]::new()

            Show-SubHeader "Searching for GPO scheduled tasks..." -ObjectType "GPOScheduledTask"

            $gpos = Get-DomainGPO @PSBoundParameters

            if (-not $gpos) {
                Show-Line "No GPOs found in domain" -Class Note
                return
            }

            $gpoLinkage = Get-GPOLinkage

            # Track SYSVOL access status
            $Script:sysvolAccessible = $false

            # Build GPO GUID to name mapping for later lookup
            $gpoNameMap = @{}
            foreach ($gpo in $gpos) {
                $gpoNameMap[$gpo.Name] = $gpo.DisplayName
            }

            # SYSVOL Access with Credential Support
            Invoke-SMBAccess -Description "Scanning GPO ScheduledTasks.xml files" -ScriptBlock {
                $sysvolPath = "\\$($Script:LDAPContext.Server)\SYSVOL\$domainFQDN\Policies"

                if (-not (Test-Path $sysvolPath)) {
                    return
                }

                $Script:sysvolAccessible = $true

                # Use cached SYSVOL file listing (no redundant SMB directory traversal)
                $scheduledTasksFiles = Get-CachedSYSVOLFiles -Filter "ScheduledTasks.xml"

                if (-not $scheduledTasksFiles) {
                    Write-Log "[Get-GPOScheduledTasks] No ScheduledTasks.xml files found in SYSVOL"
                    return
                }

                Write-Log "[Get-GPOScheduledTasks] Found $($scheduledTasksFiles.Count) ScheduledTasks.xml file(s)"

                $totalFiles = @($scheduledTasksFiles).Count
                $currentIndex = 0
                foreach ($file in $scheduledTasksFiles) {
                    $currentIndex++
                    if ($totalFiles -gt $Script:ProgressThreshold) { Show-Progress -Activity "Scanning GPO scheduled tasks" -Current $currentIndex -Total $totalFiles -ObjectName $file.Name }
                    # Extract GPO GUID from path: ...\Policies\{GUID}\Machine\...
                    if ($file.FullName -match '\\Policies\\(\{[^}]+\})\\') {
                        $gpoGUID = $Matches[1]
                        $gpoName = if ($gpoNameMap.ContainsKey($gpoGUID)) { $gpoNameMap[$gpoGUID] } else { $gpoGUID }

                        try {
                            Write-Log "[Get-GPOScheduledTasks] Reading: $($file.FullName)"
                            $taskFindings = Parse-ScheduledTasksXML -FilePath $file.FullName -GPOName $gpoName -GPOGUID $gpoGUID

                            if ($taskFindings) {
                                $linkedOUs = @()
                                if ($gpoLinkage.ContainsKey($gpoGUID)) {
                                    $linkedOUs = $gpoLinkage[$gpoGUID]
                                }

                                foreach ($task in $taskFindings) {
                                    # Only add LinkedOUs if not empty (prevents rendering issues with empty arrays)
                                    if ($linkedOUs.Count -gt 0) {
                                        $task | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $linkedOUs -Force
                                    }
                                    $task | Add-Member -NotePropertyName 'LinkedOUCount' -NotePropertyValue $linkedOUs.Count -Force
                                }

                                [void]$Script:_gpoScheduledTasks.AddRange(@($taskFindings))
                            }
                        } catch {
                            Write-Log "[Get-GPOScheduledTasks] Error parsing $($file.FullName): $_"
                        }
                    }
                }
                if ($totalFiles -gt $Script:ProgressThreshold) { Show-Progress -Activity "Scanning GPO scheduled tasks" -Completed }
            }

            # Retrieve results and clean up Script-scoped temp variables
            $scheduledTasks = @($Script:_gpoScheduledTasks)
            $sysvolAccessible = $Script:sysvolAccessible
            $Script:_gpoScheduledTasks = $null
            $Script:sysvolAccessible = $null

            if (-not $sysvolAccessible) {
                if ((Test-SysvolAccessible) -eq $false) {
                    Show-Line "Skipped - SYSVOL not accessible" -Class Hint
                } else {
                    Show-Line "SYSVOL access failed - cannot analyze GPO scheduled tasks - SMB access failed (authentication/network issue)" -Class Finding
                }
                return
            }

            if ($scheduledTasks.Count -gt 0) {
                Show-Line "Found $($scheduledTasks.Count) scheduled task(s) distributed via GPO" -Class Hint

                foreach ($task in $scheduledTasks) {
                    $task.PSObject.Properties.Remove('_Severity')
                    $task.PSObject.Properties.Remove('_Risk')
                    $task | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPOScheduledTask' -Force
                    Show-Object $task
                }
            } else {
                Show-Line "No scheduled tasks distributed via GPO in $($gpos.Count) analyzed GPO(s)" -Class Note
            }

        } catch {
            Write-Log "[Get-GPOScheduledTasks] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-GPOScheduledTasks] Check completed"
    }
}

# Helper Function: Parse ScheduledTasks.xml
function Parse-ScheduledTasksXML {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [Parameter(Mandatory=$true)]
        [string]$GPOName,

        [Parameter(Mandatory=$true)]
        [string]$GPOGUID
    )

    try {
        [xml]$xmlContent = Get-Content -Path $FilePath -ErrorAction Stop
        $tasks = @()

        $context = if ($FilePath -match '\\Machine\\') { 'Machine' } else { 'User' }

        $taskNodes = $xmlContent.SelectNodes("//Task | //TaskV2 | //ImmediateTask | //ImmediateTaskV2")

        foreach ($taskNode in $taskNodes) {
            $taskName = if ($taskNode.Properties.name) { $taskNode.Properties.name } else { "Unnamed Task" }
            $runAs = if ($taskNode.Properties.runAs) { $taskNode.Properties.runAs } else { "Unknown" }
            $action = if ($taskNode.Properties.action) { $taskNode.Properties.action } else { "Unknown" }

            $command = ""
            $arguments = ""

            if ($taskNode.Properties.Task) {
                $taskXml = $taskNode.Properties.Task

                if ($taskXml.Actions) {
                    $execAction = $taskXml.Actions.Exec
                    if ($execAction) {
                        $command = if ($execAction.Command) { $execAction.Command } else { "" }
                        $arguments = if ($execAction.Arguments) { $execAction.Arguments } else { "" }
                    }
                }
            }

            if ([string]::IsNullOrEmpty($command)) {
                $command = if ($taskNode.Properties.appName) { $taskNode.Properties.appName } else { "" }
                $arguments = if ($taskNode.Properties.args) { $taskNode.Properties.args } else { "" }
            }

            $fullCommand = if ($arguments) { "$command $arguments" } else { $command }

            if ([string]::IsNullOrEmpty($fullCommand)) {
                continue
            }

            # Security Analysis
            $severity = "Note"
            $risk = ""

            # Check for SYSTEM account (well-known SID S-1-5-18 or common string patterns)
            # These are language-independent system accounts
            $isSystemAccount = $false
            if ($runAs -match '^S-1-5-18$' -or                           # SYSTEM SID directly
                $runAs -match '\\SYSTEM$' -or                             # NT AUTHORITY\SYSTEM (any language)
                $runAs -match '^SYSTEM$' -or                              # Just SYSTEM
                $runAs -match 'LocalSystem' -or                           # LocalSystem
                $runAs -match '^S-1-5-19$' -or                            # LOCAL SERVICE
                $runAs -match '\\LOCAL SERVICE$' -or
                $runAs -match '^S-1-5-20$' -or                            # NETWORK SERVICE
                $runAs -match '\\NETWORK SERVICE$') {
                $isSystemAccount = $true
            }

            # Try to resolve the account name to SID, then check if privileged
            $isPrivilegedAccount = $false
            if (-not $isSystemAccount -and $runAs -ne "Unknown" -and -not [string]::IsNullOrEmpty($runAs)) {
                try {
                    # Try to resolve account name to SID
                    $accountSID = $null
                    if ($runAs -match '^S-1-') {
                        # Already a SID
                        $accountSID = $runAs
                    } else {
                        # Try to resolve name to SID
                        $accountSID = ConvertTo-SID -Name $runAs
                    }

                    if ($accountSID) {
                        # Check if account is in a privileged category
                        $category = (Test-IsPrivileged -Identity $accountSID).Category
                        $isPrivilegedAccount = $category -in @('Privileged', 'Operator')
                    }
                } catch {
                    Write-Log "[Parse-ScheduledTasksXML] Could not resolve account '$runAs' to SID: $_"
                }
            }

            $hasUNCPath = $fullCommand -match '\\\\[^\\]+\\'
            $hasRiskyPath = $false

            foreach ($riskyPath in $Script:RiskyPaths) {
                if ($fullCommand -match [regex]::Escape($riskyPath)) {
                    $hasRiskyPath = $true
                    break
                }
            }

            $hasUnquotedPath = ($command -match '\s' -and $command -notmatch '^".*"$')
            $isPowerShell = $command -match 'powershell|pwsh'
            $isScript = $command -match '\.(bat|cmd|vbs|vbe|ps1|wsf)$'

            # Severity Determination (using standard adPEAS severity values)
            if ($isSystemAccount -and $hasUNCPath) {
                $severity = "Finding"
                $risk = "Task runs as SYSTEM and uses UNC path - SMB credential relay attack vector"
            } elseif ($isSystemAccount -and $hasRiskyPath) {
                $severity = "Finding"
                $risk = "Task runs as SYSTEM from world-writable location - privilege escalation via file modification"
            } elseif ($isSystemAccount -and $isScript) {
                $severity = "Finding"
                $risk = "Task runs script as SYSTEM - check if script is modifiable"
            } elseif ($isSystemAccount -and $isPowerShell) {
                $severity = "Finding"
                $risk = "Task runs PowerShell as SYSTEM - check command for injection vulnerabilities"
            } elseif ($isPrivilegedAccount) {
                $severity = "Finding"
                $risk = "Task runs as privileged account"
            } elseif ($hasUNCPath) {
                $severity = "Hint"
                $risk = "Task uses UNC path - potential SMB credential exposure"
            } elseif ($hasUnquotedPath) {
                $severity = "Hint"
                $risk = "Unquoted path with spaces - potential command injection"
            } elseif ($isSystemAccount) {
                $severity = "Hint"
                $risk = "Task runs as SYSTEM"
            }

            $trigger = "Unknown"
            if ($taskNode.Properties.Task.Triggers) {
                $triggers = $taskNode.Properties.Task.Triggers
                if ($triggers.LogonTrigger) {
                    $trigger = "At Logon"
                } elseif ($triggers.BootTrigger) {
                    $trigger = "At Startup"
                } elseif ($triggers.TimeTrigger) {
                    $trigger = "Scheduled (Time-based)"
                } elseif ($triggers.CalendarTrigger) {
                    $trigger = "Scheduled (Calendar)"
                }
            }

            # Build display object with only user-relevant properties
            # Internal analysis flags (Is*/Has*) are used above for severity but not displayed
            # _Severity and _Risk are internal transport properties (removed before Show-Object)
            $taskProps = [ordered]@{
                GPOName    = $GPOName
                TaskName   = $taskName
                Command    = $fullCommand
                RunAs      = $runAs
                Context    = $context
                Action     = $action
                Trigger    = $trigger
                _Severity  = $severity
                _Risk      = $risk
            }

            $task = [PSCustomObject]$taskProps

            $tasks += $task
        }

        return $tasks
    } catch {
        Write-Log "[Parse-ScheduledTasksXML] Error parsing $FilePath : $_"
        return $null
    }
}
