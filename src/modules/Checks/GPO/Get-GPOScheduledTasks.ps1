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
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeInactive
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
            # Connection parameters only. -IncludeInactive belongs to this check and
            # neither of the two callees below has a parameter by that name, so splatting
            # $PSBoundParameters failed to bind - a terminating error before the first line
            # of output, which showed up as a check that silently produced nothing.
            $connectionParams = @{}
            if ($Domain)     { $connectionParams['Domain']     = $Domain }
            if ($Server)     { $connectionParams['Server']     = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            $domainFQDN = $Script:LDAPContext.Domain
            $Script:_gpoScheduledTasks = [System.Collections.ArrayList]::new()

            Show-SubHeader "Searching for GPO scheduled tasks..." -ObjectType "GPOScheduledTask"

            $gpos = Get-DomainGPO @connectionParams

            if (-not $gpos) {
                Show-Line "No GPOs found in domain" -Class Note
                return
            }

            $gpoLinkage = Get-GPOLinkage

            # Which policies have a half switched off, indexed the way a SYSVOL path names
            # them. Get-DomainGPO decodes the flags attribute; nothing used to read it.
            $gpoStatusMap = Get-GPOStatusMap -GPO $gpos

            # Track SYSVOL access status
            $Script:sysvolAccessible = $false

            # Build GPO GUID to name mapping for later lookup
            $gpoNameMap = @{}
            foreach ($gpo in $gpos) {
                $gpoNameMap[$gpo.Name] = $gpo.DisplayName
            }
            $gpoPathMap = Get-GPOPathMap -GPO $gpos

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
                            $taskFindings = Parse-ScheduledTasksXML -FilePath $file.FullName -GPOName $gpoName -GPOGUID $gpoGUID -GPOPath $gpoPathMap[([string]$gpoGUID).ToUpper()]

                            if ($taskFindings) {
                                # $null-guarded, and three-valued. Get-GPOLinkage returns $null
                                # when the linkage could not be resolved, and .ContainsKey on
                                # that throws - inside a try/catch that logs and moves to the
                                # next file, so every task was dropped and the check closed
                                # with "No scheduled tasks distributed via GPO". A transient
                                # LDAP failure reported the quietest result as the truth.
                                $linkedOUs = $null
                                if ($null -ne $gpoLinkage) {
                                    $linkedOUs = @()
                                    if ($gpoLinkage.ContainsKey($gpoGUID)) {
                                        $linkedOUs = @($gpoLinkage[$gpoGUID])
                                    }
                                }
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

                                foreach ($task in $taskFindings) {
                                    # Set unconditionally, including when the list is empty:
                                    # the transformer turns that into an explicit "Not
                                    # linked" row, and a policy that runs nowhere is a
                                    # statement rather than an absence.
                                    $task | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $linkedOUsDisplay -Force

                                    # A task in a policy whose relevant half is switched off
                                    # does not run, and it used to read exactly like one that
                                    # does. The scope comes off the task itself: the file's
                                    # path decided it during parsing.
                                    $gpoStatus = Get-GPOEffectiveStatus `
                                        -StatusEntry $gpoStatusMap[$gpoGUID] `
                                        -Scope $(if ($task.Context -eq 'Machine') { 'Machine' } else { 'User' }) `
                                        -Link $linkedOUs
                                    if ($gpoStatus) {
                                        $task | Add-Member -NotePropertyName 'GPOStatus' -NotePropertyValue $gpoStatus -Force
                                    }
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
                # Most severe first, and the computed risk actually reaches the reader.
                # The whole severity analysis used to be discarded right before output:
                # a SYSTEM task running from a UNC path rendered exactly like a benign one
                # and the section was always announced in yellow.
                $severityRank = @{ 'Finding' = 0; 'Hint' = 1; 'Note' = 2 }
                $scheduledTasks = @($scheduledTasks | Sort-Object -Property `
                    @{ Expression = { if ($severityRank.ContainsKey([string]$_._Severity)) { $severityRank[[string]$_._Severity] } else { 9 } } }, `
                    @{ Expression = { $_.GPOName } })

                # A task defined by a policy that is not linked or not enabled is never
                # registered on any machine. Held back rather than dropped - see
                # Show-GPOInactiveSummary. The scope is Machine throughout: a GPP scheduled
                # task under User\ still registers the task on the computer the user logs
                # on to, and the Context property on the row says which half it came from.
                $split = Split-GPOFindingByReach -Finding $scheduledTasks -GPOStatusMap $gpoStatusMap `
                    -GPOLinkage $gpoLinkage -Scope 'Machine'

                $shown = if ($IncludeInactive) { @($scheduledTasks) } else { @($split.Active) }

                $hasFinding = @($shown | Where-Object { $_._Severity -eq 'Finding' }).Count -gt 0
                $headerClass = if ($hasFinding) { 'Finding' } else { 'Hint' }

                if (@($shown).Count -gt 0) {
                    Show-Line "Found $(@($shown).Count) scheduled task(s) distributed via GPO" -Class $headerClass
                } else {
                    Show-Line "No scheduled task is distributed by a policy that is linked and enabled" -Class Note
                }

                Show-GPOInactiveSummary -Unlinked $split.Unlinked -Disabled $split.Disabled -Listed:$IncludeInactive

                foreach ($task in $shown) {
                    # Grey whatever the severity analysis concluded: the class describes the
                    # task, the colour has to describe today's risk.
                    $taskClass = if (@($split.Inactive) -contains $task) {
                        'Note'
                    } elseif ($task._Severity) {
                        [string]$task._Severity
                    } else {
                        'Standard'
                    }
                    $taskRisk  = [string]$task._Risk

                    $task.PSObject.Properties.Remove('_Severity')
                    $task.PSObject.Properties.Remove('_Risk')

                    # Keep the reason as a visible attribute. It is the only thing that
                    # explains why one task is red and the next one is not.
                    if ($taskRisk) {
                        $task | Add-Member -NotePropertyName 'RiskReason' -NotePropertyValue $taskRisk -Force
                    }
                    $task | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPOScheduledTask' -Force
                    Show-Object $task -Class $taskClass
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
        [string]$GPOGUID,

        # Optional: a GPO whose gPCFileSysPath the directory does not record yields an
        # empty string here, and an empty row is skipped rather than printed blank.
        [Parameter(Mandatory=$false)]
        [string]$GPOPath
    )

    try {
        # Use XmlDocument.Load() to honor the XML encoding declaration / BOM.
        # Get-Content defaults to the ANSI code page in Windows PowerShell 5.1,
        # which mojibakes UTF-8 GPP XML (umlauts in task names / run-as accounts).
        $xmlContent = New-Object System.Xml.XmlDocument
        $xmlContent.Load($FilePath)
        $tasks = @()

        $context = if ($FilePath -match '\\Machine\\') { 'Machine' } else { 'User' }

        $taskNodes = $xmlContent.SelectNodes("//Task | //TaskV2 | //ImmediateTask | //ImmediateTaskV2")

        foreach ($taskNode in $taskNodes) {
            # GetAttribute, not property access: $node.name returns the XmlElement's own Name
            # member ("Properties") when the attribute is absent, so the fallback below was
            # unreachable and such a task was reported under the name "Properties".
            $taskNameAttribute = if ($taskNode.Properties) { [string]$taskNode.Properties.GetAttribute('name') } else { '' }
            $taskName = if (-not [string]::IsNullOrWhiteSpace($taskNameAttribute)) { $taskNameAttribute } else { "Unnamed Task" }
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
            #
            # The SID tests are the reliable half and come first. The name patterns are the
            # fallback for a Scheduled Tasks XML that carries a name instead, and every one
            # of them is anchored: 'LocalSystem' unanchored also matched an ordinary account
            # called svc-LocalSystemBackup, and '\\SYSTEM$' on its own would take any
            # domain account named SYSTEM for the machine account. Both would have filed a
            # user task as running with full machine rights.
            $isSystemAccount = $false
            if ($runAs -match '^S-1-5-18$' -or                           # SYSTEM SID directly
                $runAs -match '^(NT[ -]AUTHORITY|[^\\]+)\\SYSTEM$' -or    # DOMAIN\SYSTEM, any language
                $runAs -match '^SYSTEM$' -or                              # Just SYSTEM
                $runAs -match '^LocalSystem$' -or                         # LocalSystem
                $runAs -match '^S-1-5-19$' -or                            # LOCAL SERVICE
                $runAs -match '^(NT[ -]AUTHORITY|[^\\]+)\\LOCAL SERVICE$' -or
                $runAs -match '^S-1-5-20$' -or                            # NETWORK SERVICE
                $runAs -match '^(NT[ -]AUTHORITY|[^\\]+)\\NETWORK SERVICE$') {
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
                        # Try to resolve name to SID.
                        # ConvertTo-SID declares -Identity, not -Name. The wrong parameter name
                        # threw a binding error that the surrounding catch swallowed, so a task
                        # running as a named privileged account was never rated privileged.
                        $accountSID = ConvertTo-SID -Identity $runAs
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
                # The GUID arrived as a parameter from the start but was never written onto
                # the object, so a reader had the policy's display name and no way to find
                # the folder it lives in.
                GPOGUID    = $GPOGUID
                GPOPath    = $GPOPath
                SourceFile = Get-GPORelativePath -Path $FilePath
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
