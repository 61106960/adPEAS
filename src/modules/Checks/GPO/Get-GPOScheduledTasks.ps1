function Get-GPOScheduledTasks {
    <#
    .SYNOPSIS
    Detects Scheduled Tasks distributed via Group Policy Preferences.

    .DESCRIPTION
    Analyzes Group Policy Objects for Scheduled Tasks (ScheduledTasks.xml).
    All Scheduled Tasks distributed via GPO are manually configured by administrators.

    Focuses on security-critical configurations:
    - Tasks running as SYSTEM or privileged accounts
    - Tasks that name a UNC path (whoever can write the share controls what runs)
    - For a task with a UNC path that runs as SYSTEM or a privileged account: the NTFS
      permissions of the file and of the folder it is in, read over SMB where the host is
      a computer of the domain
    - Tasks starting code from a directory in which every user may change or add files
      by Windows default (the permissions on the hosts themselves are not read)
    - Every Exec action of a task, not only the first one

    Requires SMB access to \\domain\SYSVOL.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .PARAMETER IncludeInactive
    Also list the tasks of policies that are not linked or not enabled, and the task items
    that only delete their task.

    .PARAMETER OPSEC
    Make no connection to the hosts a task names. Without it, the check reads the NTFS
    permissions of a UNC path a task running as SYSTEM or a privileged account starts from -
    with the session's credentials, and only on a host that is an enabled computer of the
    domain, by the DNS name the directory records for it.

    .EXAMPLE
    Get-GPOScheduledTasks

    .EXAMPLE
    Get-GPOScheduledTasks -Domain "contoso.com" -Credential (Get-Credential)

    .EXAMPLE
    Get-GPOScheduledTasks -OPSEC

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
        [switch]$IncludeInactive,

        [Parameter(Mandatory=$false)]
        [switch]$OPSEC
    )

    begin {
        Write-Log "[Get-GPOScheduledTasks] Starting check"

        # Directories in which an ordinary user can put a file that a task then runs, as
        # measured with icacls on a default Windows 11 install (2026-10-16). Two different
        # rights, and which one it is decides what the attack looks like:
        #
        #   Change - files there are writable for every user, so the file the task starts
        #            can be replaced
        #   Add    - every user may create files but not change anyone else's, so the file
        #            the task starts stays intact; a DLL planted beside a program, or the
        #            file itself while it is missing, is what runs
        #
        # C:\Temp and C:\Scripts are not part of Windows: a folder an administrator creates
        # in the root of the system drive inherits "Authenticated Users: Modify" from it.
        # C:\ProgramData gives Users "create files / create folders" on itself and on every
        # subfolder that keeps inheriting, so a vendor directory below it is Add - not the
        # harmless case it is often taken for.
        #
        # Removed, because a default install gives ordinary users read access at most:
        # C:\Users\Default, C:\Windows\Installer, C:\Windows\System32\LogFiles,
        # C:\Windows\Downloaded Program Files, C:\PerfLogs and C:\inetpub. Of
        # C:\Windows\debug and C:\Windows\System32\spool\drivers only the subfolder named
        # below is writable. Listing them made a finding out of permissions nobody had
        # read - and for those directories, wrong ones.
        #
        # The first entry that matches decides the text, so Change comes before Add.
        # PerAccount marks the two variables that resolve into the profile of the account
        # the task runs as - see Parse-ScheduledTasksXML.
        $Script:RiskyPaths = @(
            @{ Path = 'C:\Temp';                                  Access = 'Change'; PerAccount = $false }
            @{ Path = 'C:\Scripts';                               Access = 'Change'; PerAccount = $false }
            @{ Path = 'C:\Users\Public';                          Access = 'Change'; PerAccount = $false }
            @{ Path = '%PUBLIC%';                                 Access = 'Change'; PerAccount = $false }
            @{ Path = 'C:\Windows\tracing';                       Access = 'Change'; PerAccount = $false }
            @{ Path = 'C:\Windows\Registration\CRMLog';           Access = 'Change'; PerAccount = $false }
            @{ Path = 'C:\Windows\debug\WIA';                     Access = 'Change'; PerAccount = $false }
            @{ Path = 'C:\Windows\System32\spool\drivers\color';  Access = 'Change'; PerAccount = $false }
            @{ Path = 'C:\ProgramData';                           Access = 'Add';    PerAccount = $false }
            @{ Path = '%ProgramData%';                            Access = 'Add';    PerAccount = $false }
            @{ Path = '%ALLUSERSPROFILE%';                        Access = 'Add';    PerAccount = $false }
            @{ Path = 'C:\Windows\Temp';                          Access = 'Add';    PerAccount = $false }
            @{ Path = '%SystemRoot%\Temp';                        Access = 'Add';    PerAccount = $false }
            @{ Path = '%windir%\Temp';                            Access = 'Add';    PerAccount = $false }
            @{ Path = 'C:\Windows\Tasks';                         Access = 'Add';    PerAccount = $false }
            @{ Path = '%TEMP%';                                   Access = 'Add';    PerAccount = $true }
            @{ Path = '%TMP%';                                    Access = 'Add';    PerAccount = $true }
        )
    }

    process {
        try {
            # Connection parameters only. -IncludeInactive and -OPSEC belong to this check
            # and neither of the two callees below has a parameter by those names, so splatting
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

            # What the hosts and UNC paths of this run turned out to be - see
            # Get-UNCWriteAccess. Fresh per run: permissions read in an earlier one may
            # have changed since.
            $Script:_uncWriteAccess = @{ Hosts = @{}; Paths = @{} }

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
                            $taskFindings = Parse-ScheduledTasksXML -FilePath $file.FullName -GPOName $gpoName -GPOGUID $gpoGUID -GPOPath $gpoPathMap[([string]$gpoGUID).ToUpper()] -OPSEC:$OPSEC

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

                                # Which of those links put a domain controller in the
                                # policy's scope - marked on LinkedOUs, no verdict.
                                $gpoDCReach = Get-GPODomainControllerReachDetail -Link $linkedOUs -GPOGUID $gpoGUID

                                foreach ($task in $taskFindings) {
                                    # Set unconditionally, including when the list is empty:
                                    # the transformer turns that into an explicit "Not
                                    # linked" row, and a policy that runs nowhere is a
                                    # statement rather than an absence.
                                    $task | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $linkedOUsDisplay -Force
                                    Add-GPODomainControllerReach -Object $task -Reach $gpoDCReach
                                    Add-GPOConditionRow -Object $task -GPOGUID $gpoGUID

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
                            Register-SYSVOLFileGap -Path $file.FullName -ErrorRecord $_
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
            $Script:_uncWriteAccess = $null

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
                # Show-GPOInactiveSummary.
                #
                # Per task, from the half it came out of - the same half the GPOStatus line
                # above is computed from. "Machine throughout" was the previous reading,
                # with the argument that a task defined under User\ still runs on the
                # computer the user logs on to. That is true of where it runs and says
                # nothing about whether it is created: a Preferences item in the User
                # configuration is applied during user policy processing, so with the user
                # half switched off the task never exists. The module therefore said
                # "User configuration disabled" on the row and counted the finding as
                # active in the same breath.
                # Items that delete their task run nothing - see Parse-ScheduledTasksXML. Held
                # back like a dormant policy, and listed with -IncludeInactive.
                $deleteTasks = @($scheduledTasks | Where-Object { $_.PSObject.Properties['_DeletesTask'] })
                $scheduledTasks = @($scheduledTasks | Where-Object { -not $_.PSObject.Properties['_DeletesTask'] })

                foreach ($task in $scheduledTasks) {
                    $task | Add-Member -NotePropertyName '_ReachScope' `
                        -NotePropertyValue $(if ("$($task.Context)" -eq 'Machine') { 'Machine' } else { 'User' }) -Force
                }

                $split = Split-GPOFindingByReach -Finding $scheduledTasks -GPOStatusMap $gpoStatusMap `
                    -GPOLinkage $gpoLinkage -ScopeProperty '_ReachScope'

                $shown = if ($IncludeInactive) { @($scheduledTasks) + @($deleteTasks) } else { @($split.Active) }

                $hasFinding = @($shown | Where-Object { $_._Severity -eq 'Finding' }).Count -gt 0
                $headerClass = if ($hasFinding) { 'Finding' } else { 'Hint' }

                # Held-back policies first, then the headline for the active ones, then the
                # active ones - the "Found ..." line heads the finding objects, not the
                # dampening block.
                Show-GPOInactiveSummary -Unlinked $split.Unlinked -Disabled $split.Disabled `
                    -Dormant $split.Dormant -Listed:$IncludeInactive

                if ($deleteTasks.Count -gt 0) {
                    if ($IncludeInactive) {
                        Show-Line "$($deleteTasks.Count) of the task items below delete their task - nothing runs" -Class Note
                    } else {
                        $deleteText = "$($deleteTasks.Count) task item(s) hidden - they delete their task, nothing runs"
                        # Invoke-adPEAS sets the context for each check; without one the
                        # switch is reachable, as in Show-GPOInactiveSummary.
                        if ($null -eq $Script:adPEAS_CurrentCheckContext) { $deleteText += ' (-IncludeInactive to list)' }
                        Show-Line "${deleteText}:" -Class Note
                        $deletePolicies = @(Get-GPOPolicySummary -Finding $deleteTasks).Count
                        $deletePolicyWord = if ($deletePolicies -eq 1) { 'policy' } else { 'policies' }
                        Show-GPOSuppressedGroup -Group 'Task items that delete their task' `
                            -Reason 'A Delete item removes the task it names from the computers in scope. The account and the program in it are never used.' `
                            -CountText "$deletePolicies $deletePolicyWord" -Policy $deleteTasks
                    }
                }

                if (@($shown).Count -gt 0) {
                    Show-Line "Found $(@($shown).Count) scheduled task(s) distributed via GPO" -Class $headerClass
                } else {
                    Show-Line "No scheduled task is distributed by a policy that is linked and enabled" -Class Note
                }

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
                # The count is the number of GPOs looked at, not the number that could be
                # read; the coverage line says which folders were skipped and which task
                # files could not be read or parsed.
                $null = Show-SYSVOLCoverageNote -FileFilter @('ScheduledTasks.xml')
                Show-Line "No scheduled tasks distributed via GPO in $($gpos.Count) analyzed GPO(s)" -Class Note
            }

        } catch {
            Write-Log "[Get-GPOScheduledTasks] Error: $_" -Level Error
            Show-Line "Error during check - scheduled tasks deployed via GPO could not be evaluated: $_" -Class Finding
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
        [string]$GPOPath,

        # Passed on to Get-UNCWriteAccess: connect to no host a task names.
        [Parameter(Mandatory=$false)]
        [switch]$OPSEC
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
            # C, R, U or D - Create, Replace, Update, Delete (MS-GPPREF 2.2.1.18) - and U where
            # the attribute is missing. The letter was printed as it stood, so "Action: D"
            # left the reader to work out that the item deletes the task.
            $actionCode = ([string]$taskNode.Properties.action).Trim()
            if (-not $actionCode) { $actionCode = 'U' }
            $action = switch ($actionCode) {
                'C'     { 'Create' }
                'R'     { 'Replace' }
                'U'     { 'Update' }
                'D'     { 'Delete' }
                default { $actionCode }
            }

            # Every Exec action, not the first one. A task may carry several, and
            # $taskXml.Actions.Exec then hands over all of them at once: taking .Command off
            # that collection yields an array, and "$command $arguments" glued the programs
            # and the argument lines into a single string that reads like one command line -
            # with the severity decided on the concatenation.
            $execPairs = @()

            if ($taskNode.Properties.Task) {
                $taskXml = $taskNode.Properties.Task

                if ($taskXml.Actions) {
                    foreach ($execAction in @($taskXml.Actions.Exec)) {
                        if (-not $execAction) { continue }
                        $execCommand = if ($execAction.Command) { [string]$execAction.Command } else { "" }
                        if ([string]::IsNullOrWhiteSpace($execCommand)) { continue }
                        $execPairs += [PSCustomObject]@{
                            Command   = $execCommand
                            Arguments = if ($execAction.Arguments) { [string]$execAction.Arguments } else { "" }
                        }
                    }
                }

                # The account the inner task names, where the Preferences wrapper says
                # nothing. A v2 task carries it in Principals/Principal/UserId, and without
                # this fallback runAs stayed "Unknown": a task running as SYSTEM through its
                # inner principal was rated neither as SYSTEM nor as privileged, and the row
                # said the account was unknown while the file names it.
                if (($runAs -eq 'Unknown' -or [string]::IsNullOrWhiteSpace($runAs)) -and $taskXml.Principals) {
                    $innerPrincipal = @($taskXml.Principals.Principal)[0]
                    if ($innerPrincipal) {
                        $innerId = [string]$innerPrincipal.UserId
                        if ([string]::IsNullOrWhiteSpace($innerId)) { $innerId = [string]$innerPrincipal.GroupId }
                        if (-not [string]::IsNullOrWhiteSpace($innerId)) { $runAs = $innerId }
                    }
                }
            }

            if (@($execPairs).Count -eq 0) {
                # The v1 shape, where the wrapper carries appName and args - two separate
                # fields there as well.
                $legacyCommand = if ($taskNode.Properties.appName) { [string]$taskNode.Properties.appName } else { "" }
                if (-not [string]::IsNullOrWhiteSpace($legacyCommand)) {
                    $execPairs += [PSCustomObject]@{
                        Command   = $legacyCommand
                        Arguments = if ($taskNode.Properties.args) { [string]$taskNode.Properties.args } else { "" }
                    }
                }
            }

            if (@($execPairs).Count -eq 0) {
                continue
            }

            # The joined line is what the path tests read and what the row prints. The
            # separator is the point: two actions are two programs, not one command with
            # arguments.
            $allCommands = @($execPairs | ForEach-Object { [string]$_.Command })
            $fullCommand = (@($execPairs | ForEach-Object {
                if ($_.Arguments) { "$($_.Command) $($_.Arguments)" } else { [string]$_.Command }
            }) -join ' ; ')

            # A Delete item removes the task it names from the computers in scope. Nothing
            # runs: the account and the program apply only to Create, Replace and Update
            # (MS-GPPREF 2.2.1.18). It was rated like a task that runs - "runs as SYSTEM and
            # uses UNC path", in red - and the share it names was connected to for nothing.
            # Handed back as a Note, marked, for the caller to hold back.
            if ($actionCode -eq 'D') {
                $tasks += [PSCustomObject][ordered]@{
                    GPOName      = $GPOName
                    GPOGUID      = $GPOGUID
                    GPOPath      = $GPOPath
                    SourceFile   = Get-GPORelativePath -Path $FilePath
                    TaskName     = $taskName
                    Command      = $fullCommand
                    RunAs        = $runAs
                    Context      = $context
                    Action       = $action
                    _Severity    = 'Note'
                    _Risk        = 'The item deletes the task - nothing runs'
                    _DeletesTask = $true
                }
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
            #
            # SYSTEM itself is kept apart from the two service accounts for one question
            # only: %TEMP% is C:\Windows\Temp for SYSTEM, and a profile of their own for
            # LOCAL SERVICE and NETWORK SERVICE.
            $isLocalSystem = ($runAs -match '^S-1-5-18$' -or                        # SYSTEM SID directly
                              $runAs -match '^(NT[ -]AUTHORITY|[^\\]+)\\SYSTEM$' -or # DOMAIN\SYSTEM, any language
                              $runAs -match '^SYSTEM$' -or                           # Just SYSTEM
                              $runAs -match '^LocalSystem$')                         # LocalSystem
            $isSystemAccount = $false
            if ($isLocalSystem -or
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

            # Every UNC path of every action, from the program field and out of the
            # arguments. The test used to be a pattern on the joined line, which also took
            # \\?\C:\... and \\.\pipe\... - a local file and a pipe - for a share.
            $uncPaths = @(Get-TaskUNCPaths -Pairs $execPairs)
            $hasUNCPath = $uncPaths.Count -gt 0
            $riskyPath = $null

            # At a path boundary, not anywhere in the string. Unanchored, "C:\Temp" matched
            # C:\TempBackup and "C:\Scripts" matched C:\Scriptsammlung - and the severity
            # that followed claimed a writable directory about a path that is not in the
            # list at all. The prefix has to end at a separator, and start at a boundary of
            # its own so that "D:\Data\C:\Temp" is not a hit either.
            foreach ($candidate in $Script:RiskyPaths) {
                $escapedRisky = [regex]::Escape([string]$candidate.Path)
                if ($fullCommand -match ('(?i)(^|["'' =,;])' + $escapedRisky + '($|[\\"''\s,;])')) {
                    $riskyPath = $candidate
                    break
                }
            }

            # %TEMP% and %TMP% are C:\Windows\Temp for SYSTEM, and the account's own profile
            # for anyone else - which nobody but that account can write.
            $riskyPathApplies = ($null -ne $riskyPath) -and ($isLocalSystem -or -not $riskyPath.PerAccount)

            # Named, and with the right a user really holds there. The old text said
            # "world-writable location" for every entry: a claim about an ACL nobody had
            # read, and not even true of C:\Windows\Temp, the most common case - a user may
            # add files there but not change the ones an administrator put down.
            $riskyPathText = ''
            if ($riskyPathApplies) {
                if ($riskyPath.Access -eq 'Change') {
                    $riskyPathText = "from $($riskyPath.Path), where every user may change files by Windows default - replacing the file the task starts runs code"
                } else {
                    $riskyPathText = "from $($riskyPath.Path), where every user may add files by Windows default - a DLL planted beside the program, or the file itself while it is missing, runs code"
                }
            }

            $runAsLabel = if ($runAs -and $runAs -ne 'Unknown') { $runAs } else { 'an account the file does not name' }

            # cmd.exe /c handed an unquoted program path with a space - the one place a
            # task's command line is split after all. See Get-CmdUnquotedTruncation.
            $cmdTruncation = $null
            foreach ($pair in $execPairs) {
                $cmdTruncation = Get-CmdUnquotedTruncation -Command $pair.Command -Arguments $pair.Arguments
                if ($cmdTruncation) { break }
            }

            # Who may create the truncated program where cmd.exe looks for it. The root of
            # the system drive is measured: ordinary users may create folders there, not
            # files. A directory of $Script:RiskyPaths carries its own right. Anything else
            # was not checked and is left $null.
            $cmdTruncationAccess = $null
            if ($cmdTruncation) {
                if ($cmdTruncation.Directory -ieq 'C:\') {
                    $cmdTruncationAccess = 'None'
                } else {
                    foreach ($entry in $Script:RiskyPaths) {
                        $entryPrefix = ([string]$entry.Path).TrimEnd([char]0x5C) + [char]0x5C
                        if ($cmdTruncation.Directory.StartsWith($entryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                            $cmdTruncationAccess = [string]$entry.Access
                            break
                        }
                    }
                }
            }

            # A task with a UNC path that runs as SYSTEM or as a privileged account: who may
            # write there, where adPEAS may look. Three outcomes, and the ladder below keeps
            # them apart - an account beyond the expected administrators can write it (a
            # finding that names them), a path that could not be read in full (the finding as
            # it always was, with the reason), and a path only privileged accounts can write.
            # That last one is a hint for SYSTEM - the administrators of that server still
            # decide what runs everywhere the policy applies - and stays a finding for a
            # privileged account, which is a finding on its own.
            $uncAccess = $null
            if (($isSystemAccount -or $isPrivilegedAccount) -and $hasUNCPath) {
                try {
                    $uncAccess = Get-UNCWriteAccess -Path $uncPaths -OPSEC:$OPSEC
                } catch {
                    Write-Log "[Parse-ScheduledTasksXML] Could not assess the UNC paths of '$taskName': $_"
                }
            }
            $uncWritable = ($null -ne $uncAccess) -and (@($uncAccess.Writers).Count -gt 0)
            $uncClean = ($null -ne $uncAccess) -and (-not $uncWritable) -and (@($uncAccess.Unchecked).Count -eq 0)

            # Who the share's content runs as, in the words the UNC verdicts below use. The
            # SYSTEM wording is the one the card's triggers have always matched.
            $uncTaskSubject = 'SYSTEM'
            $uncRunsAs = 'SYSTEM'
            if (-not $isSystemAccount) {
                $uncTaskSubject = "the privileged account $runAsLabel"
                $uncRunsAs = 'that account'
            }

            $isPowerShell = (@($allCommands) -join ' ') -match 'powershell|pwsh'

            # A script started from a share whose permissions were just read is not the open
            # question "check if script is modifiable" asks - the answer is on the row.
            $scriptPrograms = @($allCommands | Where-Object { $_ -match '\.(bat|cmd|vbs|vbe|ps1|wsf)$' })
            if ($uncClean) {
                $scriptPrograms = @($scriptPrograms | Where-Object { $_.Trim().Trim('"') -notmatch '^\\\\' })
            }
            $isScript = $scriptPrograms.Count -gt 0

            # Severity Determination (using standard adPEAS severity values)
            #
            # $uncSeverity is the colour of the program path on the row - where a task runs as
            # SYSTEM or a privileged account from a share, the path is the way in, and it carries
            # GPO_TASK_SYSTEM_UNC_PATH. The card sat on RiskReason, a sentence that repeated RunAs
            # and Command on the console; that stays on the HTML card (decided 2026-10-21).
            $uncSeverity = $null
            if (($isSystemAccount -or $isPrivilegedAccount) -and $uncWritable) {
                $severity = "Finding"
                $uncSeverity = 'Finding'
                $risk = "Task runs as $uncTaskSubject and uses UNC path - $(@($uncAccess.Writers) -join ', ') can change what it runs there by NTFS permission (see UNCPathPermissions), and so control what runs as $uncRunsAs on every computer in scope. The share permissions, which can narrow this over the network, were not read"
            } elseif (($isSystemAccount -or $isPrivilegedAccount) -and $hasUNCPath -and -not $uncClean) {
                $severity = "Finding"
                $uncSeverity = 'Finding'
                $uncReason = ''
                if ($null -ne $uncAccess -and @($uncAccess.Unchecked).Count -gt 0) {
                    $uncReason = ", because $(@($uncAccess.Unchecked)[0])"
                }
                $risk = "Task runs as $uncTaskSubject and uses UNC path - whoever can write that share, or answer for its server name, controls what runs as $uncRunsAs on every computer in scope. Who may write there was not checked$uncReason"
            } elseif ($isSystemAccount -and $riskyPathApplies) {
                $severity = "Finding"
                $risk = "Task runs as SYSTEM $riskyPathText as SYSTEM"
            } elseif ($isPrivilegedAccount -and $riskyPathApplies) {
                # Ahead of the plain privileged case, which would otherwise take the headline
                # and leave the way in unsaid.
                $severity = "Finding"
                $risk = "Task runs as the privileged account $runAsLabel $riskyPathText as that account"
            } elseif ($isSystemAccount -and $isScript) {
                # A hint, by user decision 2026-10-16: the risk is real but unread. Who may
                # change a local script sits in the file system of every computer in scope,
                # which the directory does not show - and the risky directories and UNC paths
                # this check can judge are rated above.
                $severity = "Hint"
                $risk = "Task runs a script as SYSTEM - whoever can change the script controls what runs as SYSTEM on every computer in scope. Its permissions on those computers were not checked"
            } elseif ($isSystemAccount -and $isPowerShell) {
                # The command line itself sits in the policy and is protected by its
                # permissions; what can change is a script it loads. "Check command for
                # injection vulnerabilities" claimed a surface a static line does not have.
                $severity = "Hint"
                $risk = "Task runs PowerShell as SYSTEM - whoever can change a script it loads controls what runs as SYSTEM on every computer in scope. That was not checked"
            } elseif ($isPrivilegedAccount) {
                $severity = "Finding"
                $risk = "Task runs as privileged account"
                if ($uncClean) {
                    $uncSeverity = 'Finding'
                    # Read in full, and only privileged accounts can write what it starts. Still
                    # a finding: the task runs as a privileged account on every computer in
                    # scope, whatever it starts - the row says the share is not the way in.
                    $risk = "Task runs as the privileged account $runAsLabel from UNC path $([string]@($uncPaths)[0]) - by NTFS permission only privileged accounts can write what it runs there. The share permissions were not read"
                }
            } elseif ($uncClean) {
                # SYSTEM with a UNC path that was read in full and only privileged accounts
                # can write. After the SYSTEM findings above, so a local script or a risky
                # directory in another action of the same task keeps its finding.
                $uncFirst = [string]@($uncPaths)[0]
                $uncHostName = ($uncFirst -replace '^\\\\([^\\]+)\\.*$', '$1')
                $severity = "Hint"
                $uncSeverity = 'Hint'
                $risk = "Task runs as SYSTEM from UNC path $uncFirst - by NTFS permission only privileged accounts can write what it runs there, so whoever administers $uncHostName still controls what runs as SYSTEM on every computer in scope. The share permissions were not read"
            } elseif ($riskyPathApplies) {
                # Any other account. A task running as a named account out of C:\Temp fell
                # through every branch to a Note with an empty reason, although whoever puts
                # a file there runs code as that account on every computer in scope - and as
                # whoever logs on, for a task that runs as the user.
                $severity = "Hint"
                $risk = "Task runs as $runAsLabel $riskyPathText as that account"
            } elseif ($hasUNCPath) {
                $severity = "Hint"
                $risk = "Task uses UNC path - whoever can write that share, or answer for its server name, controls what runs as the account the task uses. The permissions of the share were not checked"
            } elseif ($cmdTruncation -and $cmdTruncationAccess -ne 'None') {
                # A directory of $Script:RiskyPaths is reported by the branches above, which
                # name the right; what reaches this one is a directory nobody measured.
                $severity = "Hint"
                $risk = "Task hands cmd.exe the unquoted path $($cmdTruncation.Program) - cmd.exe starts $($cmdTruncation.Candidate).exe, .bat or .cmd if one exists, as $runAsLabel. Who may create files in $($cmdTruncation.Directory) was not checked"
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

            # The rows behind the UNC finding: which file or folder, who, and the rights an
            # administrator sees in Explorer. Written only where somebody can write, like
            # SysvolPermissions on a GPO, so every row on it is a finding.
            if ($uncWritable) {
                $taskProps['UNCPathPermissions'] = (@($uncAccess.Rows) -join "`n")
            } elseif ($uncSeverity) {
                # And short where nobody beyond the administrators can write, or where it was not
                # read: the reason, in full, is RiskReason's, on the HTML card.
                $taskProps['UNCPathPermissions'] = if ($uncClean) {
                    'Privileged accounts only (NTFS)'
                } elseif ($null -ne $uncAccess -and @($uncAccess.Unchecked).Count -gt 0) {
                    Get-UNCUncheckedShort -Reason ([string]@($uncAccess.Unchecked)[0])
                } else {
                    'Not checked'
                }
            }
            if ($uncSeverity) { $taskProps['_UNCSeverity'] = $uncSeverity }

            # A fact about the program path, and no longer a severity. Measured on Windows 11
            # (2026-10-16): the Task Scheduler service quotes the program path itself when it
            # builds the command line. A task whose Exec action named "...\a b\real.exe"
            # without quotes started real.exe with the command line "...\a b\real.exe", with
            # and without arguments, and an a.exe planted at the truncated path never ran. The
            # truncation hijack of an unquoted service ImagePath does not happen here, so this
            # used to colour practically every vendor task under C:\Program Files yellow with
            # "potential command injection".
            #
            # The statement is written only when it holds, so the attribute is absent on every
            # other task and the card cannot attach itself to one. Every action is asked, not
            # the first one.
            $unquotedPrograms = @($allCommands | Where-Object { $_ -match '\s' -and $_ -notmatch '^".*"$' })
            if ($unquotedPrograms.Count -gt 0) {
                $taskProps['gpoTaskUnquotedPath'] = 'The program path contains a space and is not quoted. The Task Scheduler quotes the program path itself when it starts the task, so this is not the truncation hijack of an unquoted service ImagePath - it only matters where the same string is handed to a shell, for example copied into a cmd.exe command line or a service definition'
            }

            # The case where it is handed to a shell: cmd.exe /c with such a path. Written
            # whatever the severity ladder chose as the headline, like the statement above,
            # and with the right a user holds where the truncated program would have to go -
            # GPO_TASK_CMD_UNQUOTED_PATH reads the colour off that wording.
            #
            # Short, as a row on the console: the program is on the Command row above, and the
            # right is the Windows default of the directory - the card says so. It was a
            # sentence of two lines that repeated the program path.
            if ($cmdTruncation) {
                $cmdWhere = 'who may create it was not checked'
                if ($cmdTruncationAccess -eq 'None') {
                    $cmdWhere = 'only administrators can create it'
                } elseif ($cmdTruncationAccess -eq 'Change') {
                    $cmdWhere = 'every user may change files there'
                } elseif ($cmdTruncationAccess -eq 'Add') {
                    $cmdWhere = 'every user may add files there'
                }
                $taskProps['gpoTaskCmdUnquotedPath'] = "cmd.exe splits the path at the space: $($cmdTruncation.Candidate).exe/.bat/.cmd runs if present - $cmdWhere"
            }

            $task = [PSCustomObject]$taskProps

            $tasks += $task
        }

        return $tasks
    } catch {
        Write-Log "[Parse-ScheduledTasksXML] Error parsing $FilePath : $_"
        Register-SYSVOLFileGap -Path $FilePath -ErrorRecord $_
        return $null
    }
}

<#
.SYNOPSIS
    Returns what cmd.exe /c (or /k) starts when it is handed a program path with a space
    and no quotes, or $null.

.DESCRIPTION
    The program field of an Exec action is quoted by the Task Scheduler itself (measured on
    Windows 11, 2026-10-16), so a space there splits nothing. A command line handed to
    cmd.exe is different: cmd.exe splits it at the first space and starts the first token,
    trying the executable extensions in turn. "cmd.exe /c C:\Tools\My App\run.bat" starts
    C:\Tools\My.exe, .bat or .cmd if one exists - in the account the task runs as.

    Only an absolute program path counts: a bare name is looked up through PATH and has no
    truncated form. The intended program is the shortest prefix that ends in an executable
    extension and is followed by a blank or the end of the line.

.OUTPUTS
    [PSCustomObject] with Program (the intended path), Candidate (the truncated path
    cmd.exe tries) and Directory (where the candidate would have to be created), or $null.
#>
function Get-CmdUnquotedTruncation {
    [CmdletBinding()]
    param(
        [string]$Command,
        [string]$Arguments
    )

    if ([string]::IsNullOrWhiteSpace($Command) -or [string]::IsNullOrWhiteSpace($Arguments)) { return $null }

    # cmd.exe in any of its spellings, quoted or not
    $program = $Command.Trim().Trim('"')
    if ($program -notmatch '(?i)(^|\\)cmd(\.exe)?$' -and $program -notmatch '(?i)^%ComSpec%$') { return $null }

    if ($Arguments -notmatch '(?i)^\s*/[ck]\s+(?<line>\S.*)$') { return $null }
    $line = $Matches['line']

    # Quoted, cmd.exe takes the path whole
    if ($line.StartsWith('"')) { return $null }

    if ($line -notmatch '(?i)^(?<prog>(?:[a-z]:|\\\\)[^"]*?\.(?:exe|bat|cmd|com|vbs|vbe|js|jse|wsf|ps1))(?:\s|$)') { return $null }
    $intended = $Matches['prog']
    $firstBlank = $intended.IndexOf(' ')
    if ($firstBlank -lt 0) { return $null }

    $candidate = $intended.Substring(0, $firstBlank)
    $lastSeparator = $candidate.LastIndexOf([char]0x5C)
    if ($lastSeparator -lt 0) { return $null }

    return [PSCustomObject]@{
        Program   = $intended
        Candidate = $candidate
        Directory = $candidate.Substring(0, $lastSeparator + 1)
    }
}

<#
.SYNOPSIS
    Returns the UNC paths a task's Exec actions name - the program and whatever is handed
    to it.

.DESCRIPTION
    The program field is one path. The Task Scheduler quotes it itself, so a UNC program
    with a space in its name is still a single path. The argument line is split the way a
    command line is: a quoted run stays together, and a UNC path inside a token such as
    -File:\\fs01\x.ps1 or /config=\\fs01\x.xml is cut out of it.

    Device paths are not network paths. \\?\C:\... names a local file and \\.\pipe\... a
    pipe; both used to count as a UNC path, which put a SYSTEM task with a long local path
    under the share-write finding. \\?\UNC\server\share\... is the long form of
    \\server\share\... and comes back in the short one.

.PARAMETER Pairs
    The Exec actions of a task, as Parse-ScheduledTasksXML collects them: objects with
    Command and Arguments.

.OUTPUTS
    [string] per distinct path, each naming at least \\host\share. Nothing if there is no
    UNC path.
#>
function Get-TaskUNCPaths {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Pairs
    )

    $candidates = @()
    foreach ($pair in @($Pairs)) {
        if ($null -eq $pair) { continue }

        $program = ([string]$pair.Command).Trim().Trim('"')
        if ($program) { $candidates += $program }

        $argumentLine = [string]$pair.Arguments
        if ($argumentLine) {
            foreach ($token in [regex]::Matches($argumentLine, '"([^"]*)"|''([^'']*)''|(\S+)')) {
                # Exactly one of the three groups takes part in a match; the others are
                # empty strings.
                $candidates += ($token.Groups[1].Value + $token.Groups[2].Value + $token.Groups[3].Value)
            }
        }
    }

    $seen = @{}
    foreach ($candidate in $candidates) {
        $at = $candidate.IndexOf('\\')
        if ($at -lt 0) { continue }
        $uncPath = $candidate.Substring($at).TrimEnd(',', ';')

        if ($uncPath -match '^\\\\\?\\UNC\\(.+)$') {
            $uncPath = '\\' + $Matches[1]
        } elseif ($uncPath -match '^\\\\[?.]\\') {
            continue
        }

        if ($uncPath -notmatch '^\\\\[^\\]+\\[^\\]+') { continue }

        $pathKey = $uncPath.ToLowerInvariant()
        if ($seen.ContainsKey($pathKey)) { continue }
        $seen[$pathKey] = $true
        $uncPath
    }
}
