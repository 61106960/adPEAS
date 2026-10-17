function Get-LogonScriptPermissions {
    <#
    .SYNOPSIS
    Reports the logon scripts accounts run that a principal beyond the administrators may change.

    .DESCRIPTION
    Coverage item A9, second half. The scriptPath of an account names a logon script,
    relative to the NETLOGON share of the domain controller that logs the account on, and
    Windows runs it at every logon of that account, as that account. Whoever may change the
    script runs code as every account that has it set - an administrator among them runs it
    with the administrator's rights. NETLOGON is the scripts folder of SYSVOL: its file
    permissions are nobody's GPO permissions, and nothing read them.

    The check reads the scriptPath of every enabled account, resolves a relative one to
    \\<domain>\NETLOGON\<path>, and reads the NTFS permissions of each distinct script and
    of the folder it is in through Get-UNCWriteAccess - the reader the GPO checks use, which
    connects only to the domain's own name and to enabled computers of the domain, and
    judges the writers by the identity gates a GPO is judged by. A script a principal beyond
    the administrators may write is a finding, with the number of accounts that run it and
    the privileged ones among them by name.

    A local path (C:\...) exists on each computer and is not read over the network; a path
    that could not be read is listed with the reason. The share permissions are not read -
    they apply on top of NTFS over the network and can only narrow what is reported.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .PARAMETER OPSEC
    Make no SMB connection: the logon scripts are not read.

    .EXAMPLE
    Get-LogonScriptPermissions

    .EXAMPLE
    Get-LogonScriptPermissions -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Accounts
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
        [switch]$OPSEC
    )

    begin {
        Write-Log "[Get-LogonScriptPermissions] Starting check"
    }

    process {
        try {
            # Connection parameters only - -OPSEC belongs to this check, and splatting
            # $PSBoundParameters into Ensure-LDAPConnection fails to bind it.
            $connectionParams = @{}
            if ($Domain)     { $connectionParams['Domain']     = $Domain }
            if ($Server)     { $connectionParams['Server']     = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            Show-SubHeader "Checking who may change the logon scripts accounts run..." -ObjectType "LogonScriptPermission"

            if ($OPSEC) {
                Show-Line "OPSEC mode: Skipping the logon scripts of accounts (reading their permissions takes an SMB connection to NETLOGON)" -Class "Hint"
                return
            }

            # The hosts and paths read in this run - see Get-UNCWriteAccess. Cleared below.
            $Script:_uncWriteAccess = @{ Hosts = @{}; Paths = @{} }

            # Internal: the attributes are used here, the accounts are not shown.
            $accounts = @(Get-DomainUser -Enabled -LDAPFilter '(scriptPath=*)' -Properties 'sAMAccountName', 'scriptPath', 'objectSid' @connectionParams)
            if ($accounts.Count -eq 0) {
                Show-Line "No enabled account runs a logon script" -Class Note
                return
            }

            # One read per script, however many accounts run it. A relative scriptPath is
            # resolved against NETLOGON, by the domain's own name, which is the namespace every
            # domain controller answers for; forward slashes are what some tools write.
            $domainFQDN = [string]$Script:LDAPContext.Domain
            $byScript = [ordered]@{}
            $localAccounts = 0
            foreach ($account in $accounts) {
                $scriptPath = ([string]@($account.scriptPath)[0]).Trim().Trim('"').Replace('/', '\')
                if (-not $scriptPath) { continue }
                if ($scriptPath -match '^[A-Za-z]:\\') {
                    $localAccounts++
                    continue
                }
                $uncPath = $scriptPath
                if ($scriptPath -notmatch '^\\\\') { $uncPath = "\\$domainFQDN\NETLOGON\" + $scriptPath.TrimStart([char]0x5C) }

                # [ordered] compares its keys without regard to case, as a script path is
                # compared on Windows - logon.bat and LOGON.BAT are one script, read once.
                if (-not $byScript.Contains($uncPath)) {
                    $byScript[$uncPath] = [PSCustomObject]@{ Path = $uncPath; Accounts = @() }
                }
                $byScript[$uncPath].Accounts += $account
            }

            $writable = @()
            $unchecked = @()
            $readClean = 0
            foreach ($scriptKey in @($byScript.Keys)) {
                $entry = $byScript[$scriptKey]
                $access = Get-UNCWriteAccess -Path @($entry.Path) -Caller 'Get-LogonScriptPermissions' -Runner 'the logon script'
                if (@($access.Writers).Count -gt 0) {
                    $writable += [PSCustomObject]@{ Entry = $entry; Access = $access }
                } elseif (@($access.Unchecked).Count -gt 0) {
                    $unchecked += @($access.Unchecked)
                } else {
                    $readClean++
                }
            }

            if ($writable.Count -gt 0) {
                # Who among the accounts that run them is privileged: one query for the
                # candidates, each confirmed - the filter is a candidate list, adminCount
                # included, not a verdict. Operators count: a script that runs as one is
                # code that runs as one.
                $privilegedSIDs = @{}
                try {
                    $privilegedFilter = Get-PrivilegedAccountFilter -IncludeOperators @connectionParams
                    foreach ($candidate in @(Get-DomainUser -Enabled -LDAPFilter "(&(scriptPath=*)$privilegedFilter)" -Properties 'sAMAccountName', 'objectSid' @connectionParams)) {
                        $candidateSID = [string]$candidate.objectSid
                        if (-not $candidateSID -or $privilegedSIDs.ContainsKey($candidateSID)) { continue }
                        if ((Test-IsPrivileged -Identity $candidateSID -IncludeOperators).IsPrivileged) {
                            $privilegedSIDs[$candidateSID] = $true
                        }
                    }
                } catch {
                    Write-Log "[Get-LogonScriptPermissions] Could not tell the privileged accounts apart: $_"
                }

                Show-Line "Found $($writable.Count) logon script(s) a principal beyond the administrators may change" -Class Finding -FindingId 'LOGON_SCRIPT_WRITABLE'
                foreach ($item in $writable) {
                    $runBy = @($item.Entry.Accounts)
                    $privilegedNames = @($runBy |
                        Where-Object { $privilegedSIDs.ContainsKey([string]$_.objectSid) } |
                        ForEach-Object { [string]$_.sAMAccountName } | Sort-Object)

                    $risk = "$(@($item.Access.Writers) -join ', ') can change it by NTFS permission (see logonScriptPermissions), and so run code as each of the $($runBy.Count) account(s) that run it at logon"
                    if ($privilegedNames.Count -gt 0) { $risk += " - $($privilegedNames.Count) of them privileged" }
                    $risk += '. The share permissions, which can narrow this over the network, were not read'

                    $row = [PSCustomObject]@{
                        Name                   = $item.Entry.Path
                        logonScript            = $item.Entry.Path
                        logonScriptRisk        = $risk
                        logonScriptPermissions = (@($item.Access.Rows) -join "`n")
                        runByAccounts          = $runBy.Count
                    }
                    if ($privilegedNames.Count -gt 0) {
                        $row | Add-Member -NotePropertyName 'runByPrivilegedAccounts' -NotePropertyValue $privilegedNames -Force
                    }
                    $row | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LogonScriptPermission' -Force
                    Show-Object $row -Class Finding
                }
            }

            if ($unchecked.Count -gt 0) {
                $distinctReasons = @($unchecked | Select-Object -Unique)
                $reasonText = (@($distinctReasons | Select-Object -First 10) -join '; ')
                if ($distinctReasons.Count -gt 10) { $reasonText += "; and $($distinctReasons.Count - 10) more" }
                Show-Line "$($distinctReasons.Count) logon script(s) could not be checked - who may change them was not evaluated: $reasonText" -Class Note
            }

            if ($localAccounts -gt 0) {
                Show-Line "$localAccounts account(s) run a logon script from a local path, which exists on each computer and is not read over the network" -Class Note
            }

            if ($writable.Count -eq 0 -and $readClean -gt 0) {
                $cleanClass = 'Secure'
                if ($unchecked.Count -gt 0) { $cleanClass = 'Note' }
                Show-Line "Only administrators and privileged accounts may change the $readClean logon script(s) read" -Class $cleanClass
            }

        } catch {
            Write-Log "[Get-LogonScriptPermissions] Error: $_" -Level Error
            Show-Line "Error during check - the logon scripts of accounts could not be evaluated: $_" -Class Finding
        } finally {
            $Script:_uncWriteAccess = $null
        }
    }

    end {
        Write-Log "[Get-LogonScriptPermissions] Check completed"
    }
}
