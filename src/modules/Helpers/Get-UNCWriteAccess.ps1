<#
.SYNOPSIS
    Reads who may write the UNC paths a check names - the program a GPO task starts, the
    script a policy or an account runs - where adPEAS may connect.

.DESCRIPTION
    Whoever can write a program or script that something runs from a share controls what
    runs in that account on every computer that starts it. The NTFS permissions of that file
    and of the folder it is in can be read by any account that can read the file - but
    reading them takes an SMB connection, with the tester's credentials, to a host the
    directory names. Get-UNCConnectHost decides whether that connection is made at all.

    The share permissions are not read: NetShareGetInfo returns a share's security
    descriptor to administrators of the file server only. Over the network they apply on
    top of NTFS, so they can narrow what is reported here and never widen it.

    One read per path, cached in $Script:_uncWriteAccess - the same deployment share tends
    to sit in a dozen policies. A check sets the cache up when it starts and clears it when
    it ends, so permissions read in an earlier run are not reused.

    Moved here from Get-GPOScheduledTasks, where it was written for the program a task
    starts, when Get-GPOScriptPaths needed the same answer for scripts.

.PARAMETER Path
    The UNC paths to read, each naming at least \\host\share - Get-TaskUNCPaths returns
    them for a task.

.PARAMETER OPSEC
    Connect to nothing; every path is reported as not checked.

.PARAMETER Caller
    The check name the log lines carry.

.PARAMETER Runner
    What runs the path, for the reason given when the path holds an environment variable:
    "the task", "the script".

.OUTPUTS
    [PSCustomObject] with
      Rows      - "<path>: Identity (Rights)" per trustee that can write, across all paths
      Writers   - the distinct identities behind those rows
      Unchecked - per path that could not be read in full, a clause that completes "Who
                  may write there was not checked, because ..."
#>
function Get-UNCWriteAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$OPSEC,

        [Parameter(Mandatory = $false)]
        [string]$Caller = 'Get-UNCWriteAccess',

        [Parameter(Mandatory = $false)]
        [string]$Runner = 'the task'
    )

    if ($null -eq $Script:_uncWriteAccess) {
        $Script:_uncWriteAccess = @{ Hosts = @{}; Paths = @{} }
    }

    $rows = @()
    $writers = @()
    $unchecked = @()

    foreach ($uncPath in @($Path)) {
        if (-not $uncPath) { continue }

        $pathKey = $uncPath.ToLowerInvariant()
        if (-not $Script:_uncWriteAccess.Paths.ContainsKey($pathKey)) {
            $Script:_uncWriteAccess.Paths[$pathKey] = Read-UNCPathAccess -Path $uncPath -OPSEC:$OPSEC -Caller $Caller -Runner $Runner
        }
        $entry = $Script:_uncWriteAccess.Paths[$pathKey]

        foreach ($writer in @($entry.Findings)) {
            $rows += "$($writer.Object): $($writer.Row)"
            if ($writers -notcontains $writer.Identity) { $writers += $writer.Identity }
        }
        if ($entry.Reason) { $unchecked += [string]$entry.Reason }
    }

    [PSCustomObject]@{
        Rows      = @($rows)
        Writers   = @($writers)
        Unchecked = @($unchecked)
    }
}

<#
.SYNOPSIS
    Reads the NTFS permissions of one UNC path and the folder it is in. The uncached half
    of Get-UNCWriteAccess.

.DESCRIPTION
    Three shapes of path, told apart by what can be read rather than by a Test-Path probe:

      a file     - the file and the folder it is in. Writing the file replaces the
                   program; creating files in the folder plants a DLL beside it, or the
                   program itself once it is deleted.
      a folder   - the folder. A share root, or a folder handed to a program such as
                   robocopy.
      neither    - the folder it would be in. A program that is missing runs from the
                   moment someone creates it, which makes that folder the whole question.

    Inherit-only rules on a folder are skipped: they reach the files below it, and the
    file is read on its own.

.OUTPUTS
    [PSCustomObject] with Findings (Object, Identity, Row per trustee) and Reason ($null, or
    the clause Get-UNCWriteAccess reports for a path it could not read in full).
#>
function Read-UNCPathAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$OPSEC,

        [Parameter(Mandatory = $false)]
        [string]$Caller = 'Get-UNCWriteAccess',

        [Parameter(Mandatory = $false)]
        [string]$Runner = 'the task'
    )

    $findings = @()

    try {
        if ($OPSEC) {
            return [PSCustomObject]@{ Findings = @(); Reason = '-OPSEC connects to no host a policy names' }
        }

        # Resolved on the computer that runs it, and nowhere else.
        if ($Path -match '%') {
            return [PSCustomObject]@{ Findings = @(); Reason = "$Path contains an environment variable, which only the computer running $Runner resolves" }
        }

        if ($Path -notmatch '^\\\\([^\\]+)\\([^\\]+)(.*)$') {
            return [PSCustomObject]@{ Findings = @(); Reason = "$Path could not be read" }
        }
        $uncHost = $Matches[1]
        $share = $Matches[2]
        $uncRest = ([string]$Matches[3]).TrimEnd([char]0x5C)

        $target = Get-UNCConnectHost -HostName $uncHost
        if (-not $target.Host) {
            return [PSCustomObject]@{ Findings = @(); Reason = [string]$target.Reason }
        }

        # The folder a file is in, as a path below the share. Empty for the share root.
        $uncParentRest = ''
        if ($uncRest) { $uncParentRest = $uncRest.Substring(0, $uncRest.LastIndexOf([char]0x5C)) }

        $uncShareRoot = "\\$($target.Host)\$share"

        # The scriptblock gets the root Invoke-SMBAccess mounted, which is not always the
        # one it was given: a SimpleBind session with its own DNS server swaps the host
        # name for an address the local resolver does not know.
        $read = @(Invoke-SMBAccess -UNCPath $uncShareRoot -RetryCount 0 -Description "Reading the NTFS permissions of $Path" -ScriptBlock {
            $uncMountedRoot = $uncShareRoot
            if ($args.Count -gt 0 -and $args[0]) { $uncMountedRoot = [string]$args[0] }

            $fileRules = $null
            if ($uncRest) { $fileRules = Get-FileAccessRules -Path ($uncMountedRoot + $uncRest) }

            if ($null -ne $fileRules) {
                [PSCustomObject]@{
                    Kind        = 'File'
                    FileRules   = $fileRules
                    FolderRules = (Get-DirectoryAccessRules -Path ($uncMountedRoot + $uncParentRest))
                }
            } else {
                $folderRules = Get-DirectoryAccessRules -Path ($uncMountedRoot + $uncRest)
                if ($null -ne $folderRules) {
                    [PSCustomObject]@{ Kind = 'Folder'; FileRules = $null; FolderRules = $folderRules }
                } elseif ($uncRest) {
                    [PSCustomObject]@{
                        Kind        = 'Missing'
                        FileRules   = $null
                        FolderRules = (Get-DirectoryAccessRules -Path ($uncMountedRoot + $uncParentRest))
                    }
                }
            }
        } | Where-Object { $_ -and $_.PSObject.Properties['Kind'] })

        if ($read.Count -eq 0) {
            return [PSCustomObject]@{ Findings = @(); Reason = "$Path could not be read" }
        }
        $read = $read[0]

        # Rows name the path as the task does, not by the host name the connection used.
        $originalRoot = "\\$uncHost\$share"
        $folderObject = $originalRoot + $uncParentRest
        if ($read.Kind -eq 'Folder') { $folderObject = $originalRoot + $uncRest }

        if ($read.Kind -eq 'File') {
            foreach ($writer in @(Select-NTFSWriteAccess -Rules @($read.FileRules) -Target $Path -Caller $Caller)) {
                $findings += [PSCustomObject]@{ Object = $Path; Identity = $writer.Identity; Row = $writer.Row }
            }
        }

        $reason = $null
        if ($null -ne $read.FolderRules) {
            foreach ($writer in @(Select-NTFSWriteAccess -Rules @($read.FolderRules) -Target $folderObject -Caller $Caller -SkipInheritOnly)) {
                $findings += [PSCustomObject]@{ Object = $folderObject; Identity = $writer.Identity; Row = $writer.Row }
            }
        } elseif ($read.Kind -eq 'Missing') {
            $reason = "$Path could not be read"
        } else {
            $reason = "the folder $folderObject could not be read"
        }

        return [PSCustomObject]@{ Findings = @($findings); Reason = $reason }
    } catch {
        Write-Log "[$Caller] Could not read the permissions of $Path : $_"
        return [PSCustomObject]@{ Findings = @($findings); Reason = "$Path could not be read" }
    }
}

<#
.SYNOPSIS
    Decides whether adPEAS connects to the host a UNC path names, and by which name.

.DESCRIPTION
    The connection carries the tester's credentials. A host name that is stale, or that
    something else on the network answers for, would receive that authentication - which
    is exactly the risk the finding describes for the computers running the program. So
    only a host the directory vouches for is connected to:

      the domain's own name, DNS or NetBIOS - a domain controller, and the namespace a
        domain-based DFS share and NETLOGON live in
      an enabled computer of the domain - looked up by dNSHostName for a dotted name and
        by sAMAccountName for a short one, and connected to by the dNSHostName the
        directory records, so that a short name is never left to LLMNR or NetBIOS
        broadcast resolution

    An address, a name the domain does not know, a disabled computer and a computer
    without a DNS name are not connected to.

.OUTPUTS
    [PSCustomObject] with Host (the name to connect to, or $null) and Reason (why not).
#>
function Get-UNCConnectHost {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName
    )

    if ($null -eq $Script:_uncWriteAccess) {
        $Script:_uncWriteAccess = @{ Hosts = @{}; Paths = @{} }
    }
    $hostKey = $HostName.ToLowerInvariant()
    if ($Script:_uncWriteAccess.Hosts.ContainsKey($hostKey)) {
        return $Script:_uncWriteAccess.Hosts[$hostKey]
    }

    $notADomainComputer = "$HostName is not an enabled computer of this domain, and adPEAS connects to no other host"
    $answer = [PSCustomObject]@{ Host = $null; Reason = $notADomainComputer }

    $domainFQDN = [string]$Script:LDAPContext.Domain
    $domainNetBIOS = [string]$Script:LDAPContext.DomainNetBIOS
    $address = $null

    if ($domainFQDN -and ($HostName -ieq $domainFQDN -or ($domainNetBIOS -and $HostName -ieq $domainNetBIOS))) {
        $answer = [PSCustomObject]@{ Host = $domainFQDN; Reason = $null }
    } elseif ([System.Net.IPAddress]::TryParse($HostName, [ref]$address)) {
        $answer = [PSCustomObject]@{ Host = $null; Reason = "$HostName is an address rather than a computer of this domain, and adPEAS connects to no other host" }
    } elseif ($HostName -match '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$') {
        # The pattern is also what keeps the name safe inside the filter below.
        $filter = "(sAMAccountName=$HostName`$)"
        if ($HostName.Contains('.')) { $filter = "(dNSHostName=$HostName)" }

        try {
            $computer = @(Get-DomainComputer -LDAPFilter $filter -Enabled -Properties 'dNSHostName')[0]
            if ($computer) {
                $dnsName = [string]$computer.dNSHostName
                if ($dnsName) {
                    $answer = [PSCustomObject]@{ Host = $dnsName; Reason = $null }
                } else {
                    $answer = [PSCustomObject]@{ Host = $null; Reason = "the computer $HostName has no DNS host name in the directory, and adPEAS connects by no other name" }
                }
            }
        } catch {
            Write-Log "[Get-UNCConnectHost] Could not look up the computer $HostName : $_"
            $answer = [PSCustomObject]@{ Host = $null; Reason = "the computer $HostName could not be looked up in the directory" }
        }
    }

    $Script:_uncWriteAccess.Hosts[$hostKey] = $answer
    return $answer
}
