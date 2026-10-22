<#
.SYNOPSIS
    Finds the file shares of a host over SMB and tells the ones worth reading from the rest.

.DESCRIPTION
    The three steps Invoke-ShareHunt needs before it reads a single file, each callable on
    its own:

    - Test-TcpPortReachable: which hosts answer on port 445 at all - or on any ports, which
      is what Invoke-PortScan asks it
    - Get-SMBShareList: the shares of one host (NetShareEnum, MS-SRVS 3.1.4.8)
    - Test-ShareWorthScanning: which of those a credential scan should look at

    Why the sweep is written the way it is: a host that does not answer costs the full
    connection timeout, and a thread per host turns 5000 hosts into either 5000 threads or
    a queue that runs for an hour. Test-TcpPortReachable starts a block of connections at
    once and waits for the block, so the cost of the whole sweep is the number of blocks
    times one timeout rather than the number of hosts.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function Start-TcpConnectAttempt {
    <#
    .SYNOPSIS
    Starts one connection attempt and returns the socket with its handle.

    .DESCRIPTION
    A seam of two lines, extracted so that the failure of the socket itself is reachable
    from a test. BeginConnect does not throw for a host that cannot be resolved - measured
    on every shape of bad name: an empty one, a backslash, a space, 256.256.256.256 and a
    300-character label all start and fail asynchronously. What does throw here is the
    machine running out of sockets, which a sweep over thousands of hosts can do, and the
    caller has to keep sweeping when it happens.

    .PARAMETER Target
    The host name or address.

    .PARAMETER Port
    The port.

    .OUTPUTS
    PSCustomObject with Client and Handle.

    .NOTES
    Internal helper function
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    # finally rather than catch: the exception reaches the caller either way, and without a
    # catch there is no rethrow to leave out. What stays untested is the close itself -
    # getting into it means the machine is out of sockets, which no test can ask for - and
    # leaving it out is unobservable, since TcpClient releases the handle when it is
    # collected. The caller keeps sweeping, which is the part that is tested.
    $client = New-Object System.Net.Sockets.TcpClient
    $handle = $null
    try {
        $handle = $client.BeginConnect($Target, $Port, $null, $null)
    } finally {
        if (-not $handle) { try { $client.Close() } catch { } }
    }
    return [PSCustomObject]@{ Client = $client; Handle = $handle }
}

function Test-TcpPortReachable {
    <#
    .SYNOPSIS
    Tells which of many hosts answer on which TCP ports, in blocks with one deadline each.

    .DESCRIPTION
    Every pair of target and port in a block gets a connection attempt started at once
    (BeginConnect, which returns immediately), then the block is given TimeoutMs to finish.
    A pair that has connected by then is reachable; everything else is not, whether it was
    refused, filtered or simply slow. No thread is created for any of it.

    The deadline is per block, not per pair: a block of 256 unreachable hosts costs one
    timeout, not 256. That is the whole point of the function.

    Refused and filtered are not told apart. Windows answers a refused connection only
    after retrying it for about a second, so within a deadline short enough to sweep with,
    a closed port and a dropped one look the same.

    .PARAMETER Target
    Host names or addresses. A name is resolved by the system resolver, so the caller
    decides what to pass - an address avoids the lookup, a host name is what Kerberos needs.

    .PARAMETER Port
    The ports. Default 445 (SMB). Every target is tried on every port, port by port: the
    first port on all targets, then the next - so a block spreads over many hosts rather
    than putting 256 connections on one.

    .PARAMETER TimeoutMs
    How long one block is given. Default 1000.

    .PARAMETER BatchSize
    How many connections are in flight at once. Default 256.

    .OUTPUTS
    PSCustomObject per target and port: Target, Port and Reachable.

    .EXAMPLE
    Test-TcpPortReachable -Target '10.1.2.21', '10.1.2.22'

    .EXAMPLE
    Test-TcpPortReachable -Target '10.1.2.21' -Port 22, 445, 3389

    .NOTES
    Internal helper function
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        # An empty or absent name among the targets is skipped below rather than refused:
        # the caller's list comes out of the directory, where a computer without a
        # dNSHostName is an ordinary case, and a binder error there would take the whole
        # sweep down.
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [AllowNull()]
        [string[]]$Target,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int[]]$Port = 445,

        [Parameter(Mandatory = $false)]
        [ValidateRange(50, 60000)]
        [int]$TimeoutMs = 1000,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 1024)]
        [int]$BatchSize = 256
    )

    # No guard for an empty list: the loop below then runs zero times.
    $targets = @($Target | Where-Object { $_ })
    $pairs = New-Object System.Collections.Generic.List[object]
    foreach ($onePort in @($Port | Select-Object -Unique)) {
        foreach ($one in $targets) { $pairs.Add([PSCustomObject]@{ Target = $one; Port = $onePort }) }
    }

    for ($offset = 0; $offset -lt $pairs.Count; $offset += $BatchSize) {
        $last = [Math]::Min($offset + $BatchSize, $pairs.Count) - 1
        $pending = New-Object System.Collections.Generic.List[object]

        foreach ($pair in $pairs.GetRange($offset, $last - $offset + 1)) {
            try {
                $attempt = Start-TcpConnectAttempt -Target $pair.Target -Port $pair.Port
                $pending.Add([PSCustomObject]@{ Target = $pair.Target; Port = $pair.Port; Client = $attempt.Client; Handle = $attempt.Handle })
            } catch {
                # The socket itself failed - the machine is out of them. The sweep goes on
                # with the next pair; this one is simply not known to be reachable. Kept in
                # the list without a handle, so its answer comes in its place rather than
                # ahead of the block.
                Write-Log "[Test-TcpPortReachable] $($pair.Target):$($pair.Port) could not be probed: $($_.Exception.Message)"
                $pending.Add([PSCustomObject]@{ Target = $pair.Target; Port = $pair.Port; Client = $null; Handle = $null })
            }
        }

        # One deadline for the whole block. Waiting on each handle in turn would add up to
        # the per-host timeout again for every host that does not answer.
        $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
        foreach ($entry in $pending) {
            $reachable = $false
            if ($entry.Handle) {
                $left = [int][Math]::Ceiling(($deadline - [DateTime]::UtcNow).TotalMilliseconds)
                if ($left -lt 0) { $left = 0 }
                $done = $false
                try { $done = $entry.Handle.AsyncWaitHandle.WaitOne($left, $false) } catch { }

                if ($done) {
                    # Connected rather than refused: EndConnect throws on a refusal, and
                    # BeginConnect signals the handle either way.
                    try { $entry.Client.EndConnect($entry.Handle); $reachable = $true } catch { }
                }
                try { $entry.Client.Close() } catch { }
                try { $entry.Client.Dispose() } catch { }
            }

            [PSCustomObject]@{ Target = $entry.Target; Port = $entry.Port; Reachable = $reachable }
        }
    }
}

function ConvertFrom-ShareType {
    <#
    .SYNOPSIS
    Decodes the type field of a share (MS-SRVS 2.2.2.4).

    .DESCRIPTION
    The low bits name the kind of share, the top two bits are flags: 0x80000000 marks a
    special share - the administrative ones (C$, ADMIN$) and IPC$ - and 0x40000000 a
    temporary one.

    The masks carry the L suffix because Windows PowerShell 5.1 reads an eight-digit hex
    literal as a signed Int32: 0x80000000 is -2147483648 there, and [uint32] of it throws.

    .PARAMETER Type
    The type field as NetShareEnum returns it.

    .OUTPUTS
    PSCustomObject: Kind (Disk, Print, Device, IPC or "Unknown (n)"), IsSpecial, IsTemporary.

    .NOTES
    Internal helper function
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [uint32]$Type
    )

    $kind = switch ([long]$Type -band 0x0FL) {
        0 { 'Disk' }
        1 { 'Print' }
        2 { 'Device' }
        3 { 'IPC' }
        default { "Unknown ($([long]$Type -band 0x0FL))" }
    }

    return [PSCustomObject]@{
        Kind        = $kind
        IsSpecial   = (([long]$Type -band 0x80000000L) -ne 0)
        IsTemporary = (([long]$Type -band 0x40000000L) -ne 0)
    }
}

# The shares Windows creates for itself, by name. The special flag below is what marks
# them - measured on a domain member: ADMIN$, C$ and IPC$ all carry 0x80000000 - and this
# list is the second half of the test, for a server that presents such a name without the
# flag. A drive share is matched by its shape instead, since the letter varies.
#
# A share whose name merely ends in a dollar is NOT in here. That makes it hidden, not
# administrative: Software$, Daten$ and Profiles$ are ordinary file shares an
# administrator made, and on an assessment they are the more interesting ones, because
# whoever made them often took "not browsable" for "not reachable".
$Script:WindowsOwnShareName = @('ADMIN$', 'IPC$', 'print$', 'FAX$')

function Test-ShareWorthScanning {
    <#
    .SYNOPSIS
    Decides whether a credential scan should look at one share.

    .DESCRIPTION
    Left out, and why:

    - Anything that is not a disk share. A printer queue and an IPC pipe hold no files.
    - The shares Windows creates for itself. C$ and ADMIN$ are the whole volume and the
      Windows directory, reachable only as an administrator, and walking one means walking
      every file of the machine. They are told by the special flag - measured, Windows sets
      it on all of them - and additionally by name and by the shape of a drive share, for a
      server that presents such a name without the flag.

      A name that merely ends in a dollar is not one of them. The dollar makes a share
      hidden, not administrative, and a hidden share is an ordinary one that somebody did
      not want in the browse list: Software$, Daten$, Profiles$. Those are searched, and
      they are often where the interesting files are, because "not browsable" gets taken
      for "not reachable".
    - SYSVOL and NETLOGON. Get-CredentialExposure reads them in full, with the policy each
      file belongs to; finding the same credential again here, without that context, is
      noise. -IncludeSysvol asks for them anyway.

    The name test is case-insensitive and the share name is compared whole: a share named
    "Sysvolume" is not SYSVOL.

    .PARAMETER Name
    The share name as it was enumerated.

    .PARAMETER Type
    Its type field, as NetShareEnum returns it.

    .PARAMETER IncludeAdmin
    Takes the shares Windows creates for itself as well (C$, ADMIN$, print$ and the like).
    It does not govern hidden shares: a share whose name ends in a dollar but is not one of
    Windows' own is searched either way.

    .PARAMETER IncludeSysvol
    Takes SYSVOL and NETLOGON as well.

    .OUTPUTS
    PSCustomObject: Scan (bool) and Reason - why it was left out, $null where it is scanned.

    .NOTES
    Internal helper function
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [uint32]$Type,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeAdmin,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeSysvol
    )

    $decoded = ConvertFrom-ShareType -Type $Type
    $trimmed = ([string]$Name).Trim()

    if (-not $trimmed) {
        return [PSCustomObject]@{ Scan = $false; Reason = 'No share name' }
    }
    if ($decoded.Kind -ne 'Disk') {
        return [PSCustomObject]@{ Scan = $false; Reason = "Not a file share ($($decoded.Kind))" }
    }
    if (-not $IncludeAdmin) {
        # Three tests, because each can be true without the others: a special share need
        # not be named with a dollar, a server may present C$ or ADMIN$ without the flag,
        # and the letter of a drive share varies so it is matched by shape.
        #
        # What is deliberately NOT a test here: a name ending in a dollar. That made every
        # hidden share an administrative one and hid Software$ and its kind from the scan.
        if ($decoded.IsSpecial -or
            ($Script:WindowsOwnShareName -contains $trimmed) -or
            ($trimmed -match '^[A-Za-z]\$$')) {
            return [PSCustomObject]@{ Scan = $false; Reason = 'Administrative share' }
        }
    }
    if (-not $IncludeSysvol -and ($trimmed -ieq 'SYSVOL' -or $trimmed -ieq 'NETLOGON')) {
        return [PSCustomObject]@{ Scan = $false; Reason = 'Read by Get-CredentialExposure' }
    }

    return [PSCustomObject]@{ Scan = $true; Reason = $null }
}

function Initialize-ShareNativeMethod {
    <#
    .SYNOPSIS
    Compiles the netapi32 signatures the share enumeration needs, once per process.

    .DESCRIPTION
    Its own function for two reasons. A type added with Add-Type lands in the AppDomain and
    is therefore shared by every runspace of the process, so the parallel enumeration
    compiles it once in the caller rather than once in each of thirty-two runspaces -
    compiling C# takes longer than the enumeration it is for. And the failure to compile is
    then one answer in one place instead of a branch in every caller.

    .OUTPUTS
    [bool] whether the types are available.

    .NOTES
    Internal helper function
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (([System.Management.Automation.PSTypeName]'adPEAS.NativeMethods.Shares').Type) { return $true }

    $shareCode = @'
using System;
using System.Runtime.InteropServices;

namespace adPEAS.NativeMethods
{
    public class Shares
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHARE_INFO_1
        {
            [MarshalAs(UnmanagedType.LPWStr)] public string netname;
            public uint type;
            [MarshalAs(UnmanagedType.LPWStr)] public string remark;
        }

        [DllImport("netapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int NetShareEnum(
            string servername,
            int level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            ref int resume_handle);

        [DllImport("netapi32.dll")]
        public static extern int NetApiBufferFree(IntPtr buffer);
    }
}
'@

    try {
        Add-Type -TypeDefinition $shareCode -Language CSharp -ErrorAction Stop
        Write-Log "[Initialize-ShareNativeMethod] P/Invoke types compiled successfully"
        return $true
    } catch {
        # A second caller that got here at the same time has already added the type.
        if (([System.Management.Automation.PSTypeName]'adPEAS.NativeMethods.Shares').Type) { return $true }
        Write-Log "[Initialize-ShareNativeMethod] The P/Invoke types could not be compiled: $($_.Exception.Message)" -Level Warning
        return $false
    }
}

function Get-SMBShareList {
    <#
    .SYNOPSIS
    Lists the shares of one host over SMB.

    .DESCRIPTION
    NetShareEnum at information level 1 (MS-SRVS 3.1.4.8), which returns the name, the type
    and the comment of every share and is the level an ordinary account may call - level 2
    carries the local path and needs an administrator on the target.

    A host that refuses the call answers with Win32 5 (access denied), one that is not
    reachable with 53, and one whose Server service is not running with 2114. Each is
    returned as the Error of the result rather than thrown: a share hunt over a domain is
    expected to meet all three.

    .PARAMETER ComputerName
    The host, as a name or an address.

    .OUTPUTS
    PSCustomObject: ComputerName, Shares (one object per share with Name, Type, Remark) and
    Error ($null on success).

    .EXAMPLE
    Get-SMBShareList -ComputerName 'fs01.contoso.com'

    .NOTES
    Internal helper function
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    if (-not (Initialize-ShareNativeMethod)) {
        return [PSCustomObject]@{ ComputerName = $ComputerName; Shares = @(); Error = 'The P/Invoke types could not be compiled' }
    }

    $buffer = [IntPtr]::Zero
    $read = 0
    $total = 0
    $resume = 0
    $shares = New-Object System.Collections.Generic.List[object]

    try {
        # -1 as prefmaxlen: the API allocates what it needs, so there is no second call
        # with a larger buffer and no ERROR_MORE_DATA to handle.
        $result = [adPEAS.NativeMethods.Shares]::NetShareEnum($ComputerName, 1, [ref]$buffer, -1, [ref]$read, [ref]$total, [ref]$resume)

        if ($result -ne 0) {
            $reason = switch ($result) {
                5     { 'Access denied' }
                53    { 'Host not reachable over SMB' }
                2114  { 'The Server service is not running' }
                1722  { 'The RPC server is unavailable' }
                default { "NetShareEnum failed with Win32 error $result" }
            }
            Write-Log "[Get-SMBShareList] $ComputerName : $reason"
            return [PSCustomObject]@{ ComputerName = $ComputerName; Shares = @(); Error = $reason }
        }

        $entrySize = [System.Runtime.InteropServices.Marshal]::SizeOf([type][adPEAS.NativeMethods.Shares+SHARE_INFO_1])
        for ($i = 0; $i -lt $read; $i++) {
            $entryPtr = [IntPtr]([long]$buffer + ($i * $entrySize))
            $entry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($entryPtr, [type][adPEAS.NativeMethods.Shares+SHARE_INFO_1])
            $shares.Add([PSCustomObject]@{
                Name   = [string]$entry.netname
                Type   = [uint32]$entry.type
                Remark = [string]$entry.remark
            })
        }
        Write-Log "[Get-SMBShareList] $ComputerName : $($shares.Count) share(s) of $total"

        return [PSCustomObject]@{ ComputerName = $ComputerName; Shares = $shares.ToArray(); Error = $null }

    } catch {
        Write-Log "[Get-SMBShareList] $ComputerName could not be enumerated: $_"
        return [PSCustomObject]@{ ComputerName = $ComputerName; Shares = @(); Error = "Could not be enumerated: $($_.Exception.Message)" }
    } finally {
        if ($buffer -ne [IntPtr]::Zero) {
            [void][adPEAS.NativeMethods.Shares]::NetApiBufferFree($buffer)
        }
    }
}

function Get-SMBShareListMany {
    <#
    .SYNOPSIS
    Lists the shares of many hosts at once, with a bound on how long the whole pass takes.

    .DESCRIPTION
    NetShareEnum has no timeout of its own. A host that completes the TCP handshake on 445
    and then does not answer the RPC call blocks for the RPC timeout, which is tens of
    seconds, and a domain with a handful of such hosts would add hours to a sequential
    pass. So the calls run in a runspace pool and the collection has ONE deadline for the
    whole pass rather than one per host: with a pool of 32, a hundred hosts that all stall
    cost four stalls, not a hundred.

    The deadline is derived from the number of hosts and the pool size - the number of
    batches a stall can cost, plus one - so that it scales with the work and does not
    depend on the caller doing that arithmetic.

    Each runspace is given Get-SMBShareList itself, read from the session, so there is one
    implementation of the enumeration and not a copy of it inside a scriptblock. Write-Log
    is replaced with a stub in the runspaces: thirty-two threads writing the same log file
    is a conflict, and what the enumeration has to say is in the Error of its result, which
    this function logs in order when it collects.

    A host whose call has not returned by the deadline is reported as timed out. Its thread
    is abandoned rather than waited for, which is the point.

    .PARAMETER Target
    The hosts, as names or addresses.

    .PARAMETER ThrottleLimit
    How many calls run at once. Default 32.

    .PARAMETER TimeoutSeconds
    How long one batch of calls may take. Default 20, which is longer than a reachable host
    needs and shorter than the RPC timeout of one that stalls.

    .OUTPUTS
    One PSCustomObject per target, in the order given, shaped as Get-SMBShareList returns
    them: ComputerName, Shares and Error.

    .EXAMPLE
    Get-SMBShareListMany -Target 'fs01.contoso.com', 'fs02.contoso.com'

    .NOTES
    Internal helper function
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [AllowNull()]
        [string[]]$Target,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 256)]
        [int]$ThrottleLimit = 32,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 600)]
        [int]$TimeoutSeconds = 20
    )

    # No shortcut for an empty list: measured, opening a pool for nothing costs less than
    # a test can tell from not opening one, and the loops below then run zero times.
    $targets = @($Target | Where-Object { $_ })

    # Compiled here, in the caller, so the runspaces do not each compile the same C#.
    if (-not (Initialize-ShareNativeMethod)) {
        foreach ($one in $targets) {
            [PSCustomObject]@{ ComputerName = $one; Shares = @(); Error = 'The P/Invoke types could not be compiled' }
        }
        return
    }

    $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    # The enumeration itself and every adPEAS function it calls, taken from this session
    # rather than written out again.
    #
    # Initialize-ShareNativeMethod was missing from this list, and the enumeration worked
    # anyway - by accident. A command that is not found ends only the statement that calls
    # it, so the guard around it was skipped, and NetShareEnum succeeded because this
    # session had compiled the type already. The error went to the runspace's error stream,
    # which nothing read. The test that now guards this list reads the commands the
    # enumeration calls out of its own syntax tree, so a call added later is caught there.
    foreach ($name in 'Get-SMBShareList', 'Initialize-ShareNativeMethod') {
        [void]$sessionState.Commands.Add(
            (New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry $name, (Get-Command $name).Definition))
    }
    [void]$sessionState.Commands.Add(
        (New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry 'Write-Log', 'param([string]$Message, [string]$Level)'))

    $pool = $null
    $jobs = New-Object System.Collections.Generic.List[object]
    try {
        $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit, $sessionState, $Host)
        $pool.ApartmentState = [System.Threading.ApartmentState]::MTA
        $pool.Open()

        foreach ($one in $targets) {
            $shell = [PowerShell]::Create()
            $shell.RunspacePool = $pool
            [void]$shell.AddScript('param($ComputerName) Get-SMBShareList -ComputerName $ComputerName')
            [void]$shell.AddParameter('ComputerName', $one)
            $jobs.Add([PSCustomObject]@{ Target = $one; Shell = $shell; Handle = $shell.BeginInvoke() })
        }

        # One deadline for the pass: the number of batches a stall can cost, plus one.
        $batches = [Math]::Ceiling($targets.Count / [double]$ThrottleLimit) + 1
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds * $batches)

        foreach ($job in $jobs) {
            $left = [int][Math]::Ceiling(($deadline - [DateTime]::UtcNow).TotalMilliseconds)
            if ($left -lt 0) { $left = 0 }

            $done = $false
            try { $done = $job.Handle.AsyncWaitHandle.WaitOne($left, $false) } catch { }

            if (-not $done) {
                Write-Log "[Get-SMBShareListMany] $($job.Target) did not answer within the pass deadline"
                [PSCustomObject]@{ ComputerName = $job.Target; Shares = @(); Error = 'Timed out' }
                continue
            }

            try {
                $output = @($job.Shell.EndInvoke($job.Handle))
                # What the runspace wrote to its error stream is read rather than dropped: it
                # is where the missing command above went unnoticed, because a statement that
                # fails there does not stop the script around it.
                if ($job.Shell.Streams.Error.Count -gt 0) {
                    Write-Log "[Get-SMBShareListMany] $($job.Target) : the enumeration reported $($job.Shell.Streams.Error.Count) error(s), the first: $($job.Shell.Streams.Error[0])" -Level Warning
                }
                if ($output.Count -gt 0 -and $null -ne $output[0]) {
                    if ($output[0].Error) { Write-Log "[Get-SMBShareListMany] $($job.Target) : $($output[0].Error)" }
                    $output[0]
                } else {
                    # The runspace returned nothing at all, which is not a shape any caller
                    # should have to handle.
                    [PSCustomObject]@{ ComputerName = $job.Target; Shares = @(); Error = 'The enumeration returned no result' }
                }
            } catch {
                Write-Log "[Get-SMBShareListMany] $($job.Target) failed: $($_.Exception.Message)"
                [PSCustomObject]@{ ComputerName = $job.Target; Shares = @(); Error = "Failed: $($_.Exception.Message)" }
            }
        }
    } finally {
        # Stop is deliberately not called on a job that is still running: a thread stuck in
        # the RPC call does not come back, and waiting for it here is what the deadline
        # above exists to avoid. The process releases them when it exits.
        #
        # Dispose is called on every job, running or not: measured with eight threads
        # asleep for thirty seconds and a two second deadline, it returns at once rather
        # than waiting for them, so there is nothing to be gained by asking first.
        foreach ($job in $jobs) {
            try { $job.Shell.Dispose() } catch { }
        }
        if ($pool) { try { $pool.Dispose() } catch { } }
    }
}
