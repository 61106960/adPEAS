<#
.SYNOPSIS
    Finds the file shares of a host over SMB and tells the ones worth reading from the rest.

.DESCRIPTION
    The three steps Invoke-ShareHunt needs before it reads a single file, each callable on
    its own:

    - Test-TcpPortReachable: which hosts answer on port 445 at all
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
    Tells which of many hosts answer on a TCP port, in blocks with one deadline each.

    .DESCRIPTION
    Every target in a block gets a connection attempt started at once (BeginConnect, which
    returns immediately), then the block is given TimeoutMs to finish. A target that has
    connected by then is reachable; everything else is not, whether it was refused, filtered
    or simply slow. No thread is created for any of it.

    The deadline is per block, not per target: a block of 256 unreachable hosts costs one
    timeout, not 256. That is the whole point of the function.

    .PARAMETER Target
    Host names or addresses. A name is resolved by the system resolver, so the caller
    decides what to pass - an address avoids the lookup, a host name is what Kerberos needs.

    .PARAMETER Port
    The port. Default 445 (SMB).

    .PARAMETER TimeoutMs
    How long one block is given. Default 1000.

    .PARAMETER BatchSize
    How many connections are in flight at once. Default 256.

    .OUTPUTS
    PSCustomObject per target: Target and Reachable.

    .EXAMPLE
    Test-TcpPortReachable -Target '10.1.2.21', '10.1.2.22'

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
        [int]$Port = 445,

        [Parameter(Mandatory = $false)]
        [ValidateRange(50, 60000)]
        [int]$TimeoutMs = 1000,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 1024)]
        [int]$BatchSize = 256
    )

    # No guard for an empty list: the loop below then runs zero times.
    $targets = @($Target | Where-Object { $_ })

    for ($offset = 0; $offset -lt $targets.Count; $offset += $BatchSize) {
        $last = [Math]::Min($offset + $BatchSize, $targets.Count) - 1
        $pending = New-Object System.Collections.Generic.List[object]

        foreach ($one in $targets[$offset..$last]) {
            try {
                $attempt = Start-TcpConnectAttempt -Target $one -Port $Port
                $pending.Add([PSCustomObject]@{ Target = $one; Client = $attempt.Client; Handle = $attempt.Handle })
            } catch {
                # The socket itself failed - the machine is out of them. The sweep goes on
                # with the next target; this one is simply not known to be reachable.
                Write-Log "[Test-TcpPortReachable] $one could not be probed: $($_.Exception.Message)"
                [PSCustomObject]@{ Target = $one; Reachable = $false }
            }
        }

        # One deadline for the whole block. Waiting on each handle in turn would add up to
        # the per-host timeout again for every host that does not answer.
        $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
        foreach ($entry in $pending) {
            $left = [int][Math]::Ceiling(($deadline - [DateTime]::UtcNow).TotalMilliseconds)
            if ($left -lt 0) { $left = 0 }
            $done = $false
            try { $done = $entry.Handle.AsyncWaitHandle.WaitOne($left, $false) } catch { }

            $reachable = $false
            if ($done) {
                # Connected rather than refused: EndConnect throws on a refusal, and
                # BeginConnect signals the handle either way.
                try { $entry.Client.EndConnect($entry.Handle); $reachable = $true } catch { }
            }
            try { $entry.Client.Close() } catch { }
            try { $entry.Client.Dispose() } catch { }

            [PSCustomObject]@{ Target = $entry.Target; Reachable = $reachable }
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

function Test-ShareWorthScanning {
    <#
    .SYNOPSIS
    Decides whether a credential scan should look at one share.

    .DESCRIPTION
    Left out, and why:

    - Anything that is not a disk share. A printer queue and an IPC pipe hold no files.
    - The administrative shares. C$ and ADMIN$ are the whole volume and the Windows
      directory, reachable only as an administrator, and walking them means walking every
      file of the machine. They are told by the special flag and by their name, because a
      share named C$ that does not carry the flag is still the volume.
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
    Takes the administrative shares as well.

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
        # Two tests, because either can be true without the other: a share named C$ that
        # does not carry the special flag is still the volume, and a special share need not
        # be named with a dollar. print$, the driver store, is covered by its name.
        if ($decoded.IsSpecial -or $trimmed.EndsWith('$')) {
            return [PSCustomObject]@{ Scan = $false; Reason = 'Administrative share' }
        }
    }
    if (-not $IncludeSysvol -and ($trimmed -ieq 'SYSVOL' -or $trimmed -ieq 'NETLOGON')) {
        return [PSCustomObject]@{ Scan = $false; Reason = 'Read by Get-CredentialExposure' }
    }

    return [PSCustomObject]@{ Scan = $true; Reason = $null }
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

    if (-not ([System.Management.Automation.PSTypeName]'adPEAS.NativeMethods.Shares').Type) {
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
            Write-Log "[Get-SMBShareList] P/Invoke types compiled successfully"
        } catch {
            if ($_.Exception.Message -notmatch 'already exists') {
                return [PSCustomObject]@{ ComputerName = $ComputerName; Shares = @(); Error = "P/Invoke types could not be compiled: $($_.Exception.Message)" }
            }
        }
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
