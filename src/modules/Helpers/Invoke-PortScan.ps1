<#
.SYNOPSIS
    A fast TCP connect scan of hosts, networks and the active computers of the domain.

.DESCRIPTION
    Invoke-PortScan is the scan a tester otherwise does by hand with Test-NetConnection, one
    port at a time and one timeout at a time. It is built from what adPEAS already has:

    - the targets: addresses, networks, ranges and names as given or piped in, or without
      any the active computers of the domain (Get-DomainComputer), resolved through the
      AD-integrated DNS zones (Get-NetworkMapAddressMap) and the domain controller
    - the sweep: Test-TcpPortReachable, which starts a block of connections at once and
      gives the whole block one deadline, so a port that does not answer costs one timeout
      per block rather than one per probe
    - the output: one object per address with an open port, as every adPEAS check shows it,
      and an optional CSV of the open ports to work from

    A connect scan: a port is open when a TCP connection to it completes. Nothing is sent
    over the connection. Refused and filtered are not told apart (see Test-TcpPortReachable).

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

# The ports scanned when none are named: the ones that say whether a host can be reached
# for what a test does next - remote shells (22, 135, 3389, 5985, 5986), the domain (88,
# 389, 636), files (445), databases (1433) and the web ports administrators put consoles
# on. Not 1000 like nmap, and not every service there is: whether the target is reachable
# for those is the question, and a short list answers it in seconds. Ascending, so a scan
# cut short has covered the low ports. A constant, read and never written.
$Script:PortScanDefaultPort = @(22, 80, 88, 135, 389, 443, 445, 636, 1433, 3389, 5985, 5986, 8080, 8443, 9080, 9443)

# The name shown beside an open port - more than the default list, so that a port named with
# -Port is named in the result too. A constant. A hashtable rather than an ordered
# dictionary: the indexer of an ordered dictionary takes an integer as a position, not as a key.
$Script:PortScanServiceName = @{
    21    = 'FTP'
    22    = 'SSH'
    23    = 'Telnet'
    25    = 'SMTP'
    53    = 'DNS'
    80    = 'HTTP'
    88    = 'Kerberos'
    110   = 'POP3'
    111   = 'RPCbind'
    135   = 'RPC'
    139   = 'NetBIOS'
    143   = 'IMAP'
    389   = 'LDAP'
    443   = 'HTTPS'
    445   = 'SMB'
    464   = 'Kpasswd'
    636   = 'LDAPS'
    1433  = 'MSSQL'
    1521  = 'Oracle'
    2049  = 'NFS'
    3268  = 'GC'
    3269  = 'GC-SSL'
    3306  = 'MySQL'
    3389  = 'RDP'
    5432  = 'PostgreSQL'
    5900  = 'VNC'
    5985  = 'WinRM'
    5986  = 'WinRM-HTTPS'
    6379  = 'Redis'
    8000  = 'HTTP-Alt'
    8080  = 'HTTP-Alt'
    8443  = 'HTTPS-Alt'
    9080  = 'HTTP-Alt'
    9389  = 'ADWS'
    9443  = 'HTTPS-Alt'
    27017 = 'MongoDB'
}

# The most addresses one network or range may stand for: a /16. A /8 at 34 ports is 570
# million probes - not a scan anyone means to start by mistyping a prefix.
$Script:PortScanMaxAddresses = 65536

function ConvertTo-PortScanPortList {
    <#
    .SYNOPSIS
    Reads port numbers and ranges into a sorted list without duplicates.

    .DESCRIPTION
    Takes what a tester types: "445", "22,80,443", "1-1024", and any mix of them, as
    strings or numbers. A part that is not a port from 1 to 65535 or a range of them is
    returned as invalid rather than dropped, so the caller can refuse the whole list - a
    scan of the ports that happened to parse is not the scan that was asked for.

    .OUTPUTS
    PSCustomObject with Ports (int[], ascending) and Invalid (the parts that did not parse).

    .NOTES
    Internal helper function
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory=$false)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [string[]]$Port
    )

    $ports = New-Object 'System.Collections.Generic.SortedSet[int]'
    $invalid = New-Object System.Collections.Generic.List[string]

    foreach ($spec in @($Port)) {
        foreach ($part in ([string]$spec).Split(',')) {
            $item = $part.Trim()
            if (-not $item) { continue }

            if ($item -match '^(\d{1,5})$') {
                $from = [int]$Matches[1]
                $to = $from
            } elseif ($item -match '^(\d{1,5})\s*-\s*(\d{1,5})$') {
                $from = [int]$Matches[1]
                $to = [int]$Matches[2]
            } else {
                $invalid.Add($item)
                continue
            }

            if ($from -lt 1 -or $to -gt 65535 -or $from -gt $to) {
                $invalid.Add($item)
                continue
            }
            for ($number = $from; $number -le $to; $number++) { [void]$ports.Add($number) }
        }
    }

    return [PSCustomObject]@{
        Ports   = @($ports)
        Invalid = @($invalid)
    }
}

function ConvertFrom-PortScanIPv4Number {
    <#
    .SYNOPSIS
    Turns the number of an IPv4 address back into its dotted form.

    .NOTES
    Internal helper function. The counterpart of ConvertTo-NetworkMapIPv4Number.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)]
        [long]$Number
    )

    $octets = @(
        [Math]::Floor($Number / 16777216) % 256
        [Math]::Floor($Number / 65536) % 256
        [Math]::Floor($Number / 256) % 256
        $Number % 256
    )
    return ($octets -join '.')
}

function ConvertTo-PortScanTarget {
    <#
    .SYNOPSIS
    Tells what one target stands for: addresses, a name to resolve, or nothing usable.

    .DESCRIPTION
    - an IPv4 address: itself
    - a network, 10.1.2.0/24: its addresses. The network and broadcast address are left
      out down to a /30; a /31 and a /32 have none. An address inside the network is taken
      for the network it is in - 10.1.2.77/24 is 10.1.2.0/24.
    - a range, 10.1.2.10-50 or 10.1.2.10-10.1.3.20: every address from the first to the last
    - anything else that is a host name: the name, for the caller to resolve

    Not taken: a network or range above 65536 addresses, IPv6 (the sweep's sockets are
    IPv4), and anything that is neither an address nor a name - "fs01:445" included.

    .OUTPUTS
    PSCustomObject with Target, Kind ('Address', 'Name' or 'Invalid'), Address, Name and Reason.

    .NOTES
    Internal helper function
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory=$false)]
        [AllowEmptyString()]
        [string]$Target
    )

    $spec = ([string]$Target).Trim()
    $result = [PSCustomObject]@{ Target = $spec; Kind = 'Invalid'; Address = @(); Name = $null; Reason = $null }
    $dotted = '\d{1,3}(?:\.\d{1,3}){3}'

    if ($spec -match "^($dotted)/(\d{1,2})$") {
        $base = ConvertTo-NetworkMapIPv4Number -Address $Matches[1]
        $prefix = [int]$Matches[2]
        if ($null -eq $base -or $prefix -gt 32) { $result.Reason = 'not an IPv4 network'; return $result }
        if ([Math]::Pow(2, 32 - $prefix) -gt $Script:PortScanMaxAddresses) {
            $result.Reason = 'larger than a /16'
            return $result
        }
        $first = $base -band (Get-NetworkMapPrefixMask -PrefixLength $prefix)
        $last = $first + [long][Math]::Pow(2, 32 - $prefix) - 1
        if ($prefix -le 30) { $first++; $last-- }
    } elseif ($spec -match "^($dotted)-($dotted|\d{1,3})$") {
        $startText = $Matches[1]
        $endText = $Matches[2]
        # The short form names the last octet only.
        if ($endText -notmatch '\.') { $endText = $startText.Substring(0, $startText.LastIndexOf('.') + 1) + $endText }
        $first = ConvertTo-NetworkMapIPv4Number -Address $startText
        $last = ConvertTo-NetworkMapIPv4Number -Address $endText
        if ($null -eq $first -or $null -eq $last) { $result.Reason = 'not an IPv4 range'; return $result }
        if ($last -lt $first) { $result.Reason = 'the range ends before it starts'; return $result }
        if (($last - $first + 1) -gt $Script:PortScanMaxAddresses) {
            $result.Reason = 'more than 65536 addresses'
            return $result
        }
    } elseif ($spec -match "^$dotted$") {
        $first = ConvertTo-NetworkMapIPv4Number -Address $spec
        if ($null -eq $first) { $result.Reason = 'not an IPv4 address'; return $result }
        $last = $first
    } elseif ($spec.Contains(':')) {
        $result.Reason = if ($spec -match '^[^:]+:\d+$') { 'a port belongs in -Port' } else { 'IPv6 is not scanned' }
        return $result
    } elseif ($spec -match '^[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_-])?\.?$') {
        $result.Kind = 'Name'
        $result.Name = $spec.TrimEnd('.')
        return $result
    } else {
        $result.Reason = 'not an address, a network or a name'
        return $result
    }

    $addresses = New-Object System.Collections.Generic.List[string]
    for ($number = $first; $number -le $last; $number++) {
        $addresses.Add((ConvertFrom-PortScanIPv4Number -Number $number))
    }
    $result.Kind = 'Address'
    $result.Address = @($addresses)
    return $result
}

function Start-NameResolution {
    <#
    .SYNOPSIS
    Starts the resolution of one name and returns its handle.

    .DESCRIPTION
    A seam of one line, so that a resolution that never comes back is reachable from a test.

    .NOTES
    Internal helper function
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    return [System.Net.Dns]::BeginGetHostAddresses($Name, $null, $null)
}

function Resolve-PortScanName {
    <#
    .SYNOPSIS
    Resolves many names at once, in blocks with one deadline each.

    .DESCRIPTION
    The system resolver, which for a short name tries the DNS suffixes and then LLMNR and
    NetBIOS - several seconds for a name that does not exist. Started all at once and given
    one deadline per block, a list of names costs one wait rather than one per name, and a
    name that has not resolved by then is not waited for any longer.

    Each name is resolved once here rather than once per port by the connection itself, so
    a name that does not resolve is reported as that rather than as a host without an open
    port. IPv4 only: the sweep's sockets are IPv4.

    .OUTPUTS
    PSCustomObject per name, in the order given: Name and Address (the IPv4 addresses, none
    when it did not resolve in time).

    .NOTES
    Internal helper function
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        # An empty name is skipped below rather than refused by the binder.
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [AllowNull()]
        [string[]]$Name,

        [Parameter(Mandatory=$false)]
        [ValidateRange(50, 60000)]
        [int]$TimeoutMs = 3000,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1, 1024)]
        [int]$BatchSize = 256
    )

    $names = @($Name | Where-Object { $_ })

    for ($offset = 0; $offset -lt $names.Count; $offset += $BatchSize) {
        $last = [Math]::Min($offset + $BatchSize, $names.Count) - 1
        $pending = New-Object System.Collections.Generic.List[object]

        foreach ($one in $names[$offset..$last]) {
            try {
                $pending.Add([PSCustomObject]@{ Name = $one; Handle = (Start-NameResolution -Name $one) })
            } catch {
                # A name the resolver refuses outright - too long, or a character it does
                # not take. It has no address, which is what the caller reports.
                Write-Log "[Resolve-PortScanName] $one could not be resolved: $($_.Exception.Message)"
                $pending.Add([PSCustomObject]@{ Name = $one; Handle = $null })
            }
        }

        $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
        foreach ($entry in $pending) {
            $addresses = @()
            if ($entry.Handle) {
                $left = [int][Math]::Ceiling(($deadline - [DateTime]::UtcNow).TotalMilliseconds)
                if ($left -lt 0) { $left = 0 }
                $done = $false
                try { $done = $entry.Handle.AsyncWaitHandle.WaitOne($left, $false) } catch { }
                if ($done) {
                    try {
                        $addresses = @([System.Net.Dns]::EndGetHostAddresses($entry.Handle) |
                            Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                            ForEach-Object { $_.IPAddressToString })
                    } catch {
                        Write-Log "[Resolve-PortScanName] $($entry.Name) did not resolve: $($_.Exception.Message)"
                    }
                } else {
                    Write-Log "[Resolve-PortScanName] $($entry.Name) did not resolve within $TimeoutMs ms"
                }
            }
            [PSCustomObject]@{ Name = $entry.Name; Address = $addresses }
        }
    }
}

function Get-PortScanBlock {
    <#
    .SYNOPSIS
    Cuts a scan into blocks of at most BatchSize probes, each one call of the sweep.

    .DESCRIPTION
    Test-TcpPortReachable gives each block one deadline, so a block should be full: a
    block of one probe spends a whole timeout on a port that does not answer. With at
    least BatchSize addresses, a block is a slice of the addresses on one port. With fewer,
    a block is every address on as many ports as fill it - one host on 1000 ports is four
    blocks, not 1000.

    .OUTPUTS
    PSCustomObject per block: Target and Port.

    .NOTES
    Internal helper function
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [string[]]$Address,

        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [int[]]$Port,

        [Parameter(Mandatory=$true)]
        [ValidateRange(1, 1024)]
        [int]$BatchSize
    )

    if ($Address.Count -eq 0 -or $Port.Count -eq 0) { return }

    if ($Address.Count -ge $BatchSize) {
        foreach ($onePort in $Port) {
            for ($offset = 0; $offset -lt $Address.Count; $offset += $BatchSize) {
                $last = [Math]::Min($offset + $BatchSize, $Address.Count) - 1
                [PSCustomObject]@{ Target = @($Address[$offset..$last]); Port = @($onePort) }
            }
        }
    } else {
        $portsPerBlock = [int][Math]::Floor($BatchSize / $Address.Count)
        for ($offset = 0; $offset -lt $Port.Count; $offset += $portsPerBlock) {
            $last = [Math]::Min($offset + $portsPerBlock, $Port.Count) - 1
            [PSCustomObject]@{ Target = @($Address); Port = @($Port[$offset..$last]) }
        }
    }
}

function Invoke-PortScan {
    <#
    .SYNOPSIS
    Scans hosts, networks or, on request, the active computers of the domain for open TCP ports.

    .DESCRIPTION
    A TCP connect scan built for the system a tester is working from: no installation, no
    driver, no waiting on one timeout per port. Connections are started a block at a time
    and the block gets one deadline, so 254 hosts on the 16 default ports that drop every
    packet take about 20 seconds at the default timeout (measured: 16 blocks of one second,
    and the sockets themselves) rather than over an hour.

    The targets:
    - given as -Target or piped in: IPv4 addresses, networks (10.1.2.0/24), ranges
      (10.1.2.10-50, 10.1.2.10-10.1.3.20) and host names, in any mix - also the objects
      every Get-Domain* function returns, by their dNSHostName. A name is resolved once, by
      this machine's resolver, before the scan.
    - with -DomainComputers: the enabled computers of the domain with a logon in the last 30
      days (-ActiveDays), by DNS name - only a name below the domain's own, since a computer
      account may write its dNSHostName itself. Their addresses come from the AD-integrated
      DNS zones over LDAP, and for a name the zones do not hold, from the domain controller -
      a computer name of the domain is not sent to a resolver outside it. Together with
      targets given, both are scanned.

    Without either there is nothing to scan, and the call says so: a domain-wide scan is
    something to ask for, not what a forgotten -Target turns into.

    Every address is scanned once, however many targets stand for it.

    .PARAMETER Target
    Addresses, networks, ranges or host names. An empty pipeline scans nothing.

    .PARAMETER DomainComputers
    Scans the enabled computers of the domain with a logon in the last -ActiveDays days, as
    well as any targets given. Needs a session, or -Domain and a way to log on.

    .PARAMETER Port
    Ports and ranges: 445, '22,80,443', '1-1024', or a mix. Default: 22, 80, 88, 135, 389,
    443, 445, 636, 1433, 3389, 5985, 5986, 8080, 8443, 9080, 9443 - whether a host can be
    reached for a remote shell, the domain, files, a database or a web console.

    .PARAMETER TimeoutMs
    How long one block of connections is given. Default 1000. A port that answers later is
    reported closed; on a slow link raise it.

    .PARAMETER BatchSize
    How many connections are in flight at once. Default 256.

    .PARAMETER ActiveDays
    With -DomainComputers: how recent the last logon of a computer has to be. Default 30.

    .PARAMETER ExportOpenPorts
    Writes the open ports to this file as CSV, one row per open port, sorted by address:
    IPAddress, HostName, Port and Service. UTF-8, comma-separated whatever the locale of this
    machine, so Import-Csv reads it back anywhere - and a row piped on binds by IPAddress, to
    Invoke-PortScan as to Invoke-ShareHunt. An existing file is overwritten; nothing is
    written when no port is open.

    A host without an open port has no row: the file is the list of what was found, and
    what was scanned is the call that wrote it.

    .PARAMETER PassThru
    Returns one object per address with an open port: ComputerName (the name it was found
    under, or the address), IPAddress and OpenPorts. ComputerName is what Invoke-ShareHunt
    takes from the pipeline.

    .PARAMETER Domain
    Target domain, for the scan of the domain's computers.

    .PARAMETER Server
    Domain Controller to query, for the scan of the domain's computers.

    .PARAMETER Credential
    PSCredential object for authentication, for the scan of the domain's computers.

    .EXAMPLE
    Invoke-PortScan -Target 10.1.2.0/24

    .EXAMPLE
    Invoke-PortScan 10.1.2.10-50 -Port 22,80,443,8000-8100 -TimeoutMs 500

    .EXAMPLE
    Get-Content .\subnets.txt | Invoke-PortScan -Port 445 -ExportOpenPorts .\smb.csv

    .EXAMPLE
    Import-Csv .\open.csv | Where-Object Port -eq 5985 | Invoke-PortScan -Port 1-1024
    The hosts a first scan found with WinRM, scanned again on more ports.

    .EXAMPLE
    Get-DomainComputer -OperatingSystem '*Server*' | Invoke-PortScan -Port 1433,3306,5432

    .EXAMPLE
    Invoke-PortScan -Target 10.1.2.0/24 -Port 445 -PassThru | Invoke-ShareHunt

    .EXAMPLE
    Invoke-PortScan -DomainComputers -Domain contoso.com -Credential (Get-Credential)
    The active computers of the domain, on the default ports.

    .NOTES
    Author: Alexander Sturz (@_61106960_)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('ComputerName', 'DNSHostName', 'Name', 'CN', 'IPAddress')]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [AllowNull()]
        [string[]]$Target,

        [Parameter(Mandatory=$false, Position=1)]
        [string[]]$Port,

        [Parameter(Mandatory=$false)]
        [ValidateRange(50, 60000)]
        [int]$TimeoutMs = 1000,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1, 1024)]
        [int]$BatchSize = 256,

        [Parameter(Mandatory=$false)]
        [switch]$DomainComputers,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1, 3650)]
        [int]$ActiveDays = 30,

        [Parameter(Mandatory=$false)]
        [string]$ExportOpenPorts,

        [Parameter(Mandatory=$false)]
        [switch]$PassThru,

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    begin {
        Write-Log "[Invoke-PortScan] Starting"

        # Filled by process{}, used once by end{}.
        $givenTargets = New-Object System.Collections.Generic.List[string]
        $givenNameless = 0
        $targetsWereGiven = $false
    }

    process {
        # Collects and nothing else; the scan runs once, in end{}, over everything piped in.
        if (-not $PSBoundParameters.ContainsKey('Target')) { return }
        $targetsWereGiven = $true
        foreach ($one in @($Target)) {
            $trimmed = ([string]$one).Trim()
            if ($trimmed) { $givenTargets.Add($trimmed) } else { $givenNameless++ }
        }
    }

    end {
        try {
            # ===== The ports =====
            # Checked before anything else: a mistyped port list must not cost a domain query.
            $portList = if ($PSBoundParameters.ContainsKey('Port')) {
                ConvertTo-PortScanPortList -Port $Port
            } else {
                [PSCustomObject]@{ Ports = @($Script:PortScanDefaultPort); Invalid = @() }
            }
            if (@($portList.Invalid).Count -gt 0) {
                Write-Error "Not a port or a port range: $(@($portList.Invalid) -join ', '). Expected numbers from 1 to 65535, such as 445, 22,80 or 1-1024."
                return
            }
            $ports = @($portList.Ports)
            if ($ports.Count -eq 0) {
                Write-Error "No port to scan."
                return
            }

            # ExpectingInput as well as the flag: an empty pipeline binds nothing, so the
            # flag alone cannot tell "@() | Invoke-PortScan" from a call with no targets.
            # The first scans nothing; the second is refused.
            $targetsGiven = $targetsWereGiven -or $PSCmdlet.MyInvocation.ExpectingInput
            if (-not $targetsGiven -and -not $DomainComputers) {
                Write-Error "No target to scan. Name one with -Target or pipe targets in; -DomainComputers scans the active computers of the domain."
                return
            }

            Show-SubHeader "Scanning for open ports..." -ObjectType "OpenPorts"

            # Every address once, with every name it was reached under.
            $scanTargets = New-Object 'System.Collections.Generic.Dictionary[string,object]'
            $invalidTargets = New-Object System.Collections.Generic.List[string]
            $unresolved = New-Object System.Collections.Generic.List[string]
            $withoutDnsName = 0
            $outsideDomain = 0
            $domainFQDN = $null

            function Add-ScanAddress {
                param([string]$Address, [string]$HostName)
                if (-not $scanTargets.ContainsKey($Address)) {
                    $scanTargets[$Address] = [PSCustomObject]@{
                        Address = $Address
                        Number  = ConvertTo-NetworkMapIPv4Number -Address $Address
                        Names   = New-Object System.Collections.Generic.List[string]
                    }
                }
                if ($HostName -and -not $scanTargets[$Address].Names.Contains($HostName)) {
                    $scanTargets[$Address].Names.Add($HostName)
                }
            }

            # ===== The targets given =====
            if ($targetsGiven) {
                $names = New-Object System.Collections.Generic.List[string]
                $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($spec in @($givenTargets | Select-Object -Unique)) {
                    $parsed = ConvertTo-PortScanTarget -Target $spec
                    if ($parsed.Kind -eq 'Address') {
                        foreach ($address in $parsed.Address) { Add-ScanAddress -Address $address }
                    } elseif ($parsed.Kind -eq 'Name') {
                        if ($seen.Add($parsed.Name)) { $names.Add($parsed.Name) }
                    } else {
                        $invalidTargets.Add("$spec ($($parsed.Reason))")
                    }
                }

                if ($names.Count -gt 0) {
                    Show-Progress -Activity 'Port scan' -Current 1 -Total 1 -Status "Resolving $($names.Count) name(s)"
                    foreach ($resolved in @(Resolve-PortScanName -Name @($names))) {
                        if (@($resolved.Address).Count -eq 0) { $unresolved.Add($resolved.Name); continue }
                        foreach ($address in $resolved.Address) { Add-ScanAddress -Address $address -HostName $resolved.Name }
                    }
                }
            }

            # ===== The computers of the domain, when asked for =====
            if ($DomainComputers) {
                # Connection parameters only: splatting $PSBoundParameters would hand
                # Ensure-LDAPConnection parameters it does not have.
                $connectionParams = @{}
                if ($PSBoundParameters.ContainsKey('Domain'))     { $connectionParams['Domain'] = $Domain }
                if ($PSBoundParameters.ContainsKey('Server'))     { $connectionParams['Server'] = $Server }
                if ($PSBoundParameters.ContainsKey('Credential')) { $connectionParams['Credential'] = $Credential }

                if (-not (Ensure-LDAPConnection @connectionParams)) {
                    return
                }

                $domainFQDN = ([string]$Script:LDAPContext.Domain).Trim().TrimEnd('.').ToLowerInvariant()
                $since = (Get-Date).AddDays(-$ActiveDays).ToFileTime()
                Show-Progress -Activity 'Port scan' -Current 1 -Total 1 -Status 'Looking for the active computers of the domain'
                # Only the attribute the scan needs: nothing of the computer objects is
                # shown, so the -Properties rule for displayed objects does not apply.
                $computers = @(Get-DomainComputer -Enabled -LDAPFilter "(lastLogonTimestamp>=$since)" -Properties 'dNSHostName' @connectionParams)

                $names = New-Object System.Collections.Generic.List[string]
                $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($computer in $computers) {
                    $fqdn = ([string]$computer.dNSHostName).Trim().TrimEnd('.').ToLowerInvariant()
                    if (-not $fqdn) { $withoutDnsName++; continue }
                    # The computer account may write its own dNSHostName; a name outside the
                    # domain is one this scan was not asked to contact.
                    if (-not $fqdn.EndsWith(".$domainFQDN")) { $outsideDomain++; continue }
                    if ($seen.Add($fqdn)) { $names.Add($fqdn) }
                }
                Write-Log "[Invoke-PortScan] $($names.Count) active computer(s) of the domain"

                if ($names.Count -gt 0) {
                    Show-Progress -Activity 'Port scan' -Current 1 -Total 1 -Status "Resolving $($names.Count) computer name(s)"
                    $zoneAddresses = (Get-NetworkMapAddressMap -Name @($names) @connectionParams).Addresses
                    $dnsServer = $null
                    if ($Script:LDAPContext['DnsServer']) { $dnsServer = [string]$Script:LDAPContext['DnsServer'] }
                    elseif ($Script:LDAPContext['ServerIP']) { $dnsServer = [string]$Script:LDAPContext['ServerIP'] }

                    $index = 0
                    foreach ($name in $names) {
                        $index++
                        $candidates = if ($zoneAddresses.ContainsKey($name)) {
                            @($zoneAddresses[$name].IPv4)
                        } else {
                            Show-Progress -Activity 'Port scan' -Current $index -Total $names.Count -Status "Resolving computer names at the domain controller" -ObjectName $name
                            @(Resolve-NetworkMapName -Name $name -DnsServer $dnsServer)
                        }
                        # A record for 127.0.0.1 or a link-local address is registered, but it
                        # is not where the computer can be reached.
                        $usable = @($candidates | Where-Object {
                            $number = ConvertTo-NetworkMapIPv4Number -Address $_
                            ($null -ne $number) -and (Test-NetworkMapUsableIPv4 -Number $number)
                        })
                        if ($usable.Count -eq 0) { $unresolved.Add($name); continue }
                        foreach ($address in $usable) { Add-ScanAddress -Address $address -HostName $name }
                    }
                }
            }

            # ===== The scan =====
            $addresses = @($scanTargets.Values | Sort-Object -Property Number | ForEach-Object { $_.Address })
            $probeTotal = $addresses.Count * $ports.Count
            $openByAddress = @{}
            $openTotal = 0
            $probed = 0
            $clock = [System.Diagnostics.Stopwatch]::StartNew()

            foreach ($block in @(Get-PortScanBlock -Address $addresses -Port $ports -BatchSize $BatchSize)) {
                Show-Progress -Activity 'Port scan' -Current ([Math]::Max(1, $probed)) -Total $probeTotal `
                    -Status "$probed of $probeTotal probe(s), $openTotal open port(s)"
                foreach ($answer in @(Test-TcpPortReachable -Target $block.Target -Port $block.Port -TimeoutMs $TimeoutMs -BatchSize $BatchSize)) {
                    $probed++
                    if (-not $answer.Reachable) { continue }
                    if (-not $openByAddress.ContainsKey($answer.Target)) {
                        $openByAddress[$answer.Target] = New-Object 'System.Collections.Generic.SortedSet[int]'
                    }
                    # Every pair is probed once, so every answer is a port not counted yet.
                    [void]$openByAddress[$answer.Target].Add([int]$answer.Port)
                    $openTotal++
                }
            }
            $clock.Stop()
            Show-Progress -Activity 'Port scan' -Completed
            Write-Log "[Invoke-PortScan] $openTotal open port(s) on $($openByAddress.Count) of $($addresses.Count) address(es)"

            # ===== What was not scanned, and the result =====
            if ($invalidTargets.Count -gt 0) {
                Show-Line "$($invalidTargets.Count) target(s) skipped: $($invalidTargets -join ', ')" -Class Hint
            }
            if ($outsideDomain -gt 0) {
                Show-Line "$outsideDomain active computer(s) with a DNS name outside $domainFQDN - not scanned" -Class Note
            }
            if ($withoutDnsName -gt 0) {
                Show-Line "$withoutDnsName active computer(s) without a DNS name (dNSHostName) - not scanned" -Class Note
            }
            if ($givenNameless -gt 0) {
                Show-Line "$givenNameless target(s) without a name - not scanned" -Class Note
            }
            if ($unresolved.Count -gt 0) {
                $shown = @($unresolved | Select-Object -First 10)
                $more = if ($unresolved.Count -gt $shown.Count) { " and $($unresolved.Count - $shown.Count) more" } else { '' }
                Show-Line "$($unresolved.Count) name(s) without an address - not scanned: $($shown -join ', ')$more" -Class Note
            }

            if ($addresses.Count -eq 0) {
                Show-Line "No address to scan" -Class Note
                return
            }

            $seconds = [Math]::Round($clock.Elapsed.TotalSeconds, 1)
            Show-Line "Scanned $($addresses.Count) address(es) on $($ports.Count) port(s) in $seconds s" -Class Note

            if ($openTotal -eq 0) {
                Show-Line "No open port found" -Class Note
            } else {
                Show-Line "Found $openTotal open port(s) on $($openByAddress.Count) address(es):" -Class Note
            }

            $exportRows = New-Object System.Collections.Generic.List[object]
            foreach ($address in $addresses) {
                if (-not $openByAddress.ContainsKey($address)) { continue }
                $open = @($openByAddress[$address])
                $hostNames = @($scanTargets[$address].Names)

                $display = [PSCustomObject][ordered]@{
                    Name      = if ($hostNames.Count -gt 0) { $hostNames[0] } else { $address }
                    hostName  = if ($hostNames.Count -gt 0) { $hostNames -join ', ' } else { $null }
                    ipAddress = $address
                    openPorts = @($open | ForEach-Object {
                        if ($Script:PortScanServiceName.ContainsKey($_)) { "$_ ($($Script:PortScanServiceName[$_]))" } else { "$_" }
                    })
                }
                $display | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'OpenPorts' -Force
                Show-Object $display -Class Note

                foreach ($one in $open) {
                    $exportRows.Add([PSCustomObject][ordered]@{
                        IPAddress = $address
                        # A string, not $null: Windows PowerShell 5.1 writes $null as a bare
                        # empty field where every other field is quoted.
                        HostName  = [string]$display.hostName
                        Port      = $one
                        Service   = if ($Script:PortScanServiceName.ContainsKey($one)) { $Script:PortScanServiceName[$one] } else { '' }
                    })
                }

                if ($PassThru) {
                    [PSCustomObject]@{
                        ComputerName = $display.Name
                        IPAddress    = $address
                        OpenPorts    = $open
                    }
                }
            }

            if ($ExportOpenPorts) {
                if ($exportRows.Count -eq 0) {
                    Show-Line "No open port to write to $ExportOpenPorts" -Class Note
                } else {
                    # Comma, not the list separator of this machine's culture: a German
                    # Windows would write semicolons, which Import-Csv elsewhere does not read.
                    $csv = @($exportRows | ConvertTo-Csv -NoTypeInformation)
                    $export = Export-adPEASFile -Path $ExportOpenPorts -Content (($csv -join "`r`n") + "`r`n") -Type Text -Force -SanitizeFilename:$false
                    if ($export.Success) {
                        Show-Line "Wrote $($exportRows.Count) open port(s) to $($export.Path)" -Class Note
                    } else {
                        Show-Line "The open ports could not be written to ${ExportOpenPorts}: $($export.Message)" -Class Hint
                    }
                }
            }

        } catch {
            Show-Progress -Activity 'Port scan' -Completed
            Write-Log "[Invoke-PortScan] Error: $_" -Level Error
            Show-Line "Error during the port scan: $_" -Class Finding
        }
    }
}
