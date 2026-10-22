function ConvertTo-NetworkMapIPv4Number {
    <#
    .SYNOPSIS
    Turns a dotted IPv4 address into its number, and anything else into no output at all.

    .NOTES
    Internal helper function. Int64, so that the bitwise operators of Windows PowerShell 5.1
    never see a negative Int32 for an address from 128.0.0.0 on. No output rather than
    $null: a function's $null is an element of the pipeline it writes to.
    #>
    [CmdletBinding()]
    [OutputType([long])]
    param(
        [Parameter(Mandatory=$false)]
        [AllowEmptyString()]
        [string]$Address
    )

    # The dotted quad only - TryParse also takes "10.1" and "167772161" - and TryParse then
    # for an octet above 255.
    if ($Address -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return }
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$parsed)) { return }

    $b = $parsed.GetAddressBytes()
    return ([long]$b[0] * 16777216) + ([long]$b[1] * 65536) + ([long]$b[2] * 256) + [long]$b[3]
}

function Get-NetworkMapPrefixMask {
    <#
    .SYNOPSIS
    The netmask of a prefix length, as a number.

    .NOTES
    Internal helper function
    #>
    [CmdletBinding()]
    [OutputType([long])]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateRange(0, 32)]
        [int]$PrefixLength
    )

    return [long](4294967296 - [Math]::Pow(2, 32 - $PrefixLength))
}

function Test-NetworkMapUsableIPv4 {
    <#
    .SYNOPSIS
    Tells an address a computer can be reached at from one it cannot.

    .DESCRIPTION
    0.0.0.0/8 and 127.0.0.0/8 name this host, 169.254.0.0/16 is the address Windows gives
    itself when DHCP does not answer, and from 224.0.0.0 on there is multicast and the
    reserved range. A record with one of those is registered and says nothing about where
    the computer is.

    .NOTES
    Internal helper function
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory=$true)]
        [long]$Number
    )

    $first = [Math]::Floor($Number / 16777216)
    if ($first -eq 0 -or $first -eq 127 -or $first -ge 224) { return $false }
    if ([Math]::Floor($Number / 65536) -eq ((169 * 256) + 254)) { return $false }
    return $true
}

function Resolve-NetworkMapName {
    <#
    .SYNOPSIS
    Resolves the A records of one name by a DNS query to the domain controller.

    .DESCRIPTION
    The fallback of Get-NetworkMap for a name the AD-integrated zones did not hold. It asks
    the given server and no other. Resolve-HostnameToIP falls back to the resolver of this
    machine, which on a tester's own laptop is a server outside the domain, and a computer
    name of the domain has no business there - least of all one the domain's own DNS server
    did not know. Without a server, which is a session on a domain-joined machine where no
    address of a domain controller was recorded, the resolver of this machine is the
    domain's.

    Every A record of the name is returned, not the first.

    .NOTES
    Internal helper function
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [Parameter(Mandatory=$false)]
        [string]$DnsServer
    )

    if ($DnsServer) {
        try {
            return @(Resolve-DnsName -Name $Name -Server $DnsServer -Type A -DnsOnly -QuickTimeout -ErrorAction Stop |
                Where-Object { $_.Type -eq 'A' } | ForEach-Object { [string]$_.IPAddress })
        } catch [System.Management.Automation.CommandNotFoundException] {
            # Windows 7 and Server 2008 R2 have no Resolve-DnsName.
            $address = Invoke-RawDnsQuery -Name $Name -DnsServer $DnsServer -Type A -Timeout 2000
            return @($address | Where-Object { $_ })
        } catch {
            Write-Log "[Get-NetworkMap] $Name did not resolve at ${DnsServer}: $($_.Exception.Message)"
            return @()
        }
    }

    try {
        return @([System.Net.Dns]::GetHostAddresses($Name) |
            Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
            ForEach-Object { $_.IPAddressToString })
    } catch {
        Write-Log "[Get-NetworkMap] $Name did not resolve: $($_.Exception.Message)"
        return @()
    }
}

function Get-NetworkMapAddressMap {
    <#
    .SYNOPSIS
    The addresses the AD-integrated DNS zones hold for a set of names.

    .DESCRIPTION
    One LDAP pass over the zones instead of a DNS query per name, and nothing leaves the
    domain: a tester's own machine may resolve through a server that has no business
    learning the domain's computer names. Get-NetworkMap and Invoke-PortScan start from it
    and ask the domain controller only for the names it did not hold.

    Only the zones a name falls in are read: a zone is relevant when it is a suffix of one
    of the names, and the suffixes of every name are collected once. The name itself is one
    of them - a pinpoint zone is named after its only host, and the address is the record
    of the zone itself.

    The same name in two zones - a zone stored in two partitions during a migration -
    contributes the addresses of both. Zones that cannot be read leave the map empty
    rather than failing; the caller falls back to its DNS query per name.

    .OUTPUTS
    PSCustomObject: Addresses, a case-insensitive dictionary of name to an entry with IPv4
    and IPv6 lists, and ZonesRead, how many zones were read - none at all is what tells a
    domain without the zones from zones that could not be read.

    .NOTES
    Internal helper function
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [string[]]$Name,

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    $connectionParams = @{}
    if ($PSBoundParameters.ContainsKey('Domain'))     { $connectionParams['Domain'] = $Domain }
    if ($PSBoundParameters.ContainsKey('Server'))     { $connectionParams['Server'] = $Server }
    if ($PSBoundParameters.ContainsKey('Credential')) { $connectionParams['Credential'] = $Credential }

    $addressMap = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $zonesRead = 0
    $names = @($Name | Where-Object { $_ })
    if ($names.Count -eq 0) { return [PSCustomObject]@{ Addresses = $addressMap; ZonesRead = $zonesRead } }

    try {
        $suffixes = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($one in $names) {
            $labels = ([string]$one).Split('.')
            for ($i = 0; $i -lt $labels.Count; $i++) {
                [void]$suffixes.Add(($labels[$i..($labels.Count - 1)] -join '.'))
            }
        }
        $zones = @(Get-DomainDNSZone @connectionParams | Where-Object { $suffixes.Contains([string]$_.Name) })
        $zonesRead = $zones.Count
        if ($zones.Count -gt 0) {
            foreach ($record in @(Get-DomainDNSRecord -Zone $zones @connectionParams)) {
                if (-not $addressMap.ContainsKey($record.Name)) {
                    $addressMap[$record.Name] = [PSCustomObject]@{
                        IPv4 = New-Object System.Collections.Generic.List[string]
                        IPv6 = New-Object System.Collections.Generic.List[string]
                    }
                }
                $entry = $addressMap[$record.Name]
                foreach ($address in @($record.IPv4Address)) { $entry.IPv4.Add([string]$address) }
                foreach ($address in @($record.IPv6Address)) { $entry.IPv6.Add([string]$address) }
            }
        }
    } catch {
        Write-Log "[Get-NetworkMapAddressMap] The AD-integrated DNS zones could not be read: $_"
    }
    Write-Log "[Get-NetworkMapAddressMap] $($addressMap.Count) name(s) with an address in $zonesRead zone(s)"
    return [PSCustomObject]@{ Addresses = $addressMap; ZonesRead = $zonesRead }
}

function Get-NetworkMap {
    <#
    .SYNOPSIS
    Maps the IP subnets the active computers of the domain are in, and the OUs they sit in.

    .DESCRIPTION
    Which networks hold which systems is the first question of an internal assessment, and
    the domain answers it better than a scan: every active computer has a DNS name and an
    address, and the OU it sits in usually says what it is - workstations, servers, a site,
    a department. This check puts the two together, one object per /24 subnet that holds an
    active computer, with the OUs and containers those computers are in. The computers
    themselves are not listed; the question is which network holds what.

    Active means an enabled computer account whose lastLogonTimestamp lies within the last
    ActiveDays days. The attribute is replicated only once it is older than
    ms-DS-Logon-Time-Sync-Interval allows - 9 to 14 days by default - so a window shorter
    than 14 days misses computers that are in use.

    The name of a computer is its dNSHostName, and it is resolved only when it lies below
    the DNS name of the domain. The computer account may write that attribute itself, and
    with msDS-AllowedDNSSuffixes even a name outside the domain; whoever controls an account
    would otherwise choose a name this check looks up. Computers outside the domain's name
    are counted, not resolved.

    The addresses come from the AD-integrated DNS zones the names fall in, read over LDAP
    from the connected domain controller: one search per zone, no DNS query, and every
    address of a name. A name not found there - its zone is not stored in Active Directory,
    or its record is hidden from this account - is resolved by a DNS query to the domain
    controller, unless -OPSEC is set.

    Where Sites and Services defines the subnet of an address, the object names the most
    specific one with its site. A subnet with computers that no defined subnet contains is
    worth a look: its clients pick any domain controller, and its network may be missing
    from the documentation too. The other way round, the subnets Sites and Services
    defines that hold no active computer follow in one list - networks the domain knows of
    and the computers do not show, such as a VPN pool, a DMZ or a floor of appliances.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .PARAMETER ActiveDays
    How recent the last logon of a computer must be, in days. Default: 30.

    .PARAMETER ExportTargets
    Writes the subnets to this file, one per line in CIDR notation (10.1.2.0/24) - the /24s
    with active computers, then the defined subnets without one - as a target list for a
    scanner, such as nmap -iL. An existing file is overwritten. Without it nothing is
    written.

    .PARAMETER OPSEC
    Sends no DNS query. Addresses come from the AD-integrated zones only, read over LDAP; a
    computer not found there is counted and not mapped.

    .EXAMPLE
    Get-NetworkMap

    .EXAMPLE
    Get-NetworkMap -ActiveDays 60 -ExportTargets .\subnets.txt

    .EXAMPLE
    Get-NetworkMap -Domain "contoso.com" -Credential (Get-Credential) -OPSEC

    .NOTES
    Category: Computer
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
        [ValidateRange(1, 3650)]
        [int]$ActiveDays = 30,

        [Parameter(Mandatory=$false)]
        [string]$ExportTargets,

        [Parameter(Mandatory=$false)]
        [switch]$OPSEC
    )

    begin {
        Write-Log "[Get-NetworkMap] Starting check"
    }

    process {
        try {
            # Connection parameters only: Ensure-LDAPConnection and the Get-Domain* functions
            # have none of the others, and splatting $PSBoundParameters would fail to bind.
            $connectionParams = @{}
            if ($PSBoundParameters.ContainsKey('Domain'))     { $connectionParams['Domain'] = $Domain }
            if ($PSBoundParameters.ContainsKey('Server'))     { $connectionParams['Server'] = $Server }
            if ($PSBoundParameters.ContainsKey('Credential')) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            Show-SubHeader "Mapping the IP subnets of the active computers..." -ObjectType "NetworkSubnet"

            $domainFQDN = ([string]$Script:LDAPContext.Domain).Trim().TrimEnd('.').ToLowerInvariant()

            # ===== The active computers =====
            # Only the attributes this check counts with: nothing of the computer objects
            # is shown, so the -Properties rule for displayed objects does not apply.
            $since = (Get-Date).AddDays(-$ActiveDays).ToFileTime()
            $computers = @(Get-DomainComputer -Enabled -LDAPFilter "(lastLogonTimestamp>=$since)" `
                -Properties 'dNSHostName', 'operatingSystem' @connectionParams)
            Write-Log "[Get-NetworkMap] $($computers.Count) enabled computer(s) with a logon in the last $ActiveDays days"

            if ($computers.Count -eq 0) {
                Show-Line "No enabled computer logged on within the last $ActiveDays days" -Class Note
                return
            }

            # The domain controllers, by the one definition Get-DomainComputer keeps.
            $dcSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            $dcLookupFailed = $false
            try {
                foreach ($dc in @(Get-DomainComputer -DomainController -Properties 'distinguishedName' @connectionParams)) {
                    if ($dc.distinguishedName) { [void]$dcSet.Add([string]$dc.distinguishedName) }
                }
            } catch {
                Write-Log "[Get-NetworkMap] The domain controllers could not be read: $_"
                $dcLookupFailed = $true
            }

            # ===== Names below the domain's own =====
            $withoutName = 0
            $outsideDomain = 0
            $candidates = New-Object System.Collections.Generic.List[object]
            foreach ($computer in $computers) {
                $fqdn = ([string]$computer.dNSHostName).Trim().TrimEnd('.').ToLowerInvariant()
                if (-not $fqdn) { $withoutName++; continue }
                if (-not $fqdn.EndsWith(".$domainFQDN")) { $outsideDomain++; continue }

                $dn = [string]$computer.distinguishedName
                # The OU or container: everything after the first RDN, read escape-aware -
                # a CN may hold an escaped comma.
                $location = if ($dn -match '^(?:[^,\\]|\\.)+,(.+)$') { $Matches[1] } else { $dn }

                $os = [string]$computer.operatingSystem
                $osClass = if ($os -match 'Windows' -and $os -match 'Server') { 'Server' }
                           elseif ($os -match 'Windows') { 'Client' }
                           else { 'Other' }

                $candidates.Add([PSCustomObject]@{
                    DN       = $dn
                    FQDN     = $fqdn
                    Location = $location
                    IsDC     = $dcSet.Contains($dn)
                    OSClass  = $osClass
                })
            }

            # ===== Addresses from the AD-integrated zones =====
            # An address in two zones does no harm: a computer counts once per subnet,
            # however many of its addresses fall in it.
            $zoneAddresses = Get-NetworkMapAddressMap -Name @($candidates | ForEach-Object { $_.FQDN }) @connectionParams
            $addressMap = $zoneAddresses.Addresses
            $zonesRead = $zoneAddresses.ZonesRead

            # ===== Sites and Services =====
            # The defined subnets by prefix length, so that the most specific one containing
            # an address is a lookup per length rather than a pass over all of them. $null
            # when they could not be read: then there is no row, rather than one claiming
            # that no subnet is defined.
            $adSubnets = @{}
            $adPrefixes = @()
            try {
                $configNC = [string]$Script:LDAPContext.ConfigurationNamingContext
                if (-not $configNC) { throw 'no configuration naming context' }
                foreach ($subnetObject in @(Get-DomainObject -LDAPFilter '(objectClass=subnet)' -SearchBase "CN=Subnets,CN=Sites,$configNC" `
                        -Properties 'name', 'siteObject' @connectionParams)) {
                    $subnetName = [string]$subnetObject.name
                    # IPv6 subnets are not mapped.
                    if ($subnetName -notmatch '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') { continue }
                    $networkNumber = ConvertTo-NetworkMapIPv4Number -Address $Matches[1]
                    $prefixLength = [int]$Matches[2]
                    if ($null -eq $networkNumber -or $prefixLength -gt 32) { continue }

                    # The site name as written, its escapes undone: "Branch\, North" is "Branch, North".
                    $siteName = if ([string]$subnetObject.siteObject -match '^CN=((?:[^,\\]|\\.)+),CN=Sites,') { $Matches[1] -replace '\\(.)', '$1' } else { $null }
                    $label = if ($siteName) { "$subnetName ($siteName)" } else { "$subnetName (no site)" }

                    if (-not $adSubnets.ContainsKey($prefixLength)) { $adSubnets[$prefixLength] = @{} }
                    $key = $networkNumber -band (Get-NetworkMapPrefixMask -PrefixLength $prefixLength)
                    $adSubnets[$prefixLength][$key] = [PSCustomObject]@{
                        Name          = $subnetName
                        Network       = $key
                        Prefix        = $prefixLength
                        Label         = $label
                        HoldsComputer = $false
                    }
                }
                $adPrefixes = @($adSubnets.Keys | Sort-Object -Descending)
            } catch {
                Write-Log "[Get-NetworkMap] The subnets of Sites and Services could not be read: $_"
                $adSubnets = $null
            }

            # ===== One entry per /24 =====
            $dnsServer = $null
            if ($Script:LDAPContext['DnsServer']) { $dnsServer = [string]$Script:LDAPContext['DnsServer'] }
            elseif ($Script:LDAPContext['ServerIP']) { $dnsServer = [string]$Script:LDAPContext['ServerIP'] }

            $subnets = @{}
            $mapped = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            $notInZones = 0
            $queried = 0
            $withoutAddress = 0
            $ipv6Only = 0

            $total = $candidates.Count
            $index = 0
            foreach ($candidate in $candidates) {
                $index++
                $ipv4 = @()
                $ipv6 = @()
                if ($addressMap.ContainsKey($candidate.FQDN)) {
                    $ipv4 = @($addressMap[$candidate.FQDN].IPv4)
                    $ipv6 = @($addressMap[$candidate.FQDN].IPv6)
                } elseif ($OPSEC) {
                    $notInZones++
                    continue
                } else {
                    $queried++
                    if ($total -gt $Script:ProgressThreshold) { Show-Progress -Activity "Resolving computer names" -Current $index -Total $total -ObjectName $candidate.FQDN }
                    $ipv4 = @(Resolve-NetworkMapName -Name $candidate.FQDN -DnsServer $dnsServer)
                }

                $numbers = @($ipv4 | ForEach-Object { ConvertTo-NetworkMapIPv4Number -Address $_ } |
                    Where-Object { Test-NetworkMapUsableIPv4 -Number $_ })
                if ($numbers.Count -eq 0) {
                    if ($ipv6.Count -gt 0) { $ipv6Only++ } else { $withoutAddress++ }
                    continue
                }
                [void]$mapped.Add($candidate.DN)

                foreach ($number in $numbers) {
                    $network = $number - ($number % 256)
                    if (-not $subnets.ContainsKey($network)) {
                        $subnets[$network] = [PSCustomObject]@{
                            Network   = $network
                            Computers = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                            DCs       = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                            OSClasses = @{ Server = 0; Client = 0; Other = 0 }
                            Locations = @{}
                            ADSubnets = New-Object System.Collections.Generic.List[string]
                        }
                    }
                    $entry = $subnets[$network]

                    if ($null -ne $adSubnets) {
                        # Every defined subnet that contains the address holds an active
                        # computer; the most specific of them names it.
                        $label = $null
                        foreach ($prefixLength in $adPrefixes) {
                            $adEntry = $adSubnets[$prefixLength][$number -band (Get-NetworkMapPrefixMask -PrefixLength $prefixLength)]
                            if ($null -eq $adEntry) { continue }
                            $adEntry.HoldsComputer = $true
                            if ($null -eq $label) { $label = $adEntry.Label }
                        }
                        if ($null -eq $label) { $label = 'Not in Sites and Services' }
                        if (-not $entry.ADSubnets.Contains($label)) { $entry.ADSubnets.Add($label) }
                    }

                    # Two addresses of one computer in the same /24 count it once.
                    if (-not $entry.Computers.Add($candidate.DN)) { continue }
                    if ($candidate.IsDC) { [void]$entry.DCs.Add($candidate.DN) }
                    $entry.OSClasses[$candidate.OSClass]++
                    if (-not $entry.Locations.ContainsKey($candidate.Location)) { $entry.Locations[$candidate.Location] = 0 }
                    $entry.Locations[$candidate.Location]++
                }
            }
            if ($queried -gt 0 -and $total -gt $Script:ProgressThreshold) { Show-Progress -Activity "Resolving computer names" -Completed }
            Write-Log "[Get-NetworkMap] $queried name(s) resolved by DNS query, $($mapped.Count) computer(s) in $($subnets.Count) subnet(s)"

            # ===== Output =====
            # First what was left out, then the headline and the subnets.
            if ($outsideDomain -gt 0) {
                Show-Line "$outsideDomain active computer(s) with a DNS name outside $domainFQDN - not resolved" -Class Note
            }
            if ($withoutName -gt 0) {
                Show-Line "$withoutName active computer(s) without a DNS name (dNSHostName) - not mapped" -Class Note
            }
            if ($notInZones -gt 0) {
                Show-Line "OPSEC mode: $notInZones active computer(s) not found in the AD-integrated DNS zones - not resolved by DNS query" -Class Note
            } elseif ($queried -gt 0 -and $zonesRead -eq 0) {
                $askedServer = if ($dnsServer) { $dnsServer } else { 'the DNS resolver of this machine' }
                Show-Line "No AD-integrated DNS zone of these names could be read - addresses by DNS query to $askedServer" -Class Note
            }
            if ($withoutAddress -gt 0) {
                Show-Line "$withoutAddress active computer(s) without a usable IPv4 address in DNS - not mapped" -Class Note
            }
            if ($ipv6Only -gt 0) {
                Show-Line "$ipv6Only active computer(s) with IPv6 addresses only - IPv6 is not mapped" -Class Note
            }
            if ($dcLookupFailed) {
                Show-Line "The domain controllers could not be determined - no subnet counts them" -Class Note
            }

            # The subnets of the list -ExportTargets writes, in the order shown.
            $targets = New-Object System.Collections.Generic.List[string]

            if ($subnets.Count -eq 0) {
                Show-Line "No active computer could be mapped to an IPv4 subnet" -Class Note
            } else {
                Show-Line "Found $($subnets.Count) /24 subnet(s) with $($mapped.Count) computer(s) active in the last $ActiveDays days:" -Class Note
            }

            foreach ($entry in @($subnets.Values | Sort-Object -Property Network)) {
                $n = [long]$entry.Network
                $subnetName = '{0}.{1}.{2}.0/24' -f [Math]::Floor($n / 16777216), ([Math]::Floor($n / 65536) % 256), ([Math]::Floor($n / 256) % 256)
                $targets.Add($subnetName)

                $osParts = @()
                if ($entry.OSClasses['Server'] -gt 0) { $osParts += "$($entry.OSClasses['Server']) server(s)" }
                if ($entry.OSClasses['Client'] -gt 0) { $osParts += "$($entry.OSClasses['Client']) client(s)" }
                if ($entry.OSClasses['Other'] -gt 0)  { $osParts += "$($entry.OSClasses['Other']) other" }

                # The OUs with the most computers first, the DN as everywhere in adPEAS.
                # Sort-Object compares strings without regard to case, which is how a DN
                # compares too.
                $locations = @($entry.Locations.GetEnumerator() |
                    Sort-Object -Property @{ Expression = { $_.Value }; Descending = $true }, @{ Expression = { [string]$_.Key }; Descending = $false } |
                    ForEach-Object { "$($_.Key) ($($_.Value))" })

                $subnetObject = [PSCustomObject][ordered]@{
                    Name   = $subnetName
                    subnet = $subnetName
                }
                if ($null -ne $adSubnets) {
                    $subnetObject | Add-Member -NotePropertyName 'adSubnet' -NotePropertyValue @($entry.ADSubnets) -Force
                }
                $subnetObject | Add-Member -NotePropertyName 'computerCount' -NotePropertyValue $entry.Computers.Count -Force
                if ($entry.DCs.Count -gt 0) {
                    $subnetObject | Add-Member -NotePropertyName 'domainControllerCount' -NotePropertyValue $entry.DCs.Count -Force
                }
                $subnetObject | Add-Member -NotePropertyName 'operatingSystems' -NotePropertyValue ($osParts -join ', ') -Force
                $subnetObject | Add-Member -NotePropertyName 'organizationalUnits' -NotePropertyValue $locations -Force
                $subnetObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'NetworkSubnet' -Force

                # The subnet of the domain controllers is the one to know first; the row
                # carries the card, NETWORK_SUBNET_DOMAIN_CONTROLLERS.
                $objectClass = if ($entry.DCs.Count -gt 0) { 'Hint' } else { 'Note' }
                Show-Object $subnetObject -Class $objectClass
            }

            # The subnets Sites and Services defines that hold no active computer: networks
            # the domain knows of - a VPN pool, a DMZ, a floor of printers and appliances -
            # which the computers above do not show. One object for all of them, in the
            # format of adSubnet: a list to scan, not a card each, as Get-DomainInformation
            # lists the subnets of a site. A defined subnet whose /24 is listed above is left
            # out, that /24 covers it - which can only be one smaller than a /24, since a
            # larger one would contain the computers of that /24. Where the subnets could not
            # be read, $adSubnets is $null and there is nothing to list.
            $emptySubnets = @(@(foreach ($table in $adSubnets.Values) {
                foreach ($adEntry in $table.Values) {
                    if ($adEntry.HoldsComputer) { continue }
                    if ($subnets.ContainsKey($adEntry.Network - ($adEntry.Network % 256))) { continue }
                    $adEntry
                }
            }) | Sort-Object -Property Network, Prefix)

            if ($emptySubnets.Count -gt 0) {
                Show-Line "$($emptySubnets.Count) subnet(s) defined in Sites and Services without an active computer:" -Class Note
                $emptyObject = [PSCustomObject][ordered]@{
                    Name              = 'Sites and Services, no active computer'
                    adSubnet          = @($emptySubnets | ForEach-Object { $_.Label })
                    _adPEASObjectType = 'NetworkSubnet'
                }
                Show-Object $emptyObject -Class Note
                foreach ($adEntry in $emptySubnets) { $targets.Add($adEntry.Name) }
            }

            if ($ExportTargets) {
                if ($targets.Count -eq 0) {
                    Show-Line "No subnet to write to $ExportTargets" -Class Note
                } else {
                    $export = Export-adPEASFile -Path $ExportTargets -Content (($targets -join "`r`n") + "`r`n") -Type Text -Force -SanitizeFilename:$false
                    if ($export.Success) {
                        Show-Line "Wrote $($targets.Count) subnet(s) to $($export.Path)" -Class Note
                    } else {
                        Show-Line "The subnet list could not be written to ${ExportTargets}: $($export.Message)" -Class Hint
                    }
                }
            }

        } catch {
            Write-Log "[Get-NetworkMap] Error: $_" -Level Error
            Show-Line "Error during check - the network map could not be built: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-NetworkMap] Check completed"
    }
}
