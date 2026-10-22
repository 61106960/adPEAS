function ConvertFrom-DNSRecord {
    <#
    .SYNOPSIS
    Decodes one value of the dnsRecord attribute of an Active Directory-integrated DNS zone.

    .DESCRIPTION
    A dnsNode object carries its resource records in dnsRecord, one binary value each, in
    the layout MS-DNSP 2.3.2.2 defines: a 24-byte header, then the data.

       0  DataLength  2 bytes, little-endian - the length of Data
       2  Type        2 bytes, little-endian - 1 = A, 28 = AAAA, 0 = a tombstone
       4  Version     1 byte, always 5
       5  Rank        1 byte
       6  Flags       2 bytes
       8  Serial      4 bytes
      12  TtlSeconds  4 bytes, big-endian
      16  Reserved    4 bytes
      20  TimeStamp   4 bytes - hours since 1601 of the last dynamic update, 0 when static
      24  Data

    Only address records are decoded. Every other type answers $null, as does a value too
    short for its header or its data, and one whose version is not 5.

    .PARAMETER Bytes
    One value of dnsRecord.

    .OUTPUTS
    PSCustomObject with Type ('A' or 'AAAA') and Address, or $null.

    .NOTES
    Internal helper function
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    # The header first: the version byte and the two fields below are read from it, and
    # an index past the end of an array throws under Set-StrictMode.
    if ($null -eq $Bytes -or $Bytes.Length -lt 24) { return $null }
    if ($Bytes[4] -ne 5) { return $null }

    $dataLength = [BitConverter]::ToUInt16($Bytes, 0)
    $recordType = [BitConverter]::ToUInt16($Bytes, 2)
    if ($Bytes.Length -lt (24 + $dataLength)) { return $null }

    if ($recordType -eq 1 -and $dataLength -eq 4) {
        return [PSCustomObject]@{
            Type    = 'A'
            Address = ('{0}.{1}.{2}.{3}' -f $Bytes[24], $Bytes[25], $Bytes[26], $Bytes[27])
        }
    }
    if ($recordType -eq 28 -and $dataLength -eq 16) {
        $addressBytes = New-Object byte[] 16
        [Array]::Copy($Bytes, 24, $addressBytes, 0, 16)
        return [PSCustomObject]@{
            Type    = 'AAAA'
            Address = ([System.Net.IPAddress]::new($addressBytes)).ToString()
        }
    }
    return $null
}

function Get-DomainDNSZone {
    <#
    .SYNOPSIS
    Lists the forward lookup zones stored in Active Directory.

    .DESCRIPTION
    An Active Directory-integrated zone is a dnsZone object in a container CN=MicrosoftDNS,
    and there are three of those:

    - DC=DomainDnsZones,<domain>     - replicated to the DNS servers of the domain
    - DC=ForestDnsZones,<forest root> - replicated to the DNS servers of the forest
    - CN=System,<domain>             - the Windows 2000 location, still replicated with
                                       the domain partition

    Each is asked of the connected domain controller only. The two application partitions
    are held by every domain controller that runs DNS; one that does not answers with a
    referral, which is not followed, and that location is skipped.

    Left out: the reverse lookup zones (in-addr.arpa, ip6.arpa), RootDNSServers, which holds
    the root hints, and every name that begins with two dots - ..TrustAnchors, and the
    ..Deleted- prefix a zone carries between its deletion and its removal.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .OUTPUTS
    PSCustomObject per zone: Name (lower case), DistinguishedName and Partition
    (DomainDnsZones, ForestDnsZones or System).

    .EXAMPLE
    Get-DomainDNSZone

    .NOTES
    Author: Alexander Sturz (@_61106960_)
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

    process {
        $connectionParams = @{}
        if ($PSBoundParameters.ContainsKey('Domain'))     { $connectionParams['Domain'] = $Domain }
        if ($PSBoundParameters.ContainsKey('Server'))     { $connectionParams['Server'] = $Server }
        if ($PSBoundParameters.ContainsKey('Credential')) { $connectionParams['Credential'] = $Credential }

        if (-not (Ensure-LDAPConnection @connectionParams)) { return }

        $domainDN = [string]$Script:LDAPContext.DomainDN
        $forestDN = [string]$Script:LDAPContext.RootDomainNamingContext
        if (-not $forestDN) { $forestDN = $domainDN }

        $locations = @(
            [PSCustomObject]@{ Partition = 'DomainDnsZones'; Container = "CN=MicrosoftDNS,DC=DomainDnsZones,$domainDN" }
            [PSCustomObject]@{ Partition = 'ForestDnsZones'; Container = "CN=MicrosoftDNS,DC=ForestDnsZones,$forestDN" }
            [PSCustomObject]@{ Partition = 'System';         Container = "CN=MicrosoftDNS,CN=System,$domainDN" }
        )

        foreach ($location in $locations) {
            $zones = @()
            try {
                $zones = @(Get-DomainObject -LDAPFilter '(objectClass=dnsZone)' -SearchBase $location.Container -Scope OneLevel `
                    -Properties 'name' -Raw @connectionParams)
            } catch {
                Write-Log "[Get-DomainDNSZone] $($location.Container) could not be read: $_"
                continue
            }
            Write-Log "[Get-DomainDNSZone] $($zones.Count) zone(s) in $($location.Container)"

            foreach ($zone in $zones) {
                $zoneName = ([string]$zone.name).Trim().TrimEnd('.').ToLowerInvariant()
                if (-not $zoneName -or -not $zone.distinguishedName) { continue }
                if ($zoneName.StartsWith('..') -or $zoneName -eq 'rootdnsservers') { continue }
                if ($zoneName -match '\.(in-addr|ip6)\.arpa$') { continue }

                [PSCustomObject]@{
                    Name              = $zoneName
                    DistinguishedName = [string]$zone.distinguishedName
                    Partition         = $location.Partition
                }
            }
        }
    }
}

function Get-DomainDNSRecord {
    <#
    .SYNOPSIS
    Reads the address records of Active Directory-integrated DNS zones over LDAP.

    .DESCRIPTION
    One LDAP search per zone, for the dnsNode objects directly below it and their dnsRecord
    values. Unlike a DNS query it needs no DNS server reachable from here, and it returns
    every address of a name rather than the ones a server picks. Unlike a zone transfer it
    is not refused: Authenticated Users may read the zones by default. A node whose ACL
    hides it from the reading account is not returned.

    A node whose dNSTombstoned is TRUE was deleted and waits for its removal; it is skipped.
    The node named "@" is the zone itself.

    .PARAMETER Zone
    The zones to read, as Get-DomainDNSZone returns them. Default: every zone it returns.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .OUTPUTS
    PSCustomObject per name with an address record: Name (the fully qualified name, lower
    case), Zone, IPv4Address and IPv6Address (string arrays).

    .EXAMPLE
    Get-DomainDNSRecord

    .EXAMPLE
    Get-DomainDNSZone | Where-Object Name -eq 'contoso.com' | ForEach-Object { Get-DomainDNSRecord -Zone $_ }

    .NOTES
    Author: Alexander Sturz (@_61106960_)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [AllowEmptyCollection()]
        [object[]]$Zone,

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    process {
        $connectionParams = @{}
        if ($PSBoundParameters.ContainsKey('Domain'))     { $connectionParams['Domain'] = $Domain }
        if ($PSBoundParameters.ContainsKey('Server'))     { $connectionParams['Server'] = $Server }
        if ($PSBoundParameters.ContainsKey('Credential')) { $connectionParams['Credential'] = $Credential }

        if (-not (Ensure-LDAPConnection @connectionParams)) { return }

        if (-not $PSBoundParameters.ContainsKey('Zone')) {
            $Zone = @(Get-DomainDNSZone @connectionParams)
        }

        foreach ($zoneEntry in @($Zone)) {
            if (-not $zoneEntry -or -not $zoneEntry.DistinguishedName) { continue }
            $zoneName = ([string]$zoneEntry.Name).ToLowerInvariant()

            $nodes = @()
            try {
                $nodes = @(Get-DomainObject -LDAPFilter '(objectClass=dnsNode)' -SearchBase $zoneEntry.DistinguishedName -Scope OneLevel `
                    -Properties 'name', 'dnsRecord', 'dNSTombstoned' -Raw @connectionParams)
            } catch {
                Write-Log "[Get-DomainDNSRecord] Zone $zoneName could not be read: $_"
                continue
            }
            Write-Log "[Get-DomainDNSRecord] $($nodes.Count) node(s) in zone $zoneName"

            foreach ($node in $nodes) {
                if ([string]$node.dNSTombstoned -eq 'TRUE') { continue }
                $nodeName = ([string]$node.name).ToLowerInvariant()
                if (-not $nodeName) { continue }
                $fqdn = if ($nodeName -eq '@') { $zoneName } else { "$nodeName.$zoneName" }

                # One value comes back as the byte array itself, several as an array of them.
                $values = $node.dnsRecord
                if ($values -is [byte[]]) { $values = @(, $values) }

                $ipv4 = New-Object System.Collections.Generic.List[string]
                $ipv6 = New-Object System.Collections.Generic.List[string]
                foreach ($value in @($values)) {
                    if ($value -isnot [byte[]]) { continue }
                    $record = ConvertFrom-DNSRecord -Bytes $value
                    if (-not $record) { continue }
                    if ($record.Type -eq 'A') {
                        if (-not $ipv4.Contains($record.Address)) { $ipv4.Add($record.Address) }
                    } elseif (-not $ipv6.Contains($record.Address)) {
                        $ipv6.Add($record.Address)
                    }
                }
                if (($ipv4.Count + $ipv6.Count) -eq 0) { continue }

                [PSCustomObject]@{
                    Name        = $fqdn
                    Zone        = $zoneName
                    IPv4Address = $ipv4.ToArray()
                    IPv6Address = $ipv6.ToArray()
                }
            }
        }
    }
}
