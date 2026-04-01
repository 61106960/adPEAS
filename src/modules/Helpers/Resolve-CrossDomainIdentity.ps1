function Resolve-CrossDomainIdentity {
<#
.SYNOPSIS
    Resolves cross-domain identity information from DOMAIN\username format.

.DESCRIPTION
    This function analyzes an identity string (e.g., "contoso\administrator") and determines:
    - Whether it's a cross-domain query
    - The target domain DN (via Configuration Partition lookup)
    - Extracted domain and identity parts

    Used by Get-DomainObject, ConvertTo-SID, and other functions that need to handle
    cross-domain identities in a forest environment.

.PARAMETER Identity
    Identity string, potentially in DOMAIN\username format.

.EXAMPLE
    Resolve-CrossDomainIdentity -Identity "contoso\administrator"

    Returns:
    @{
        Domain = "contoso"
        Identity = "administrator"
        IsCrossDomain = $true
        TargetDomainDN = "DC=contoso,DC=com"
        TargetDomainFQDN = "contoso.com"
    }

.EXAMPLE
    Resolve-CrossDomainIdentity -Identity "administrator"

    Returns:
    @{
        Domain = $null
        Identity = "administrator"
        IsCrossDomain = $false
        TargetDomainDN = $null
        TargetDomainFQDN = $null
    }

.NOTES
    - Requires active LDAP session via Ensure-LDAPConnection
    - Queries Configuration Partition to resolve NetBIOS domain names
    - Caches domain resolution results for performance
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Identity
    )

    # Initialize result object
    $result = [PSCustomObject]@{
        Domain = $null
        Identity = $Identity
        IsCrossDomain = $false
        TargetDomainDN = $null
        TargetDomainFQDN = $null
    }

    # Check if Identity contains DOMAIN\username format
    if ($Identity -notmatch '^(.+)\\(.+)$') {
        # No domain prefix - local query
        Write-Log "[Resolve-CrossDomainIdentity] No domain prefix found - local query"
        return $result
    }

    # Extract domain and identity parts
    $specifiedDomain = $Matches[1]
    $result.Identity = $Matches[2]
    $result.Domain = $specifiedDomain

    Write-Log "[Resolve-CrossDomainIdentity] Parsed: Domain='$specifiedDomain', Identity='$($result.Identity)'"

    # Check if specified domain differs from current domain
    if (-not $Script:LDAPContext -or -not $Script:LDAPContext.Domain) {
        Write-Log "[Resolve-CrossDomainIdentity] No LDAP context available - cannot determine cross-domain status" -Level Warning
        return $result
    }

    $currentDomain = $Script:LDAPContext.Domain.Split('.')[0]  # Extract NetBIOS from FQDN

    # Compare NetBIOS names (case-insensitive)
    if ($specifiedDomain -eq $currentDomain) {
        Write-Log "[Resolve-CrossDomainIdentity] Domain matches current domain - not cross-domain"
        return $result
    }

    # Cross-domain query detected
    $result.IsCrossDomain = $true
    Write-Log "[Resolve-CrossDomainIdentity] Cross-domain query detected: $specifiedDomain != $currentDomain"

    # Resolve NetBIOS domain name to DN via Configuration Partition
    try {
        # Build Configuration Partition DN
        $configurationDN = $Script:LDAPContext.ConfigurationNamingContext
        if (-not $configurationDN) {
            # Fallback: build from Domain
            $forestRootParts = $Script:LDAPContext.Domain.Split('.')
            $configurationDN = "CN=Configuration," + (($forestRootParts | ForEach-Object { "DC=$_" }) -join ',')
        }

        $partitionsDN = "CN=Partitions,$configurationDN"

        # Query Configuration Partition for NetBIOS name
        Write-Log "[Resolve-CrossDomainIdentity] Resolving NetBIOS name '$specifiedDomain' via Configuration Partition"
        $partitionResults = @(Invoke-LDAPSearch `
            -Filter "(nETBIOSName=$specifiedDomain)" `
            -SearchBase $partitionsDN `
            -Properties @("nCName") `
            -SizeLimit 1 `
            -Raw)

        if ($partitionResults.Count -gt 0 -and $partitionResults[0].nCName) {
            $result.TargetDomainDN = $partitionResults[0].nCName

            # Convert DN to FQDN (DC=contoso,DC=com -> contoso.com)
            $result.TargetDomainFQDN = (($result.TargetDomainDN -replace 'DC=', '' -replace ',', '.')).ToLower()

            Write-Log "[Resolve-CrossDomainIdentity] Resolved NetBIOS '$specifiedDomain' to DN: $($result.TargetDomainDN)"
        } else {
            Write-Log "[Resolve-CrossDomainIdentity] Failed to resolve NetBIOS name '$specifiedDomain' in Configuration Partition" -Level Warning
        }
    }
    catch {
        Write-Log "[Resolve-CrossDomainIdentity] Error resolving NetBIOS name via Configuration Partition: $_" -Level Warning
    }

    return $result
}

function Test-DomainMatch {
<#
.SYNOPSIS
    Tests if an object's DN matches a target domain FQDN.

.DESCRIPTION
    Extracts the domain FQDN from an object's distinguishedName and compares it
    with the target domain FQDN. Used for post-filtering cross-domain GC queries
    to exclude child domains.

.PARAMETER DistinguishedName
    The distinguishedName of the AD object.

.PARAMETER TargetDomainFQDN
    The target domain FQDN (e.g., "contoso.com").

.EXAMPLE
    Test-DomainMatch -DistinguishedName "CN=Admin,CN=Users,DC=contoso,DC=com" -TargetDomainFQDN "contoso.com"
    Returns: $true

.EXAMPLE
    Test-DomainMatch -DistinguishedName "CN=Admin,CN=Users,DC=dev,DC=contoso,DC=com" -TargetDomainFQDN "contoso.com"
    Returns: $false (child domain)

.NOTES
    Helper function for cross-domain query filtering.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DistinguishedName,

        [Parameter(Mandatory=$true)]
        [string]$TargetDomainFQDN
    )

    # Extract DC components from DN
    $dnParts = $DistinguishedName -split ','
    $dcParts = $dnParts | Where-Object { $_ -match '^DC=' } | ForEach-Object { $_ -replace '^DC=', '' }
    $objDomainFQDN = ($dcParts -join '.').ToLower()

    # Compare FQDNs
    $match = ($objDomainFQDN -eq $TargetDomainFQDN.ToLower())

    if (-not $match) {
        Write-Log "[Test-DomainMatch] Domain mismatch: '$objDomainFQDN' vs '$TargetDomainFQDN'"
    }

    return $match
}
