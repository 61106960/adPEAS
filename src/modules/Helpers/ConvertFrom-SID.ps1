<#
.SYNOPSIS
    Converts a Security Identifier (SID) to DOMAIN\sAMAccountName format.

.DESCRIPTION
    Resolves a SID to a user-friendly account name using LDAP queries.

    Features:
    - LDAP-based resolution (works in all environments)
    - Global caching for performance (critical for ACL parsing)
    - Verbose tracking (shows each resolution only once)
    - Fallback to SID if resolution fails
    - Foreign domain SID detection and formatting

    Performance Optimization:
    This function caches all resolved SIDs in $Script:SIDResolutionCache.
    When parsing ACLs with hundreds of ACEs referencing the same principals, caching reduces LDAP queries from O(n) to O(unique principals).

.PARAMETER SID
    Security Identifier as string (e.g., "S-1-5-21-...")

.EXAMPLE
    ConvertFrom-SID -SID "S-1-5-21-123456789-123456789-123456789-500"
    Returns: "CONTOSO\Administrator"

.EXAMPLE
    $ACE.IdentityReference.Value | ConvertFrom-SID
    Resolves SID from pipeline

.OUTPUTS
    String in format "DOMAIN\sAMAccountName" or original SID if not resolvable

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function ConvertFrom-SID {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SID
    )

    begin {
        # Negative cache marker for definitively unresolvable SIDs
        $Script:UNRESOLVABLE_MARKER = "[UNRESOLVABLE]"

        # Initialize global caches if not already present
        if (-not $Script:SIDResolutionCache) {
            $Script:SIDResolutionCache = @{}
            Write-Log "[ConvertFrom-SID] Initialized SID resolution cache"
        }

        if (-not $Script:SIDVerboseCache) {
            $Script:SIDVerboseCache = @{}
        }

        # Initialize bidirectional cache for ConvertTo-SID (Name ? SID)
        if (-not $Script:NameToSIDCache) {
            $Script:NameToSIDCache = @{}
            Write-Log "[ConvertFrom-SID] Initialized bidirectional Name-to-SID cache"
        }

        # Initialize Foreign Domain cache (SID Domain Part → Domain FQDN)
        if (-not $Script:ForeignDomainCache) {
            $Script:ForeignDomainCache = @{}
            Write-Log "[ConvertFrom-SID] Initialized Foreign Domain cache"
        }
    }

    process {
        # Check LDAP connection FIRST - fail fast if no session
        if (-not $Script:LdapConnection) {
            Show-NoSessionError -Context "ConvertFrom-SID"
            Write-Log "[ConvertFrom-SID] No active LDAP connection - returning SID as-is"
            return $SID
        }

        # Check cache (after session check)
        if ($Script:SIDResolutionCache.ContainsKey($SID)) {
            $cachedValue = $Script:SIDResolutionCache[$SID]

            # Check for negative cache marker - remove it before returning
            if ($cachedValue.StartsWith($Script:UNRESOLVABLE_MARKER)) {
                return $cachedValue.Substring($Script:UNRESOLVABLE_MARKER.Length)
            }

            # Return cached value (either resolved name or already formatted)
            return $cachedValue
        }

        # Check Well-Known SIDs first (these don't exist in AD)
        if ($Script:SIDToName.ContainsKey($SID)) {
            $resolvedName = $Script:SIDToName[$SID]
            Write-Log "[ConvertFrom-SID] Well-known SID resolved: $SID -> $resolvedName"
            $Script:SIDResolutionCache[$SID] = $resolvedName
            $Script:SIDVerboseCache[$SID] = $true
            # Populate bidirectional cache (Name ? SID)
            $Script:NameToSIDCache[$resolvedName] = $SID
            return $resolvedName
        }

        try {

            # Convert SID to binary format for LDAP query
            $SIDObj = New-Object System.Security.Principal.SecurityIdentifier($SID)
            $SIDBytes = New-Object byte[] $SIDObj.BinaryLength
            $SIDObj.GetBinaryForm($SIDBytes, 0)

            # Convert to LDAP hex format (\XX\XX\XX...)
            $SIDHex = ($SIDBytes | ForEach-Object { '\' + $_.ToString('X2') }) -join ''

            # Check if this is a foreign domain SID before querying local domain
            # If the SID's domain part doesn't match the current domain, skip local domain lookup
            $skipLocalLookup = $false
            if ($SID -match '^S-1-5-21-(\d+-\d+-\d+)-\d+$') {
                $sidDomainPart = $matches[1]
                if ($Script:LDAPContext -and $Script:LDAPContext.DomainSID) {
                    if ($Script:LDAPContext.DomainSID -match '^S-1-5-21-(\d+-\d+-\d+)') {
                        $localDomainPart = $matches[1]
                        if ($sidDomainPart -ne $localDomainPart) {
                            $skipLocalLookup = $true
                            Write-Log "[ConvertFrom-SID] SID is from foreign domain, skipping local domain lookup"
                        }
                    }
                }
            }

            # Only query local domain if SID belongs to local domain
            $results = @()
            if (-not $skipLocalLookup) {
                Write-Log "[ConvertFrom-SID] Querying LDAP for SID: $SID"
                Write-Log "[ConvertFrom-SID] LDAP Filter: (objectSid=$SIDHex)"

                # Search for account with this SID using Invoke-LDAPSearch
                $results = @(Invoke-LDAPSearch -Filter "(objectSid=$SIDHex)" -Properties "sAMAccountName","distinguishedName","objectClass" -SizeLimit 1)
            }

            if ($results -and $results.Count -gt 0) {
                $result = $results[0]
                $samAccountName = $result.sAMAccountName

                # Skip if sAMAccountName is empty or whitespace
                if ([string]::IsNullOrWhiteSpace($samAccountName)) {
                    Write-Log "[ConvertFrom-SID] sAMAccountName is empty - falling back to Well-known SIDs or caching as unresolvable"

                    # Check if it's a well-known SID we missed
                    if ($Script:SIDToName.ContainsKey($SID)) {
                        $resolvedName = $Script:SIDToName[$SID]
                        $Script:SIDResolutionCache[$SID] = $resolvedName
                        $Script:SIDVerboseCache[$SID] = $true
                        return $resolvedName
                    }

                    # Object found but no sAMAccountName - cache as unresolvable
                    if ($Script:LDAPContext -and $Script:LDAPContext.Domain) {
                        $resolvedName = "$SID (UNRESOLVABLE in $($Script:LDAPContext.Domain.ToUpper()))"
                    } else {
                        $resolvedName = "$SID (UNRESOLVABLE)"
                    }
                    $Script:SIDResolutionCache[$SID] = "$Script:UNRESOLVABLE_MARKER$resolvedName"
                    $Script:SIDVerboseCache[$SID] = $true
                    return $resolvedName
                }

                # Found account - extract domain name from DN
                $DN = $result.distinguishedName

                if ($DN -match 'DC=([^,]+)') {
                    $domainName = $Matches[1].ToUpper()
                } elseif ($Script:LDAPContext.Domain) {
                    # Fallback: Use first part of domain FQDN
                    $domainName = $Script:LDAPContext.Domain.Split('.')[0].ToUpper()
                } else {
                    # Last resort fallback
                    $domainName = "UNKNOWN"
                }

                $accountName = "${domainName}\$samAccountName"
                Write-Log "[ConvertFrom-SID] Resolved to: $accountName"

                # Cache result for future lookups
                $Script:SIDResolutionCache[$SID] = $accountName
                $Script:SIDVerboseCache[$SID] = $true
                # Populate bidirectional cache (Name ? SID)
                $Script:NameToSIDCache[$accountName] = $SID

                return $accountName

            } else {
                # Object not found or has no sAMAccountName
                Write-Log "[ConvertFrom-SID] Object not found or missing sAMAccountName - checking alternatives"

                # Check if it's a well-known SID we missed (extra safety check)
                if ($Script:SIDToName.ContainsKey($SID)) {
                    $resolvedName = $Script:SIDToName[$SID]
                    $Script:SIDResolutionCache[$SID] = $resolvedName
                    $Script:SIDVerboseCache[$SID] = $true
                    # Populate bidirectional cache (Name ? SID)
                    $Script:NameToSIDCache[$resolvedName] = $SID
                    return $resolvedName
                }

                # Check if this is a LOCAL domain SID before doing FSP/GC lookup
                # If the SID's domain part matches the current domain, skip expensive foreign lookups
                if ($SID -match '^S-1-5-21-(\d+-\d+-\d+)-\d+$') {
                    $sidDomainPart = $matches[1]
                    $currentDomainSID = $null
                    if ($Script:LDAPContext -and $Script:LDAPContext.DomainSID) {
                        $currentDomainSID = $Script:LDAPContext.DomainSID
                    }

                    # Extract domain part from current domain SID
                    if ($currentDomainSID -and $currentDomainSID -match '^S-1-5-21-(\d+-\d+-\d+)') {
                        $currentDomainPart = $matches[1]

                        # This is a LOCAL domain SID that doesn't exist - skip FSP/GC lookup
                        if ($sidDomainPart -eq $currentDomainPart) {
                            if ($Script:LDAPContext -and $Script:LDAPContext.Domain) {
                                $resolvedName = "$SID (UNRESOLVABLE in $($Script:LDAPContext.Domain.ToUpper()))"
                            } else {
                                $resolvedName = "$SID (UNRESOLVABLE)"
                            }

                            Write-Log "[ConvertFrom-SID] Local domain SID not found (skipping FSP/GC lookup): $resolvedName"
                            $Script:SIDResolutionCache[$SID] = "$Script:UNRESOLVABLE_MARKER$resolvedName"
                            $Script:SIDVerboseCache[$SID] = $true
                            return $resolvedName
                        }
                    }
                }

                # Try Global Catalog for foreign SID resolution
                $gcResolved = Resolve-SIDViaGC -SIDHex $SIDHex -SID $SID
                if ($gcResolved) {
                    # Cache Foreign Domain for future unresolvable SIDs from same domain
                    if ($SID -match '^S-1-5-21-(\d+-\d+-\d+)-\d+$') {
                        $sidDomainPart = $matches[1]
                        if ($gcResolved -match '^([^\\]+)\\') {
                            $foreignDomainName = $matches[1]
                            $Script:ForeignDomainCache[$sidDomainPart] = $foreignDomainName
                            Write-Log "[ConvertFrom-SID] Cached foreign domain: $sidDomainPart -> $foreignDomainName"
                        }
                    }
                    $Script:SIDResolutionCache[$SID] = $gcResolved
                    $Script:SIDVerboseCache[$SID] = $true
                    $Script:NameToSIDCache[$gcResolved] = $SID
                    return $gcResolved
                }

                # GC lookup failed - SID is unresolvable
                # Check if we have cached foreign domain info for better UX
                if ($SID -match '^S-1-5-21-(\d+-\d+-\d+)-\d+$') {
                    $sidDomainPart = $matches[1]
                    if ($Script:ForeignDomainCache.ContainsKey($sidDomainPart)) {
                        $foreignDomain = $Script:ForeignDomainCache[$sidDomainPart]
                        $resolvedName = "$SID (UNRESOLVABLE in $foreignDomain)"
                    } else {
                        $resolvedName = "$SID (FOREIGN)"
                    }
                } else {
                    # Non-domain SID (e.g., S-1-5-X) or malformed SID
                    $resolvedName = "$SID (UNRESOLVABLE)"
                }

                Write-Log "[ConvertFrom-SID] SID could not be resolved: $resolvedName"
                $Script:SIDResolutionCache[$SID] = "$Script:UNRESOLVABLE_MARKER$resolvedName"
                $Script:SIDVerboseCache[$SID] = $true
                return $resolvedName
            }

        } catch {
            # Resolution failed (Exception) - cache as unresolvable to avoid repeated LDAP queries
            Write-Log "[ConvertFrom-SID] Exception: $($_.Exception.Message)"
            Write-Log "[ConvertFrom-SID] Resolution failed for SID: $SID"

            # Cache with negative marker - this prevents repeated failed LDAP queries
            # Exception could mean: network issue, permission denied, timeout, etc.
            if ($Script:LDAPContext -and $Script:LDAPContext.Domain) {
                $resolvedName = "$SID (UNRESOLVABLE in $($Script:LDAPContext.Domain.ToUpper()))"
            } else {
                $resolvedName = "$SID (UNRESOLVABLE)"
            }
            $Script:SIDResolutionCache[$SID] = "$Script:UNRESOLVABLE_MARKER$resolvedName"
            $Script:SIDVerboseCache[$SID] = $true

            return $resolvedName
        }
    }

    end {
    }
}

<#
.SYNOPSIS
    Converts a SID string to LDAP binary hex format for LDAP queries.

.DESCRIPTION
    Converts a Security Identifier (SID) string to the binary hex format required for LDAP objectSid queries (e.g., \01\05\00\00...).

    This is the reverse direction of ConvertFrom-SID:
    - ConvertFrom-SID: SID ? Domain\Username
    - ConvertTo-LDAPSIDHex: SID ? LDAP hex format for queries

.PARAMETER SID
    Security Identifier as string (e.g., "S-1-5-21-...")

.EXAMPLE
    ConvertTo-LDAPSIDHex -SID "S-1-5-21-123456789-123456789-123456789-500"
    Returns: "\01\05\00\00\00\00\00\05\15\00\00\00..."

.EXAMPLE
    $sidHex = ConvertTo-LDAPSIDHex -SID $trusteeSID
    $adObject = Get-DomainObject -LDAPFilter "(objectSid=$sidHex)"

.OUTPUTS
    String in LDAP hex format (\XX\XX\XX...) or $null if conversion fails

.NOTES
    Helper function for ACL-based checks that need to resolve SIDs to full AD objects
    Author: Alexander Sturz (@_61106960_)
#>
function ConvertTo-LDAPSIDHex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SID
    )

    process {
        try {
            $SIDObj = New-Object System.Security.Principal.SecurityIdentifier($SID)
            $SIDBytes = New-Object byte[] $SIDObj.BinaryLength
            $SIDObj.GetBinaryForm($SIDBytes, 0)
            return ($SIDBytes | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
        } catch {
            Write-Log "[ConvertTo-LDAPSIDHex] Failed to convert SID '$SID': $_"
            return $null
        }
    }
}