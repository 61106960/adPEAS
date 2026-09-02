<#
.SYNOPSIS
    Converts an identity (name, DN, UPN) to a Security Identifier (SID).

.DESCRIPTION
    Resolves various identity formats to their SID using LDAP queries.
    This is the reverse direction of ConvertFrom-SID.

    Supported Input Formats:
    - SID string (passthrough): "S-1-5-21-..."
    - DOMAIN\sAMAccountName: "CONTOSO\Administrator"
    - sAMAccountName only: "Administrator" (uses current domain)
    - Distinguished Name: "CN=User,OU=Users,DC=contoso,DC=com"
    - UPN: "user@contoso.com"
    - Well-known names: "Everyone", "Authenticated Users", "SYSTEM"

    Performance Optimization:
    Uses bidirectional caching with ConvertFrom-SID. When ConvertFrom-SID
    resolves a SID to a name, it also populates the reverse cache used here.

.PARAMETER Identity
    The identity to resolve. Accepts multiple formats as described above.

.EXAMPLE
    ConvertTo-SID -Identity "CONTOSO\Administrator"
    Returns: "S-1-5-21-123456789-123456789-123456789-500"

.EXAMPLE
    ConvertTo-SID -Identity "Everyone"
    Returns: "S-1-1-0"

.EXAMPLE
    ConvertTo-SID -Identity "CN=Admin,CN=Users,DC=contoso,DC=com"
    Returns: "S-1-5-21-..."

.EXAMPLE
    "CONTOSO\Ordinateurs du domaine" | ConvertTo-SID
    Returns: "S-1-5-21-...-515"   (localized name for the "Domain Computers" group)

.OUTPUTS
    String - SID in format "S-1-5-..." or $null if not resolvable

.NOTES
    Author: Alexander Sturz (@_61106960_)
    Dependencies:
    - Requires active $Script:LdapConnection for LDAP lookups
    - Uses $Script:NameToSIDCache (bidirectional cache)
    - Shares cache with ConvertFrom-SID
#>

function ConvertTo-SID {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Identity
    )

    begin {
        if (-not $Script:NameToSIDCache) {
            $Script:NameToSIDCache = @{}
            Write-Log "[ConvertTo-SID] Initialized Name-to-SID cache"
        }
    }

    process {
        $Identity = $Identity.Trim()

        if ([string]::IsNullOrEmpty($Identity)) {
            Write-Log "[ConvertTo-SID] Empty identity provided"
            return $null
        }

        # Already a SID? (Passthrough - no LDAP needed)
        if ($Identity -match '^S-1-\d+-') {
            Write-Log "[ConvertTo-SID] Input is already a SID: $Identity"
            return $Identity
        }

        # Check LDAP connection FIRST - fail fast if no session
        # (Some lookups below don't need LDAP, but most do - better to check upfront)
        if (-not $Script:LdapConnection) {
            Show-NoSessionError -Context "ConvertTo-SID"
            Write-Log "[ConvertTo-SID] No active LDAP connection - cannot resolve: $Identity"
            return $null
        }

        # Check bidirectional cache (after session check)
        if ($Script:NameToSIDCache.ContainsKey($Identity)) {
            $cachedSID = $Script:NameToSIDCache[$Identity]
            # Log cache hits for debugging (can be removed later for performance)
            if ($cachedSID) {
                Write-Log "[ConvertTo-SID] Cache hit: $Identity -> $cachedSID"
            } else {
                Write-Log "[ConvertTo-SID] Cache hit (null): $Identity -> (previously failed)"
            }
            return $cachedSID
        }

        # Well-known name? (Static mapping, no LDAP needed)
        if ($Script:NameToSID.ContainsKey($Identity)) {
            $sid = $Script:NameToSID[$Identity]
            Write-Log "[ConvertTo-SID] Well-known name resolved: $Identity -> $sid"
            # Cache for future lookups
            $Script:NameToSIDCache[$Identity] = $sid
            return $sid
        }

        # Try Windows API for localized account names (NT AUTHORITY, BUILTIN, etc.)
        # This handles ANY Windows language (e.g. the German or French spelling of "NT AUTHORITY")
        # without requiring translation tables.
        # Skip Windows API for Distinguished Names - they need LDAP resolution
        if ($Identity -notmatch '^CN=') {
            try {
                $ntAccount = New-Object System.Security.Principal.NTAccount($Identity)
                $sidObj = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
                if ($sidObj) {
                    $sid = $sidObj.Value
                    Write-Log "[ConvertTo-SID] Windows API resolved: $Identity -> $sid"
                    # Cache for future lookups
                    $Script:NameToSIDCache[$Identity] = $sid
                    return $sid
                }
            }
            catch {
                # NTAccount.Translate() failed - this is expected for AD objects
                # that don't exist locally (domain users/groups), continue to LDAP
                Write-Log "[ConvertTo-SID] Windows API failed for '$Identity', trying LDAP"
            }
        }

        # LDAP Resolution (connection already checked above)

        try {
            $filter = $null

            # Determine identity format and build appropriate LDAP filter
            # Format 1: Distinguished Name (CN=...,DC=...)
            if ($Identity -match '^CN=.+,DC=') {
                Write-Log "[ConvertTo-SID] Resolving DN via Invoke-LDAPSearch: $Identity"

                # Use Invoke-LDAPSearch with distinguishedName filter - more reliable than Base scope search
                # Escaping goes through Escape-LDAPFilterDN, not through a chain of
                # -replace calls. In a -replace the replacement string does not process
                # backslash escapes, so '\\5c' produced a literal double backslash and
                # '\\28' a backslash followed by "\28": every one of those escapes was
                # malformed. A DN like "CN=Doe\, Jane (Contractor),..." - a comma in the
                # display name plus a parenthetical suffix, which is an ordinary shape -
                # then built an invalid filter, matched nothing, and resolved to $null
                # without an error. The helper also knows that a DN out of AD is already
                # RFC 4514 escaped and must not have its backslashes escaped again.
                $escapedDN = Escape-LDAPFilterDN -DistinguishedName $Identity
                $filter = "(distinguishedName=$escapedDN)"
                Write-Log "[ConvertTo-SID] DN filter: $filter"

                $results = Invoke-LDAPSearch -Filter $filter -Properties "objectSid","sAMAccountName","distinguishedName" -SizeLimit 1

                # Ensure results is always an array for consistent handling
                $resultsArray = @($results)
                Write-Log "[ConvertTo-SID] DN search returned $($resultsArray.Count) result(s)"

                if ($resultsArray.Count -gt 0 -and $resultsArray[0]) {
                    $result = $resultsArray[0]

                    # Debug: Log available properties
                    $propNames = @($result.PSObject.Properties.Name)
                    Write-Log "[ConvertTo-SID] Result properties: $($propNames -join ', ')"

                    # objectSid is already converted to string by Invoke-LDAPSearch
                    $sid = $result.objectSid

                    if ($sid) {
                        Write-Log "[ConvertTo-SID] Resolved DN: $Identity -> $sid"

                        # Cache bidirectionally
                        $Script:NameToSIDCache[$Identity] = $sid

                        # Also cache with domain prefix if we have sAMAccountName
                        if ($result.sAMAccountName) {
                            $sam = $result.sAMAccountName
                            if ($Identity -match 'DC=([^,]+)') {
                                $domainName = $Matches[1].ToUpper()
                                $fullName = "$domainName\$sam"
                                if (-not $Script:NameToSIDCache.ContainsKey($fullName)) {
                                    $Script:NameToSIDCache[$fullName] = $sid
                                }
                            }
                        }

                        return $sid
                    }
                    else {
                        Write-Log "[ConvertTo-SID] DN found but objectSid is empty: $Identity"
                        return $null
                    }
                }
                else {
                    Write-Log "[ConvertTo-SID] DN lookup returned no results: $Identity"
                    return $null
                }
            }
            # Format 2: UPN (user@domain.com)
            elseif ($Identity -match '^[^@]+@[^@]+\.[^@]+$') {
                Write-Log "[ConvertTo-SID] Resolving UPN: $Identity"
                $filter = "(userPrincipalName=$(Escape-LDAPFilterValue -Value $Identity))"

                # The search itself was missing here. Every other branch runs its query;
                # this one only built the filter and fell through to the shared result
                # handling below, where $results was still empty. A UPN therefore never
                # resolved - it returned $null and was written to the negative cache, so
                # the second lookup did not even try. UPN is a documented input format.
                Write-Log "[ConvertTo-SID] LDAP Filter: $filter"
                $results = Invoke-LDAPSearch -Filter $filter -Properties "objectSid","sAMAccountName","distinguishedName" -SizeLimit 1
            }
            # Format 3: DOMAIN\sAMAccountName (requires cross-domain resolution)
            elseif ($Identity -match '^([^\\]+)\\(.+)$') {
                Write-Log "[ConvertTo-SID] Resolving DOMAIN\\Name: $Identity"

                # Use centralized cross-domain resolution
                $crossDomainInfo = Resolve-CrossDomainIdentity -Identity $Identity

                if ($crossDomainInfo.IsCrossDomain) {
                    Write-Log "[ConvertTo-SID] Cross-domain query detected for: $($crossDomainInfo.Domain)\$($crossDomainInfo.Identity)"

                    # Use GC for cross-domain query
                    $gcConn = Get-GCConnection
                    if (-not $gcConn) {
                        Write-Log "[ConvertTo-SID] GC connection unavailable - cannot resolve cross-domain identity" -Level Warning
                        return $null
                    }

                    # Search in target domain via GC
                    $filter = "(sAMAccountName=$(Escape-LDAPFilterValue -Value $crossDomainInfo.Identity))"
                    $searchBase = $crossDomainInfo.TargetDomainDN

                    Write-Log "[ConvertTo-SID] LDAP Filter: $filter (SearchBase: $searchBase)"
                    $results = Invoke-LDAPSearch -Filter $filter -Properties "objectSid","sAMAccountName","distinguishedName" -SizeLimit 10 -SearchBase $searchBase -LdapConnection $gcConn

                    # Filter results to exact target domain (exclude child domains)
                    if ($results -and $crossDomainInfo.TargetDomainFQDN) {
                        $resultsArray = @($results)
                        $filteredResults = @()

                        foreach ($res in $resultsArray) {
                            if ($res.distinguishedName) {
                                if (Test-DomainMatch -DistinguishedName $res.distinguishedName -TargetDomainFQDN $crossDomainInfo.TargetDomainFQDN) {
                                    $filteredResults += $res
                                }
                            }
                        }

                        $results = $filteredResults
                        Write-Log "[ConvertTo-SID] After cross-domain filter: $($results.Count) result(s)"
                    }
                } else {
                    # Same domain - standard query
                    $filter = "(sAMAccountName=$(Escape-LDAPFilterValue -Value $crossDomainInfo.Identity))"
                    Write-Log "[ConvertTo-SID] LDAP Filter: $filter"
                    $results = Invoke-LDAPSearch -Filter $filter -Properties "objectSid","sAMAccountName","distinguishedName" -SizeLimit 1
                }
            }
            # Format 4: sAMAccountName only (no domain prefix)
            else {
                Write-Log "[ConvertTo-SID] Resolving sAMAccountName: $Identity"
                $filter = "(sAMAccountName=$(Escape-LDAPFilterValue -Value $Identity))"

                Write-Log "[ConvertTo-SID] LDAP Filter: $filter"
                $results = Invoke-LDAPSearch -Filter $filter -Properties "objectSid","sAMAccountName","distinguishedName" -SizeLimit 1
            }

            # Ensure results is always an array for consistent handling
            $resultsArray = @($results)
            Write-Log "[ConvertTo-SID] LDAP search returned $($resultsArray.Count) result(s)"

            if ($resultsArray.Count -gt 0 -and $resultsArray[0]) {
                $result = $resultsArray[0]
                # objectSid is already converted to string by Invoke-LDAPSearch
                $sid = $result.objectSid

                Write-Log "[ConvertTo-SID] Resolved: $Identity -> $sid"

                # Cache bidirectionally
                $Script:NameToSIDCache[$Identity] = $sid

                # Also cache with domain prefix if we have it
                if ($result.sAMAccountName -and $result.distinguishedName) {
                    $sam = $result.sAMAccountName
                    $dn = $result.distinguishedName
                    if ($dn -match 'DC=([^,]+)') {
                        $domainName = $Matches[1].ToUpper()
                        $fullName = "$domainName\$sam"
                        if (-not $Script:NameToSIDCache.ContainsKey($fullName)) {
                            $Script:NameToSIDCache[$fullName] = $sid
                        }
                    }
                }

                return $sid
            }
            else {
                Write-Log "[ConvertTo-SID] No object found for: $Identity"

                # Cache negative result to avoid repeated lookups, use $null as marker for "not found"
                $Script:NameToSIDCache[$Identity] = $null
                return $null
            }
        }
        catch {
            Write-Log "[ConvertTo-SID] Error resolving $Identity : $_"
            return $null
        }
    }

    end {
        # Cache statistics available via: $Script:NameToSIDCache.Count
    }
}
