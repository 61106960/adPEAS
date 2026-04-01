<#
.SYNOPSIS
    Determines the security category of an identity in Active Directory (factual classification).

.DESCRIPTION
    Centralized module for factual classification of AD identities into security categories.

    ALWAYS returns a PSCustomObject with:
    - IsPrivileged: Boolean result (affected by IncludeOperators)
    - Category: Factual category (Privileged, Operator, BroadGroup, ExchangeService, Standard, Unknown)
    - Reason: Why the identity was classified this way
    - MatchedSID: The SID that matched (primary SID or sIDHistory SID)
    - MatchedGroup: Group name if matched via membership
    - Identity: Original identity input

    Possible Reason values:
    - "Operator group (static SID)" - Direct Operator group SID
    - "Privileged identity (static SID)" - Well-known privileged SID (SYSTEM, etc.)
    - "Privileged group (RID suffix -512)" - Domain-relative privileged group
    - "Broad group (static SID)" - Well-known broad group (Everyone, etc.)
    - "Broad group (RID suffix -513)" - Domain-relative broad group
    - "Member of Operator group" - Nested in Operator group
    - "Member of privileged group" - Nested in privileged group
    - "Member of broad group" - Nested in broad group
    - "sIDHistory contains Operator SID (SID History Injection risk)" - CRITICAL: Operator via sIDHistory
    - "sIDHistory contains privileged SID (SID History Injection risk)" - CRITICAL: Privileged via sIDHistory
    - "sIDHistory contains privileged RID -512 (SID History Injection risk)" - CRITICAL: Privileged RID in sIDHistory
    - "Could not resolve identity to SID" - Unknown identity
    - $null - Standard identity (no special classification)

    Categories:
    - "Privileged": Domain Admins, Enterprise Admins, SYSTEM, Administrators, etc.
    - "Operator": Account/Server/Backup/Print Operators (administrative but limited)
    - "BroadGroup": Domain Users, Domain Computers, Authenticated Users, Everyone, etc.
    - "ExchangeService": Exchange service groups (permissions are by-design)
    - "Standard": Regular users/groups (none of the above)
    - "Unknown": Could not resolve identity to SID

    Category Hierarchy (for IsPrivileged boolean):
    - Privileged → IsPrivileged = $true
    - Operator → IsPrivileged = $false (unless -IncludeOperators)
    - BroadGroup → IsPrivileged = $false
    - ExchangeService → IsPrivileged = $false (by-design permissions)
    - Standard → IsPrivileged = $false
    - Unknown → IsPrivileged = $null

.PARAMETER Identity
    The identity to check. Accepts multiple formats:
    - SID string (e.g., "S-1-5-21-...")
    - Distinguished Name (e.g., "CN=User,DC=domain,DC=com")
    - AD Object (PSCustomObject with objectSid/distinguishedName)
    - sAMAccountName (e.g., "Domain Admins")

.PARAMETER IncludeOperators
    Treats Operator category as Privileged for IsPrivileged boolean.

.PARAMETER NoCache
    Bypasses the result cache. Useful for debugging or when group memberships may have changed.

.EXAMPLE
    $result = Test-IsPrivileged -Identity "S-1-5-21-1234567890-512"
    $result.Category  # "Privileged" for Domain Admins
    $result.IsPrivileged  # $true

.EXAMPLE
    $result = Test-IsPrivileged -Identity "S-1-5-32-548"
    $result.Category  # "Operator" for Account Operators
    $result.IsPrivileged  # $false (Operators not privileged by default)

.EXAMPLE
    $result = Test-IsPrivileged -Identity "S-1-5-32-548" -IncludeOperators
    $result.Category  # "Operator" (unchanged)
    $result.IsPrivileged  # $true (Operators treated as privileged)

.EXAMPLE
    (Test-IsPrivileged -Identity $userObject).Category
    # Extract just the category from the result

.OUTPUTS
    [PSCustomObject] - Always returns detailed result object:
    - IsPrivileged: $true/$false/$null (affected by IncludeOperators; $null if Unknown)
    - Category: String (Privileged, Operator, BroadGroup, Standard, Unknown)
    - Reason: String describing why identity was classified this way
    - MatchedSID: The SID that matched (or $null)
    - MatchedGroup: Group name if matched via membership (or $null)
    - Identity: Original identity input

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

if (-not $Script:PrivilegedCheckCache) {
    $Script:PrivilegedCheckCache = @{}
}

if (-not $Script:GroupMembershipCache) {
    $Script:GroupMembershipCache = @{}
}

# Note: Escape-LDAPFilterValue is defined in adPEAS-InputValidation.ps1

<#
.SYNOPSIS
    Extracts the RID (last component) from a domain SID.
.DESCRIPTION
    Precisely extracts the RID suffix to avoid false positives.
    E.g., S-1-5-21-xxx-xxx-xxx-1512 returns "-1512", not matched by "-512".
.PARAMETER SID
    The full SID string.
.OUTPUTS
    String - The RID suffix (e.g., "-512") or $null if not a domain SID.
#>
function Get-SIDRIDSuffix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SID
    )

    # Domain SIDs have format S-1-5-21-xxx-xxx-xxx-RID
    # Extract only the last component after the final hyphen
    if ($SID -match '^S-1-5-21-\d+-\d+-\d+-(\d+)$') {
        return "-$($Matches[1])"
    }
    return $null
}

<#
.SYNOPSIS
    Internal helper to compute IsPrivileged boolean from Category.
.DESCRIPTION
    Applies IncludeOperators logic to determine boolean.
#>
function Get-IsPrivilegedFromCategory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Category,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeOperators
    )

    switch ($Category) {
        'Privileged'       { return $true }
        'Operator'         { return [bool]$IncludeOperators }
        'BroadGroup'       { return $false }
        'ExchangeService'  { return $false }   # Exchange groups have by-design permissions
        'Standard'         { return $false }
        'Unknown'          { return $null }   # $null = "could not determine" (distinct from $false)
        default            { return $null }   # Treat unexpected categories as unknown
    }
}

<#
.SYNOPSIS
    Internal helper to cache result and return PSCustomObject.
.DESCRIPTION
    Eliminates code duplication for the return points in Test-IsPrivileged.
    Caches the result object and computes IsPrivileged based on flags.
#>
function Complete-PrivilegedCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Result,

        [Parameter(Mandatory=$true)]
        [string]$CacheKey,

        [Parameter(Mandatory=$false)]
        [switch]$NoCache,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeOperators
    )

    # Compute IsPrivileged based on Category and flags
    $Result.IsPrivileged = Get-IsPrivilegedFromCategory -Category $Result.Category -IncludeOperators:$IncludeOperators

    # Cache the full result object
    if (-not $NoCache) {
        $Script:PrivilegedCheckCache[$CacheKey] = $Result
    }

    # Always return PSCustomObject
    return $Result
}

<#
.SYNOPSIS
    Clears the privileged check cache.

.DESCRIPTION
    Call this when group memberships may have changed or for debugging.
#>
function Clear-PrivilegedCheckCache {
    [CmdletBinding()]
    param()

    $Script:PrivilegedCheckCache = @{}
    Write-Log "[Clear-PrivilegedCheckCache] Cache cleared"
}

<#
.SYNOPSIS
    Clears the recursive group membership cache.

.DESCRIPTION
    Call this when group memberships may have changed or when starting a new scan.
    The cache is used by Test-IsExpectedInScope for efficient recursive membership checks.
#>
function Clear-GroupMembershipCache {
    [CmdletBinding()]
    param()

    $Script:GroupMembershipCache = @{}
    Write-Log "[Clear-GroupMembershipCache] Cache cleared"
}

<#
.SYNOPSIS
    Tests if an identity is an Exchange service group based on its Distinguished Name.

.DESCRIPTION
    Exchange service groups are created during Exchange installation and reside in the
    "OU=Microsoft Exchange Security Groups" organizational unit. This OU name remains
    English even in non-English AD installations, making it a reliable, language-independent
    detection method.

    Exchange groups (like "Exchange Windows Permissions", "Exchange Trusted Subsystem", etc.)
    have extensive AD permissions by design. These permissions are required for Exchange
    to function and cannot be removed without breaking Exchange functionality.

    Groups detected as Exchange service groups are classified as "ExchangeService" category
    and treated as "Attention" (not "Finding") in security checks because:
    1. The permissions are by-design and cannot be removed
    2. They are not misconfiguration that the customer can fix
    3. Pentesters should still know WHERE Exchange has permissions

.PARAMETER Identity
    The identity to check. Accepts:
    - Distinguished Name string (e.g., "CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,DC=domain,DC=com")
    - AD Object with distinguishedName property
    - SID string (will resolve to DN via LDAP)

.OUTPUTS
    [PSCustomObject] with:
    - IsExchangeService: $true if identity is an Exchange service group
    - Reason: Description of the match (or $null if not matched)
    - DistinguishedName: The DN that was checked

.EXAMPLE
    $result = Test-IsExchangeServiceGroup -Identity "CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,DC=contoso,DC=com"
    $result.IsExchangeService  # $true

.EXAMPLE
    $result = Test-IsExchangeServiceGroup -Identity $groupObject
    if ($result.IsExchangeService) { "Exchange service group - by-design permissions" }

.NOTES
    Author: Alexander Sturz (@_61106960_)
    The OU name "Microsoft Exchange Security Groups" is always English, even in localized AD installations.
#>
function Test-IsExchangeServiceGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        $Identity
    )

    process {
        $dn = $null
        $sid = $null

        # Extract DN and SID from various input formats
        if ($Identity -is [PSCustomObject] -or $Identity -is [System.Collections.Hashtable]) {
            if ($Identity.distinguishedName) {
                $dn = $Identity.distinguishedName
            } elseif ($Identity.DistinguishedName) {
                $dn = $Identity.DistinguishedName
            }
            if ($Identity.objectSid) {
                $sid = $Identity.objectSid
            } elseif ($Identity.SID) {
                $sid = $Identity.SID
            }
        }
        elseif ($Identity -is [string]) {
            if ($Identity -match '^S-1-\d+-\d+') {
                $sid = $Identity
            }
            elseif ($Identity -match '^CN=|^OU=|^DC=') {
                $dn = $Identity
            }
            else {
                # sAMAccountName - try to resolve via LDAP
                if ($Script:LdapConnection) {
                    try {
                        $obj = @(Get-DomainObject -Identity $Identity -Properties 'distinguishedName')[0]
                        if ($obj -and $obj.distinguishedName) {
                            $dn = $obj.distinguishedName
                        }
                    } catch {
                        Write-Log "[Test-IsExchangeServiceGroup] Failed to resolve sAMAccountName: $Identity"
                    }
                }
            }
        }

        # Session-level cache — same SIDs appear across hundreds of OUs
        if (-not $Script:ExchangeGroupCache) {
            $Script:ExchangeGroupCache = @{}
        }

        # Check cache before expensive LDAP lookup
        $cacheKey = if ($sid) { $sid } elseif ($dn) { $dn.ToLowerInvariant() } else { $null }
        if ($cacheKey -and $Script:ExchangeGroupCache.ContainsKey($cacheKey)) {
            return $Script:ExchangeGroupCache[$cacheKey]
        }

        # If we only have SID, resolve to DN
        if (-not $dn -and $sid -and $Script:LdapConnection) {
            try {
                $sidHex = ConvertTo-LDAPSIDHex -SID $sid
                if ($sidHex) {
                    $obj = @(Get-DomainObject -LDAPFilter "(objectSid=$sidHex)" -Properties 'distinguishedName')[0]
                    if ($obj -and $obj.distinguishedName) {
                        $dn = $obj.distinguishedName
                    }
                }
            } catch {
                Write-Log "[Test-IsExchangeServiceGroup] Failed to resolve SID to DN: $sid"
            }
        }

        # No DN available - cannot determine
        if (-not $dn) {
            $result = [PSCustomObject]@{
                IsExchangeService = $false
                Reason = $null
                DistinguishedName = $null
            }
            if ($cacheKey) { $Script:ExchangeGroupCache[$cacheKey] = $result }
            return $result
        }

        # Check if DN contains Exchange Security Groups OU (language-independent)
        # The OU name is always "Microsoft Exchange Security Groups" even in non-English installations
        if ($dn -match 'OU=Microsoft Exchange Security Groups') {
            Write-Log "[Test-IsExchangeServiceGroup] Exchange service group detected: $dn"
            $result = [PSCustomObject]@{
                IsExchangeService = $true
                Reason = "Member of Exchange Security Groups OU (by-design permissions)"
                DistinguishedName = $dn
            }
            if ($cacheKey) { $Script:ExchangeGroupCache[$cacheKey] = $result }
            return $result
        }

        # Not an Exchange service group
        $result = [PSCustomObject]@{
            IsExchangeService = $false
            Reason = $null
            DistinguishedName = $dn
        }
        if ($cacheKey) { $Script:ExchangeGroupCache[$cacheKey] = $result }
        return $result
    }
}

<#
.SYNOPSIS
    Tests if a computer is an Exchange Server based on Exchange-specific SPNs.

.DESCRIPTION
    Exchange Servers register characteristic Service Principal Names (SPNs) that
    uniquely identify them as Exchange infrastructure:
    - exchangeMDB/* - Mailbox Database service
    - exchangeRFR/* - Referral service (Address Book)
    - exchangeAB/*  - Address Book service

    This function queries the computer's servicePrincipalName attribute and checks
    for these Exchange-specific SPNs.

.PARAMETER Identity
    Can be:
    - SID string (e.g., "S-1-5-21-...")
    - Distinguished Name (e.g., "CN=EX01,OU=Servers,DC=contoso,DC=com")
    - sAMAccountName (e.g., "EX01$")
    - PSCustomObject with objectSid/SID/distinguishedName property

.OUTPUTS
    [PSCustomObject] with properties:
    - IsExchangeServer: Boolean indicating if computer is an Exchange Server
    - SPNs: Array of Exchange-specific SPNs found (if any)
    - ComputerName: The computer's name

.EXAMPLE
    $result = Test-IsExchangeServer -Identity "S-1-5-21-xxx-1001"
    if ($result.IsExchangeServer) { "This is an Exchange Server" }

.EXAMPLE
    $result = Test-IsExchangeServer -Identity "CN=EX01,OU=Servers,DC=contoso,DC=com"

.NOTES
    Author: Alexander Sturz (@_61106960_)
    Exchange SPNs are language-independent and reliable across all Exchange versions.
#>
function Test-IsExchangeServer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        $Identity
    )

    process {
        $sid = $null
        $dn = $null

        # Extract SID/DN from various input formats
        if ($Identity -is [PSCustomObject] -or $Identity -is [System.Collections.Hashtable]) {
            if ($Identity.objectSid) { $sid = $Identity.objectSid }
            elseif ($Identity.SID) { $sid = $Identity.SID }
            if ($Identity.distinguishedName) { $dn = $Identity.distinguishedName }
            elseif ($Identity.DistinguishedName) { $dn = $Identity.DistinguishedName }
        }
        elseif ($Identity -is [string]) {
            if ($Identity -match '^S-1-\d+-\d+') {
                $sid = $Identity
            }
            elseif ($Identity -match '^CN=|^OU=|^DC=') {
                $dn = $Identity
            }
            else {
                # Assume sAMAccountName - will resolve via LDAP
                $sid = $Identity
            }
        }

        # Need LDAP connection
        if (-not $Script:LdapConnection) {
            return [PSCustomObject]@{
                IsExchangeServer = $false
                SPNs = @()
                ComputerName = $null
            }
        }

        # Build LDAP filter based on what we have
        $ldapFilter = $null
        if ($sid -and $sid -match '^S-1-\d+-\d+') {
            $sidHex = ConvertTo-LDAPSIDHex -SID $sid
            if ($sidHex) {
                $ldapFilter = "(objectSid=$sidHex)"
            }
        }
        elseif ($dn) {
            # For DN, we need to escape special characters
            $escapedDN = $dn -replace '([\\*\(\)])', '\$1'
            $ldapFilter = "(distinguishedName=$escapedDN)"
        }
        elseif ($sid) {
            # Assume it's a sAMAccountName
            $ldapFilter = "(sAMAccountName=$sid)"
        }

        if (-not $ldapFilter) {
            return [PSCustomObject]@{
                IsExchangeServer = $false
                SPNs = @()
                ComputerName = $null
            }
        }

        try {
            $obj = @(Get-DomainObject -LDAPFilter $ldapFilter -Properties 'servicePrincipalName', 'name', 'sAMAccountName', 'objectClass')[0]

            if (-not $obj) {
                return [PSCustomObject]@{
                    IsExchangeServer = $false
                    SPNs = @()
                    ComputerName = $null
                }
            }

            # Check if it's a computer
            $objectClasses = @($obj.objectClass)
            if ($objectClasses -notcontains 'computer') {
                return [PSCustomObject]@{
                    IsExchangeServer = $false
                    SPNs = @()
                    ComputerName = $obj.name
                }
            }

            # Check for Exchange-specific SPNs
            $spns = @($obj.servicePrincipalName)
            $exchangeSPNs = @($spns | Where-Object {
                $_ -match '^exchangeMDB/' -or
                $_ -match '^exchangeRFR/' -or
                $_ -match '^exchangeAB/'
            })

            $computerName = if ($obj.name) { $obj.name } elseif ($obj.sAMAccountName) { $obj.sAMAccountName -replace '\$$' } else { $null }

            if ($exchangeSPNs.Count -gt 0) {
                Write-Log "[Test-IsExchangeServer] Exchange Server detected: $computerName (SPNs: $($exchangeSPNs -join ', '))"
                return [PSCustomObject]@{
                    IsExchangeServer = $true
                    SPNs = $exchangeSPNs
                    ComputerName = $computerName
                }
            }

            return [PSCustomObject]@{
                IsExchangeServer = $false
                SPNs = @()
                ComputerName = $computerName
            }

        } catch {
            Write-Log "[Test-IsExchangeServer] Error checking $Identity`: $_"
            return [PSCustomObject]@{
                IsExchangeServer = $false
                SPNs = @()
                ComputerName = $null
            }
        }
    }
}

<#
.SYNOPSIS
    Gets all recursive group memberships for an identity (cached).

.DESCRIPTION
    Uses a single LDAP query with LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941) to retrieve ALL groups where the identity is a direct or nested member.
    Results are cached for subsequent lookups (SID → Array of Group SIDs).

.PARAMETER IdentitySID
    The SID of the identity to check.

.PARAMETER IdentityDN
    The Distinguished Name of the identity. If not provided, will be resolved from SID.

.PARAMETER NoCache
    Bypasses the cache and forces a new LDAP query.

.OUTPUTS
    [String[]] - Array of group SIDs where the identity is a (recursive) member.
    Returns empty array if identity is not a member of any groups.

.EXAMPLE
    $groupSIDs = Get-RecursiveGroupMembership -IdentitySID "S-1-5-21-xxx-1234"
    if ($groupSIDs -contains "S-1-5-21-xxx-512") { "Member of Domain Admins" }

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
function Get-RecursiveGroupMembership {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$IdentitySID,

        [Parameter(Mandatory=$false)]
        [string]$IdentityDN,

        [Parameter(Mandatory=$false)]
        [switch]$NoCache
    )

    # Check cache first (unless NoCache is specified)
    if (-not $NoCache -and $Script:GroupMembershipCache.ContainsKey($IdentitySID)) {
        Write-Log "[Get-RecursiveGroupMembership] Cache hit for $IdentitySID"
        return $Script:GroupMembershipCache[$IdentitySID]
    }

    # Need LDAP connection
    if (-not $Script:LdapConnection) {
        Write-Log "[Get-RecursiveGroupMembership] No LDAP connection available"
        return @()
    }

    # Resolve DN from SID if not provided
    if (-not $IdentityDN) {
        try {
            $sidHex = ConvertTo-LDAPSIDHex -SID $IdentitySID
            if ($sidHex) {
                $obj = @(Get-DomainObject -LDAPFilter "(objectSid=$sidHex)" -Properties 'distinguishedName')[0]
                if ($obj) {
                    $IdentityDN = $obj.distinguishedName
                    Write-Log "[Get-RecursiveGroupMembership] Resolved SID to DN: $IdentityDN"
                }
            }
        } catch {
            Write-Log "[Get-RecursiveGroupMembership] Failed to resolve SID to DN: $_"
        }

        # Still no DN after resolution attempt (either exception or object not found)
        if (-not $IdentityDN) {
            Write-Log "[Get-RecursiveGroupMembership] No DN available for $IdentitySID"
            $Script:GroupMembershipCache[$IdentitySID] = @()
            return @()
        }
    }

    # Single LDAP query: Get ALL groups where identity is a recursive member
    # Query pattern: (member:1.2.840.113556.1.4.1941:=<DN>)
    $groupSIDs = @()

    try {
        Write-Log "[Get-RecursiveGroupMembership] Querying all group memberships for: $IdentityDN"

        # Escape DN for LDAP filter (special characters in DN)
        $escapedDN = Escape-LDAPFilterValue -Value $IdentityDN

        $filter = "(member:1.2.840.113556.1.4.1941:=$escapedDN)"
        $groups = @(Get-DomainGroup -LDAPFilter $filter -Properties 'objectSid','sAMAccountName')

        if ($groups) {
            foreach ($group in $groups) {
                if ($group.objectSid) {
                    $groupSIDs += $group.objectSid
                    Write-Log "[Get-RecursiveGroupMembership] Found membership: $($group.sAMAccountName) ($($group.objectSid))"
                }
            }
        }

        Write-Log "[Get-RecursiveGroupMembership] Found $($groupSIDs.Count) group membership(s) for $IdentitySID"

    } catch {
        Write-Log "[Get-RecursiveGroupMembership] Error querying group memberships: $_"
    }

    # Cache the result
    $Script:GroupMembershipCache[$IdentitySID] = $groupSIDs
    Write-Log "[Get-RecursiveGroupMembership] Cached result for $IdentitySID"

    return $groupSIDs
}

function Test-IsPrivileged {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        $Identity,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeOperators,

        [Parameter(Mandatory=$false)]
        [switch]$NoCache
    )

    process {
        # ===== PHASE 1: Identity Resolution =====
        # Extract SID, DN, and name from various input formats
        $sid = $null
        $dn = $null
        $name = $null

        # Handle AD Objects (PSCustomObject/Hashtable with objectSid)
        if ($Identity -is [PSCustomObject] -or $Identity -is [System.Collections.Hashtable]) {
            if ($Identity.objectSid) {
                $sid = $Identity.objectSid
            } elseif ($Identity.SID) {
                $sid = $Identity.SID
            }
            if ($Identity.distinguishedName) {
                $dn = $Identity.distinguishedName
            } elseif ($Identity.DistinguishedName) {
                $dn = $Identity.DistinguishedName
            }
            if ($Identity.sAMAccountName) {
                $name = $Identity.sAMAccountName
            } elseif ($Identity.name) {
                $name = $Identity.name
            }
        }
        elseif ($Identity -is [System.Security.Principal.SecurityIdentifier]) {
            $sid = $Identity.Value
        }
        elseif ($Identity -is [string]) {
            if ($Identity -match '^S-1-\d+-\d+') {
                $sid = $Identity
            } else {
                $sid = ConvertTo-SID -Identity $Identity
                $name = $Identity
            }
        }

        if (-not $sid) {
            Write-Log "[Test-IsPrivileged] Could not resolve identity to SID: $Identity"
            return [PSCustomObject]@{
                IsPrivileged = $null
                Category = 'Unknown'
                Reason = 'Could not resolve identity to SID'
                MatchedSID = $null
                MatchedGroup = $null
                Identity = $Identity
            }
        }

        # ===== PHASE 2: Cache Check =====
        $cacheKey = $sid

        if (-not $NoCache -and $Script:PrivilegedCheckCache.ContainsKey($cacheKey)) {
            $cached = $Script:PrivilegedCheckCache[$cacheKey]
            # Return a copy with IsPrivileged computed for current flags
            $resultCopy = $cached.PSObject.Copy()
            $resultCopy.IsPrivileged = Get-IsPrivilegedFromCategory -Category $cached.Category -IncludeOperators:$IncludeOperators
            return $resultCopy
        }

        # Extract RID suffix
        $ridSuffix = Get-SIDRIDSuffix -SID $sid

        # ===== PHASE 3: Static SID Checks =====
        # 3a. Check Operator SIDs FIRST (separate category)
        if ($sid -in $Script:OperatorSIDs) {
            $result = [PSCustomObject]@{
                IsPrivileged = $false
                Category = 'Operator'
                Reason = "Operator group (static SID)"
                MatchedSID = $sid
                MatchedGroup = $null
                Identity = $Identity
            }
            Write-Log "[Test-IsPrivileged] Operator detected: $sid"
            return (Complete-PrivilegedCheck -Result $result -CacheKey $cacheKey -NoCache:$NoCache -IncludeOperators:$IncludeOperators)
        }

        # 3a2. Check Operator RID suffixes (domain-relative, e.g., Cert Publishers -517)
        if ($ridSuffix -and $ridSuffix -in $Script:OperatorRIDSuffixes) {
            $result = [PSCustomObject]@{
                IsPrivileged = $false
                Category = 'Operator'
                Reason = "Operator group (RID suffix $ridSuffix)"
                MatchedSID = $sid
                MatchedGroup = $null
                Identity = $Identity
            }
            Write-Log "[Test-IsPrivileged] Operator via RID suffix: $sid"
            return (Complete-PrivilegedCheck -Result $result -CacheKey $cacheKey -NoCache:$NoCache -IncludeOperators:$IncludeOperators)
        }

        # 3b. Check Privileged SIDs (static well-known)
        if ($sid -in $Script:PrivilegedSIDs) {
            $result = [PSCustomObject]@{
                IsPrivileged = $false
                Category = 'Privileged'
                Reason = "Privileged identity (static SID)"
                MatchedSID = $sid
                MatchedGroup = $null
                Identity = $Identity
            }
            Write-Log "[Test-IsPrivileged] Privileged via static SID: $sid"
            return (Complete-PrivilegedCheck -Result $result -CacheKey $cacheKey -NoCache:$NoCache -IncludeOperators:$IncludeOperators)
        }

        # 3c. Check Privileged RID suffixes (precise matching)
        if ($ridSuffix -and $ridSuffix -in $Script:PrivilegedRIDSuffixes) {
            $result = [PSCustomObject]@{
                IsPrivileged = $false
                Category = 'Privileged'
                Reason = "Privileged group (RID suffix $ridSuffix)"
                MatchedSID = $sid
                MatchedGroup = $null
                Identity = $Identity
            }
            Write-Log "[Test-IsPrivileged] Privileged via RID suffix: $sid"
            return (Complete-PrivilegedCheck -Result $result -CacheKey $cacheKey -NoCache:$NoCache -IncludeOperators:$IncludeOperators)
        }

        # 3d. Check Broad Group SIDs (static well-known)
        # We defer the return to Phase 5 to check if the BroadGroup is member of a Privileged group.
        $isBroadGroup = $false
        $broadGroupReason = $null

        if ($sid -in $Script:BroadGroupSIDs) {
            $isBroadGroup = $true
            $broadGroupReason = "Broad group (static SID)"
            Write-Log "[Test-IsPrivileged] BroadGroup detected (static): $sid - checking for privileged membership..."
        }

        # 3e. Check Broad Group RID suffixes (precise matching)
        if (-not $isBroadGroup -and $ridSuffix -in $Script:BroadGroupRIDSuffixes) {
            $isBroadGroup = $true
            $broadGroupReason = "Broad group (RID suffix $ridSuffix)"
            Write-Log "[Test-IsPrivileged] BroadGroup detected (RID): $sid - checking for privileged membership..."
        }

        # Resolve name from SID only if not already known (needed for logging)
        if (-not $name -and $sid) {
            $name = ConvertFrom-SID -SID $sid
        }

        Write-Log "[Test-IsPrivileged] Checking SID: $sid (Name: $name)"

        # ===== PHASE 4: sIDHistory Check (SID History Injection Detection) =====
        # Check if this identity has privileged SIDs in sIDHistory attribute.
        # Only domain SIDs (S-1-5-21-*) can have sIDHistory — well-known SIDs
        # (SYSTEM, Administrators, Everyone, etc.) have no AD object to query.
        $isDomainSID = $sid -match '^S-1-5-21-'
        if ($Script:LdapConnection -and $isDomainSID) {
            try {
                # Query the AD object for sIDHistory + distinguishedName (reused by Phase 5)
                $sidHex = ConvertTo-LDAPSIDHex -SID $sid
                if ($sidHex) {
                    $adObject = @(Get-DomainObject -LDAPFilter "(objectSid=$sidHex)" -Properties 'sIDHistory','distinguishedName')[0]

                    # Capture DN for Phase 5 (avoids redundant LDAP query in Get-RecursiveGroupMembership)
                    if ($adObject -and $adObject.distinguishedName -and -not $dn) {
                        $dn = $adObject.distinguishedName
                    }

                    if ($adObject -and $adObject.sIDHistory) {
                        # sIDHistory can contain multiple SIDs
                        $sidHistoryValues = @()
                        if ($adObject.sIDHistory -is [array]) {
                            $sidHistoryValues = $adObject.sIDHistory
                        } else {
                            $sidHistoryValues = @($adObject.sIDHistory)
                        }

                        Write-Log "[Test-IsPrivileged] Found $($sidHistoryValues.Count) sIDHistory entries for $sid"

                        foreach ($historySID in $sidHistoryValues) {
                            # Convert byte array to SID string if needed
                            $historySIDString = $null
                            if ($historySID -is [byte[]]) {
                                try {
                                    $secId = New-Object System.Security.Principal.SecurityIdentifier($historySID, 0)
                                    $historySIDString = $secId.Value
                                } catch {
                                    Write-Log "[Test-IsPrivileged] Failed to convert sIDHistory byte array: $_"
                                    continue
                                }
                            } elseif ($historySID -is [string]) {
                                $historySIDString = $historySID
                            } else {
                                continue
                            }

                            Write-Log "[Test-IsPrivileged] Checking sIDHistory entry: $historySIDString"

                            # Check if this sIDHistory SID is privileged
                            $historyRIDSuffix = Get-SIDRIDSuffix -SID $historySIDString

                            # Check Operator SIDs in sIDHistory
                            if ($historySIDString -in $Script:OperatorSIDs) {
                                $result = [PSCustomObject]@{
                                    IsPrivileged = $false
                                    Category = 'Operator'
                                    Reason = "sIDHistory contains Operator SID (SID History Injection risk)"
                                    MatchedSID = $historySIDString
                                    MatchedGroup = $null
                                    Identity = $Identity
                                }
                                Write-Log "[Test-IsPrivileged] CRITICAL: sIDHistory contains Operator SID: $historySIDString"
                                return (Complete-PrivilegedCheck -Result $result -CacheKey $cacheKey -NoCache:$NoCache -IncludeOperators:$IncludeOperators)
                            }

                            # Check Operator RID suffixes in sIDHistory (e.g., Cert Publishers -517)
                            if ($historyRIDSuffix -and $historyRIDSuffix -in $Script:OperatorRIDSuffixes) {
                                $result = [PSCustomObject]@{
                                    IsPrivileged = $false
                                    Category = 'Operator'
                                    Reason = "sIDHistory contains Operator RID $historyRIDSuffix (SID History Injection risk)"
                                    MatchedSID = $historySIDString
                                    MatchedGroup = $null
                                    Identity = $Identity
                                }
                                Write-Log "[Test-IsPrivileged] CRITICAL: sIDHistory contains Operator RID: $historySIDString"
                                return (Complete-PrivilegedCheck -Result $result -CacheKey $cacheKey -NoCache:$NoCache -IncludeOperators:$IncludeOperators)
                            }

                            # Check Privileged SIDs in sIDHistory
                            if ($historySIDString -in $Script:PrivilegedSIDs) {
                                $result = [PSCustomObject]@{
                                    IsPrivileged = $false
                                    Category = 'Privileged'
                                    Reason = "sIDHistory contains privileged SID (SID History Injection risk)"
                                    MatchedSID = $historySIDString
                                    MatchedGroup = $null
                                    Identity = $Identity
                                }
                                Write-Log "[Test-IsPrivileged] CRITICAL: sIDHistory contains privileged SID: $historySIDString"
                                return (Complete-PrivilegedCheck -Result $result -CacheKey $cacheKey -NoCache:$NoCache -IncludeOperators:$IncludeOperators)
                            }

                            # Check Privileged RID suffixes in sIDHistory
                            if ($historyRIDSuffix -and $historyRIDSuffix -in $Script:PrivilegedRIDSuffixes) {
                                $result = [PSCustomObject]@{
                                    IsPrivileged = $false
                                    Category = 'Privileged'
                                    Reason = "sIDHistory contains privileged RID $historyRIDSuffix (SID History Injection risk)"
                                    MatchedSID = $historySIDString
                                    MatchedGroup = $null
                                    Identity = $Identity
                                }
                                Write-Log "[Test-IsPrivileged] CRITICAL: sIDHistory contains privileged RID: $historySIDString"
                                return (Complete-PrivilegedCheck -Result $result -CacheKey $cacheKey -NoCache:$NoCache -IncludeOperators:$IncludeOperators)
                            }
                        }
                    }
                }
            } catch {
                Write-Log "[Test-IsPrivileged] Error checking sIDHistory: $_"
            }
        }

        # ===== PHASE 5: Recursive Group Membership Check (ALWAYS when LDAP available) =====
        # Uses Get-RecursiveGroupMembership for a SINGLE LDAP query instead of N queries.
        if ($Script:LdapConnection) {
            # Get all group memberships with a single LDAP query (cached)
            $groupMemberships = Get-RecursiveGroupMembership -IdentitySID $sid -IdentityDN $dn

            if ($groupMemberships -and $groupMemberships.Count -gt 0) {
                Write-Log "[Test-IsPrivileged] Found $($groupMemberships.Count) group membership(s) for $sid"

                $domainSID = $null
                if ($Script:LDAPContext -and $Script:LDAPContext.DomainSID) {
                    $domainSID = $Script:LDAPContext.DomainSID
                }

                # 5a. Check Operator group membership (local array comparison)
                # First check static Operator SIDs
                foreach ($opSID in $Script:OperatorSIDs) {
                    if ($opSID -in $groupMemberships) {
                        $groupName = ConvertFrom-SID -SID $opSID
                        if (-not $groupName) { $groupName = $opSID }

                        $result = [PSCustomObject]@{
                            IsPrivileged = $false
                            Category = 'Operator'
                            Reason = "Member of Operator group"
                            MatchedSID = $opSID
                            MatchedGroup = $groupName
                            Identity = $Identity
                        }
                        Write-Log "[Test-IsPrivileged] Operator via membership: $groupName"
                        return (Complete-PrivilegedCheck -Result $result -CacheKey $cacheKey -NoCache:$NoCache -IncludeOperators:$IncludeOperators)
                    }
                }

                # Then check domain-relative Operator RID suffixes (e.g., Cert Publishers -517)
                if ($domainSID) {
                    foreach ($suffix in $Script:OperatorRIDSuffixes) {
                        $opSID = "$domainSID$suffix"
                        if ($opSID -in $groupMemberships) {
                            $groupName = ConvertFrom-SID -SID $opSID
                            if (-not $groupName) { $groupName = $opSID }

                            $result = [PSCustomObject]@{
                                IsPrivileged = $false
                                Category = 'Operator'
                                Reason = "Member of Operator group"
                                MatchedSID = $opSID
                                MatchedGroup = $groupName
                                Identity = $Identity
                            }
                            Write-Log "[Test-IsPrivileged] Operator via membership (RID suffix): $groupName"
                            return (Complete-PrivilegedCheck -Result $result -CacheKey $cacheKey -NoCache:$NoCache -IncludeOperators:$IncludeOperators)
                        }
                    }
                }

                # 5b. Check Privileged group membership (local array comparison)
                $privilegedGroupSIDs = @('S-1-5-32-544')  # BUILTIN\Administrators
                if ($domainSID) {
                    foreach ($suffix in $Script:PrivilegedRIDSuffixes) {
                        $privilegedGroupSIDs += "$domainSID$suffix"
                    }
                }

                foreach ($groupSID in $privilegedGroupSIDs) {
                    if ($groupSID -in $groupMemberships) {
                        $groupName = ConvertFrom-SID -SID $groupSID
                        if (-not $groupName) { $groupName = $groupSID }

                        $result = [PSCustomObject]@{
                            IsPrivileged = $false
                            Category = 'Privileged'
                            Reason = "Member of privileged group"
                            MatchedSID = $groupSID
                            MatchedGroup = $groupName
                            Identity = $Identity
                        }
                        Write-Log "[Test-IsPrivileged] Privileged via membership: $groupName"
                        return (Complete-PrivilegedCheck -Result $result -CacheKey $cacheKey -NoCache:$NoCache -IncludeOperators:$IncludeOperators)
                    }
                }

                # 5c. Check BroadGroup membership (local array comparison)
                if ($domainSID) {
                    foreach ($suffix in $Script:BroadGroupRIDSuffixes) {
                        $broadSID = "$domainSID$suffix"
                        if ($broadSID -in $groupMemberships) {
                            $groupName = ConvertFrom-SID -SID $broadSID
                            if (-not $groupName) { $groupName = $broadSID }

                            $result = [PSCustomObject]@{
                                IsPrivileged = $false
                                Category = 'BroadGroup'
                                Reason = "Member of broad group"
                                MatchedSID = $broadSID
                                MatchedGroup = $groupName
                                Identity = $Identity
                            }
                            Write-Log "[Test-IsPrivileged] BroadGroup via membership: $groupName"
                            return (Complete-PrivilegedCheck -Result $result -CacheKey $cacheKey -NoCache:$NoCache -IncludeOperators:$IncludeOperators)
                        }
                    }
                }
            } else {
                Write-Log "[Test-IsPrivileged] No group memberships found for $sid"
            }
        } else {
            Write-Log "[Test-IsPrivileged] No LDAP connection - group membership check skipped"
        }

        # ===== PHASE 6: Final Category Determination =====
        # If we identified this as a BroadGroup in Phase 3/4 but deferred the result to check
        # for privileged group membership first, return BroadGroup now.
        if ($isBroadGroup) {
            $result = [PSCustomObject]@{
                IsPrivileged = $false
                Category = 'BroadGroup'
                Reason = $broadGroupReason
                MatchedSID = $sid
                MatchedGroup = $null
                Identity = $Identity
            }
            Write-Log "[Test-IsPrivileged] BroadGroup confirmed (no privileged membership found): $sid"
            return (Complete-PrivilegedCheck -Result $result -CacheKey $cacheKey -NoCache:$NoCache -IncludeOperators:$IncludeOperators)
        }

        # Default: Standard Category
        $result = [PSCustomObject]@{
            IsPrivileged = $false
            Category = 'Standard'
            Reason = $null
            MatchedSID = $sid
            MatchedGroup = $null
            Identity = $Identity
        }
        Write-Log "[Test-IsPrivileged] Standard identity: $sid"
        return (Complete-PrivilegedCheck -Result $result -CacheKey $cacheKey -NoCache:$NoCache -IncludeOperators:$IncludeOperators)
    }
}

<#
.SYNOPSIS
    Determines if an ACL identity should be skipped based on the check context.

.DESCRIPTION
    Different security checks require different filtering logic:

    - Domain Root ACLs: SELF/Creator Owner are ABNORMAL (findings!)
    - OU/Container ACLs: SELF/Creator Owner are NORMAL (self-modification)
    - CN=Computers: SELF/Creator Owner/Pre-Win2000 are NORMAL (object management)

    This function returns $true if the identity should be SKIPPED (not a finding).

.PARAMETER SID
    The Security Identifier to check.

.PARAMETER Context
    The context of the check. Valid values:
    - 'DomainRoot': ACLs on the domain root object (DC=domain,DC=com)
    - 'OU': ACLs on Organizational Units
    - 'Container': ACLs on containers like CN=Computers
    - 'Object': ACLs on individual objects (users, computers, groups)

.OUTPUTS
    [PSCustomObject] with:
    - Skip: $true if the identity should be skipped completely
    - SkipAllPropertiesOnly: $true if only "All Properties" findings should be skipped (but specific property findings shown)
    - Reason: Why it should be skipped (or $null)

.EXAMPLE
    $result = Test-IsExpectedACLIdentity -SID 'S-1-5-10' -Context 'OU'
    if ($result.Skip) { continue }  # Skip SELF on OUs

.EXAMPLE
    $result = Test-IsExpectedACLIdentity -SID 'S-1-5-10' -Context 'DomainRoot'
    # Returns Skip=$false because SELF on Domain Root is abnormal!

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
function Test-IsExpectedACLIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SID,

        [Parameter(Mandatory=$true)]
        [ValidateSet('DomainRoot', 'OU', 'Container', 'Object', 'GPO')]
        [string]$Context
    )

    $result = [PSCustomObject]@{
        Skip = $false
        SkipAllPropertiesOnly = $false  # If true: skip "All Properties" findings but show specific property findings
        Reason = $null
    }

    switch ($Context) {
        'DomainRoot' {
            # On Domain Root, NO special identities should be skipped!
            $result.Skip = $false
            $result.Reason = $null
        }

        'OU' {
            # On OUs, only SELF/Creator Owner should be completely skipped
            if ($SID -in $Script:SelfModificationSIDs) {
                $result.Skip = $true
                $result.Reason = "Self-modification identity (normal on OUs)"
            }
            elseif ($SID -in $Script:LegacyCompatibilitySIDs) {
                # Don't skip completely - only skip "All Properties" findings
                $result.Skip = $false
                $result.SkipAllPropertiesOnly = $true
                $result.Reason = "Legacy compatibility identity (has default read rights)"
            }
            elseif ($SID -in $Script:BroadGroupSIDs) {
                # Don't skip completely - only skip "All Properties" findings
                $result.Skip = $false
                $result.SkipAllPropertiesOnly = $true
                $result.Reason = "Broad group (has default read rights)"
            }
        }

        'Container' {
            # On Containers (like CN=Computers), several identities are expected:
            # - SELF, Creator Owner: self-modification
            # - Pre-Win2000: legacy compatibility
            # - Account/Print Operators: can manage computer accounts by design
            if ($SID -in $Script:SelfModificationSIDs) {
                $result.Skip = $true
                $result.Reason = "Self-modification identity (normal on containers)"
            }
            elseif ($SID -in $Script:LegacyCompatibilitySIDs) {
                $result.Skip = $true
                $result.Reason = "Legacy compatibility identity (normal on containers)"
            }
            elseif ($SID -in $Script:ContainerOperatorSIDs) {
                $result.Skip = $true
                $result.Reason = "Operator group (expected to manage computer accounts)"
            }
        }

        'Object' {
            # On individual objects, SELF is normal (object modifies itself)
            if ($SID -in $Script:SelfModificationSIDs) {
                $result.Skip = $true
                $result.Reason = "Self-modification identity (normal on objects)"
            }
        }

        'GPO' {
            # On GPOs, Creator Owner is a default ACE (creator has rights on created GPO), this is normal Windows behavior
            if ($SID -in $Script:SelfModificationSIDs) {
                $result.Skip = $true
                $result.Reason = "Self-modification identity (normal on GPOs - creator has rights)"
            }
        }
    }

    return $result
}

<#
.SYNOPSIS
    Tests if an identity is EXPECTED in a specific security scope.

.DESCRIPTION
    Context-dependent check that answers: "Is this identity expected to have these rights?"
    Uses scope definitions from $Script:SecurityScopes to classify findings.

    This function is the complement to Test-IsPrivileged:
    - Test-IsPrivileged: "WHAT is this identity?" (factual classification)
    - Test-IsExpectedInScope: "Is it EXPECTED here?" (contextual judgment)

    Return Severities:
    - "Expected": Identity is expected in this scope (no finding needed)
    - "Attention": Identity is technically expected but security-relevant (soft finding)
    - "Finding": Identity should NOT have these rights (hard finding)

.PARAMETER Identity
    The identity to check. Accepts:
    - SID string (e.g., "S-1-5-21-...")
    - AD Object with objectSid property
    - sAMAccountName (will be resolved to SID)

.PARAMETER Scope
    The security scope to check against. Available scopes:
    - DCSync: Identities with replication rights
    - DomainRootACL: Identities with GenericAll/WriteDACL on domain root
    - OUACL: Identities with GenericAll/WriteDACL on OUs
    - ComputerContainerACL: Identities with CreateChild on CN=Computers
    - MachineAccountQuota: Identities that can create computer accounts via MAQ
    - UserObjectACL: Identities with write access to user objects
    - GPO: Identities that can create/edit GPOs
    - ADCSEnroll: Identities with certificate enrollment rights
    - KerberosDelegation: Identities with delegation configured
    - LAPSRead: Identities that can read LAPS passwords

.PARAMETER ReturnDetails
    Returns detailed object instead of just severity string.

.EXAMPLE
    Test-IsExpectedInScope -Identity "S-1-5-21-xxx-512" -Scope "DCSync"
    Returns "Finding" - Domain Admins should be flagged for DCSync (even if they have it).

.EXAMPLE
    Test-IsExpectedInScope -Identity "S-1-5-18" -Scope "DCSync"
    Returns "Expected" - SYSTEM is expected to have DCSync rights.

.EXAMPLE
    Test-IsExpectedInScope -Identity "S-1-5-11" -Scope "MachineAccountQuota"
    Returns "Attention" - Authenticated Users with MAQ is default but noteworthy.

.OUTPUTS
    [String] - Default: "Expected", "Attention", or "Finding"
    [PSCustomObject] - With -ReturnDetails: Detailed result object

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
function Test-IsExpectedInScope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        $Identity,

        [Parameter(Mandatory=$true)]
        [ValidateSet(
            'DCSync',
            'DomainRootACL',
            'OUACL',
            'ComputerContainerACL',
            'MachineAccountQuota',
            'UserObjectACL',
            'GPO',
            'ADCSEnroll',
            'KerberosDelegation',
            'LAPSRead',
            'PKIContainer'
        )]
        [string]$Scope,

        [Parameter(Mandatory=$false)]
        [switch]$ReturnDetails
    )

    process {
        # ===== Get Scope Definition =====
        $scopeDef = $Script:SecurityScopes[$Scope]
        if (-not $scopeDef) {
            Write-Warning "[Test-IsExpectedInScope] Unknown scope: $Scope"
            if ($ReturnDetails) {
                return [PSCustomObject]@{
                    Severity = 'Finding'
                    Reason = "Unknown scope: $Scope"
                    Identity = $Identity
                    Scope = $Scope
                }
            }
            return 'Finding'
        }

        # ===== Resolve Identity to SID =====
        $sid = $null
        $name = $null

        if ($Identity -is [PSCustomObject] -or $Identity -is [System.Collections.Hashtable]) {
            if ($Identity.objectSid) { $sid = $Identity.objectSid }
            elseif ($Identity.SID) { $sid = $Identity.SID }
            if ($Identity.sAMAccountName) { $name = $Identity.sAMAccountName }
            elseif ($Identity.name) { $name = $Identity.name }
        }
        elseif ($Identity -is [System.Security.Principal.SecurityIdentifier]) {
            $sid = $Identity.Value
        }
        elseif ($Identity -is [string]) {
            if ($Identity -match '^S-1-\d+-\d+') {
                $sid = $Identity
            } else {
                $sid = ConvertTo-SID -Identity $Identity
                $name = $Identity
            }
        }

        if (-not $sid -and -not $name) {
            if ($ReturnDetails) {
                return [PSCustomObject]@{
                    Severity = 'Finding'
                    Reason = "Could not resolve identity"
                    Identity = $Identity
                    Scope = $Scope
                }
            }
            return 'Finding'
        }

        # Resolve name from SID if not already known
        if (-not $name -and $sid) {
            $name = ConvertFrom-SID -SID $sid
        }

        # ===== Check Static Expected SIDs =====
        if ($sid -and $scopeDef.ExpectedSIDs -and $sid -in $scopeDef.ExpectedSIDs) {
            if ($ReturnDetails) {
                return [PSCustomObject]@{
                    Severity = 'Expected'
                    Reason = "Static SID in scope '$Scope'"
                    Identity = $Identity
                    Scope = $Scope
                    MatchedSID = $sid
                }
            }
            return 'Expected'
        }

        # ===== Check Expected RID Suffixes (precise matching) =====
        if ($sid) {
            $ridSuffix = Get-SIDRIDSuffix -SID $sid
            if ($ridSuffix -and $scopeDef.ExpectedRIDSuffixes -and $ridSuffix -in $scopeDef.ExpectedRIDSuffixes) {
                if ($ReturnDetails) {
                    return [PSCustomObject]@{
                        Severity = 'Expected'
                        Reason = "RID suffix $ridSuffix in scope '$Scope'"
                        Identity = $Identity
                        Scope = $Scope
                        MatchedSID = $sid
                        MatchedRIDSuffix = $ridSuffix
                    }
                }
                return 'Expected'
            }
        }

        # ===== Check Attention Broad Groups =====
        if ($sid -and $scopeDef.AttentionBroadGroups -and $sid -in $scopeDef.AttentionBroadGroups) {
            if ($ReturnDetails) {
                return [PSCustomObject]@{
                    Severity = 'Attention'
                    Reason = "Broad group in scope '$Scope' (expected but noteworthy)"
                    Identity = $Identity
                    Scope = $Scope
                    MatchedSID = $sid
                }
            }
            return 'Attention'
        }

        # ===== PHASE 2: Recursive Group Membership Check (Cached) =====
        # If identity is not directly expected, check if it's a MEMBER of an expected group.
        # This reduces noise: e.g., a Domain Admin user with explicit ACE is not a new finding.
        # Returns "Attention" (not "Expected") because the explicit ACE is technically unnecessary.
        if ($Script:LdapConnection -and $sid) {
            # Get all group memberships for this identity (cached after first lookup)
            $identityGroupMemberships = Get-RecursiveGroupMembership -IdentitySID $sid

            if ($identityGroupMemberships -and $identityGroupMemberships.Count -gt 0) {
                $domainSID = $null
                if ($Script:LDAPContext -and $Script:LDAPContext.DomainSID) {
                    $domainSID = $Script:LDAPContext.DomainSID
                }

                # Build list of expected group SIDs for this scope
                $expectedGroupSIDs = @()

                # Add static expected SIDs (only groups, not SYSTEM etc.)
                if ($scopeDef.ExpectedSIDs) {
                    # BUILTIN\Administrators is a group
                    if ('S-1-5-32-544' -in $scopeDef.ExpectedSIDs) {
                        $expectedGroupSIDs += 'S-1-5-32-544'
                    }
                    # Account Operators, Server Operators, etc.
                    foreach ($expSID in $scopeDef.ExpectedSIDs) {
                        if ($expSID -match '^S-1-5-32-') {
                            $expectedGroupSIDs += $expSID
                        }
                    }
                }

                # Add domain-relative expected groups
                if ($domainSID -and $scopeDef.ExpectedRIDSuffixes) {
                    foreach ($suffix in $scopeDef.ExpectedRIDSuffixes) {
                        $expectedGroupSIDs += "$domainSID$suffix"
                    }
                }

                # Check if identity is member of any expected group
                foreach ($expectedGroupSID in $expectedGroupSIDs) {
                    if ($expectedGroupSID -in $identityGroupMemberships) {
                        # Resolve group name for display
                        $groupName = ConvertFrom-SID -SID $expectedGroupSID
                        if (-not $groupName) { $groupName = $expectedGroupSID }

                        # Identity is member of an expected group → Attention (not Finding), because the explicit ACE is redundant but not a new attack vector
                        Write-Log "[Test-IsExpectedInScope] Identity $sid is member of expected group $groupName"
                        if ($ReturnDetails) {
                            return [PSCustomObject]@{
                                Severity = 'Attention'
                                Reason = "Member of expected group '$groupName' in scope '$Scope' (explicit ACE is redundant)"
                                Identity = $Identity
                                Scope = $Scope
                                ResolvedSID = $sid
                                MemberOfExpectedGroup = $groupName
                                MemberOfExpectedGroupSID = $expectedGroupSID
                            }
                        }
                        return 'Attention'
                    }
                }

            }
        }

        # ===== PHASE 3: Exchange Service Group Check =====
        # Before returning "Finding", check if this is an Exchange service group.
        # Exchange groups have by-design permissions that cannot be removed without breaking Exchange.
        # They should be shown as "Attention" (informational) rather than "Finding" (actionable).
        if ($Script:LdapConnection) {
            $exchangeCheck = Test-IsExchangeServiceGroup -Identity $Identity
            if ($exchangeCheck.IsExchangeService) {
                Write-Log "[Test-IsExpectedInScope] Exchange service group detected: $($exchangeCheck.DistinguishedName)"
                if ($ReturnDetails) {
                    return [PSCustomObject]@{
                        Severity = 'Attention'
                        Reason = "Exchange service group in scope '$Scope' (by-design permissions, cannot be removed)"
                        Identity = $Identity
                        Scope = $Scope
                        ResolvedSID = $sid
                        ResolvedName = $name
                        IsExchangeService = $true
                    }
                }
                return 'Attention'
            }
        }

        # ===== Not Expected (neither directly nor via group membership) =====
        if ($ReturnDetails) {
            return [PSCustomObject]@{
                Severity = 'Finding'
                Reason = "Identity not expected in scope '$Scope'"
                Identity = $Identity
                Scope = $Scope
                ResolvedSID = $sid
                ResolvedName = $name
            }
        }
        return 'Finding'
    }
}

