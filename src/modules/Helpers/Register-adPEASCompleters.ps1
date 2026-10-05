<#
.SYNOPSIS
    Registers tab-completion for adPEAS Get-Domain*, Set-Domain* and Request-ADCSCertificate functions.

.DESCRIPTION
    Provides tab-completion for two families of parameter, each one named function plus one
    registration table:

    IDENTITY (Get-adPEASIdentityCompletion / Register-adPEASIdentityCompleters)
    - Identity in Get-DomainUser, Get-DomainComputer, Get-DomainGroup, Get-DomainGPO
    - Identity in Set-DomainUser, Set-DomainComputer, Set-DomainGroup, Set-DomainGPO
    - Identity in Set-DomainObject and Move-DomainObject (class-agnostic: every principal cache)
    - TemplateName in Request-ADCSCertificate

    CONTAINER DN (Get-adPEASContainerCompletion / Register-adPEASContainerCompleters)
    - SearchBase in Get-Domain*, Set-DomainObject, Invoke-LDAPSearch, Get-CertificateTemplate
    - OrganizationalUnit in New-DomainUser, New-DomainComputer, New-DomainGroup
    - DestinationOU in Move-DomainObject

    Both families are registered from a table rather than one Register-ArgumentCompleter block
    per command. Twenty-three registrations as hand-written blocks would be twenty-three copies
    of two bodies, and they had already drifted: the per-command blocks quoted on a character
    class that omitted the comma, and matched with -like, which treats a bracketed GPO name as
    a wildcard character class.

    Tab-completion allows users to quickly find and select AD objects by typing the first few characters and pressing TAB.

    LAZY LOADING: The cache is built automatically on first TAB press for each object type.
    - No upfront performance cost at Connect-adPEAS time
    - Cache is built per object type only when needed (e.g., first TAB on Get-DomainUser builds Users cache only)
    - If LDAP connection exists and cache is empty, pressing TAB triggers automatic cache build
    - Failed cache build attempts are tracked to prevent repeated failed queries

    MANUAL CACHE BUILD: You can also pre-build the cache explicitly:
    - Connect-adPEAS -BuildCompletionCache (builds all object types at connect time)
    - Build-CompletionCache -ObjectTypes @('Users', 'Groups') (builds specific types)

    The cache is stored in $Script:CompletionCache with the following structure:
    @{
        Users      = @("sAMAccountName1", "sAMAccountName2", ...)
        Computers  = @("sAMAccountName1", "sAMAccountName2", ...)
        Groups     = @("sAMAccountName1", "sAMAccountName2", ...)
        GPOs       = @("displayName1", "displayName2", ...)
        Templates  = @("templateName1", "templateName2", ...)
        Containers = @("OU=...,DC=...", "CN=Users,DC=...", ...)
    }

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

# Initialize completion cache if not exists
if (-not $Script:CompletionCache) {
    $Script:CompletionCache = @{
        Users      = @()
        Computers  = @()
        Groups     = @()
        GPOs       = @()
        Templates  = @()
        Containers = @()
    }
}

# Track which object types have been attempted for lazy loading (prevents repeated failed attempts)
if (-not $Script:CompletionCacheAttempted) {
    $Script:CompletionCacheAttempted = @{
        Users      = $false
        Computers  = $false
        Groups     = $false
        GPOs       = $false
        Templates  = $false
        Containers = $false
    }
}

<#
.SYNOPSIS
    Builds the tab-completion cache by querying AD for object names.

.DESCRIPTION
    Build-CompletionCache queries Active Directory to populate the completion cache with sAMAccountNames (for Users, Computers, Groups) and displayNames (for GPOs).
    This function is called by Connect-adPEAS when -BuildCompletionCache is specified.

.PARAMETER ObjectTypes
    Array of object types to cache. Valid values: Users, Computers, Groups, GPOs, Templates,
    Containers, All.
    Default: All

.EXAMPLE
    Build-CompletionCache
    Builds cache for all object types.

.EXAMPLE
    Build-CompletionCache -ObjectTypes @('Users', 'Groups')
    Builds cache only for Users and Groups.
#>
function Build-CompletionCache {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('Users', 'Computers', 'Groups', 'GPOs', 'Templates', 'Containers', 'All')]
        [string[]]$ObjectTypes = @('All')
    )

    process {
        # Check if we have an active connection
        # UNIFIED: Check for LdapConnection (works for both LDAP and LDAPS)
        if (-not $Script:LdapConnection) {
            Write-Warning "[Build-CompletionCache] No active LDAP connection. Use Connect-adPEAS first."
            return
        }

        Write-Log "[Build-CompletionCache] Building tab-completion cache..."

        $buildAll = $ObjectTypes -contains 'All'

        # Cache Users
        if ($buildAll -or $ObjectTypes -contains 'Users') {
            Write-Log "[Build-CompletionCache] Caching user sAMAccountNames..."
            try {
                $Script:CompletionCache.Users = @(
                    Get-DomainUser -Properties @('sAMAccountName') |
                    Where-Object { $_.sAMAccountName } |
                    Select-Object -ExpandProperty sAMAccountName |
                    Sort-Object
                )
                Write-Log "[Build-CompletionCache] Cached $($Script:CompletionCache.Users.Count) users"
            }
            catch {
                Write-Log "[Build-CompletionCache] Error caching users: $_"
                $Script:CompletionCache.Users = @()
            }
        }

        # Cache Computers
        if ($buildAll -or $ObjectTypes -contains 'Computers') {
            Write-Log "[Build-CompletionCache] Caching computer sAMAccountNames..."
            try {
                $Script:CompletionCache.Computers = @(
                    Get-DomainComputer -Properties @('sAMAccountName') |
                    Where-Object { $_.sAMAccountName } |
                    Select-Object -ExpandProperty sAMAccountName |
                    ForEach-Object { $_ -replace '\$$', '' } |  # Remove trailing $ from computer accounts
                    Sort-Object
                )
                Write-Log "[Build-CompletionCache] Cached $($Script:CompletionCache.Computers.Count) computers"
            }
            catch {
                Write-Log "[Build-CompletionCache] Error caching computers: $_"
                $Script:CompletionCache.Computers = @()
            }
        }

        # Cache Groups
        if ($buildAll -or $ObjectTypes -contains 'Groups') {
            Write-Log "[Build-CompletionCache] Caching group sAMAccountNames..."
            try {
                $Script:CompletionCache.Groups = @(
                    Get-DomainGroup -Properties @('sAMAccountName') |
                    Where-Object { $_.sAMAccountName } |
                    Select-Object -ExpandProperty sAMAccountName |
                    Sort-Object
                )
                Write-Log "[Build-CompletionCache] Cached $($Script:CompletionCache.Groups.Count) groups"
            }
            catch {
                Write-Log "[Build-CompletionCache] Error caching groups: $_"
                $Script:CompletionCache.Groups = @()
            }
        }

        # Cache GPOs
        if ($buildAll -or $ObjectTypes -contains 'GPOs') {
            Write-Log "[Build-CompletionCache] Caching GPO displayNames..."
            try {
                $Script:CompletionCache.GPOs = @(
                    Get-DomainGPO -Properties @('displayName') |
                    Where-Object { $_.displayName } |
                    Select-Object -ExpandProperty displayName |
                    Sort-Object
                )
                Write-Log "[Build-CompletionCache] Cached $($Script:CompletionCache.GPOs.Count) GPOs"
            }
            catch {
                Write-Log "[Build-CompletionCache] Error caching GPOs: $_"
                $Script:CompletionCache.GPOs = @()
            }
        }

        # Cache Certificate Templates (from CA Enrollment Services)
        if ($buildAll -or $ObjectTypes -contains 'Templates') {
            Write-Log "[Build-CompletionCache] Caching certificate template names from CAs..."
            try {
                $Script:CompletionCache.Templates = @(
                    Get-CertificateAuthority |
                    Where-Object { -not $_._QueryError -and $_.CertificateTemplates } |
                    ForEach-Object { $_.CertificateTemplates } |
                    Sort-Object -Unique
                )
                $Script:CompletionCacheAttempted.Templates = $true
                Write-Log "[Build-CompletionCache] Cached $($Script:CompletionCache.Templates.Count) certificate templates"
            }
            catch {
                Write-Log "[Build-CompletionCache] Error caching templates: $_"
                $Script:CompletionCache.Templates = @()
                $Script:CompletionCacheAttempted.Templates = $true
            }
        }

        # Cache OU and container DNs (for -SearchBase / -OrganizationalUnit / -DestinationOU)
        if ($buildAll -or $ObjectTypes -contains 'Containers') {
            Write-Log "[Build-CompletionCache] Caching organizational unit and container DNs..."
            try {
                $containerDNs = New-Object System.Collections.Generic.List[string]

                # The domain root is a legitimate value for all three parameter kinds.
                if ($Script:LDAPContext -and $Script:LDAPContext.DomainDN) {
                    $containerDNs.Add([string]$Script:LDAPContext.DomainDN)
                }

                foreach ($ou in @(Get-DomainObject -LDAPFilter '(objectClass=organizationalUnit)' -Properties @('distinguishedName'))) {
                    if ($ou.distinguishedName) { $containerDNs.Add([string]$ou.distinguishedName) }
                }

                # Containers are restricted to one level below the domain root. That covers
                # CN=Users, CN=Computers and CN=Managed Service Accounts - real targets for
                # New-Domain* - without dragging in the hundreds of objects under CN=System.
                # Done with -Scope rather than a Where-Object so the DC does the filtering.
                foreach ($container in @(Get-DomainObject -LDAPFilter '(objectClass=container)' -Scope OneLevel -Properties @('distinguishedName'))) {
                    if ($container.distinguishedName) { $containerDNs.Add([string]$container.distinguishedName) }
                }

                $Script:CompletionCache.Containers = @($containerDNs | Sort-Object -Unique)
                $Script:CompletionCacheAttempted.Containers = $true
                Write-Log "[Build-CompletionCache] Cached $($Script:CompletionCache.Containers.Count) containers"
            }
            catch {
                Write-Log "[Build-CompletionCache] Error caching containers: $_"
                $Script:CompletionCache.Containers = @()
                $Script:CompletionCacheAttempted.Containers = $true
            }
        }

        # Summary
        $totalCached = $Script:CompletionCache.Users.Count +
                       $Script:CompletionCache.Computers.Count +
                       $Script:CompletionCache.Groups.Count +
                       $Script:CompletionCache.GPOs.Count +
                       $Script:CompletionCache.Templates.Count +
                       $Script:CompletionCache.Containers.Count

        Write-Log "[Build-CompletionCache] Cache built: $($Script:CompletionCache.Users.Count) users, $($Script:CompletionCache.Computers.Count) computers, $($Script:CompletionCache.Groups.Count) groups, $($Script:CompletionCache.GPOs.Count) GPOs, $($Script:CompletionCache.Templates.Count) templates, $($Script:CompletionCache.Containers.Count) containers (Total: $totalCached)"
    }
}

<#
.SYNOPSIS
    Clears the tab-completion cache.

.DESCRIPTION
    Clear-CompletionCache removes all cached entries from the completion cache.
    Useful when switching domains or when the cache becomes stale.

.EXAMPLE
    Clear-CompletionCache
    Clears all cached completion data.
#>
function Clear-CompletionCache {
    [CmdletBinding()]
    param()

    process {
        $Script:CompletionCache = @{
            Users      = @()
            Computers  = @()
            Groups     = @()
            GPOs       = @()
            Templates  = @()
            Containers = @()
        }
        # Reset lazy loading flags so cache can be rebuilt
        $Script:CompletionCacheAttempted = @{
            Users      = $false
            Computers  = $false
            Groups     = $false
            GPOs       = $false
            Templates  = $false
            Containers = $false
        }
        Write-Log "[Clear-CompletionCache] Completion cache cleared"
    }
}

<#
.SYNOPSIS
    Gets statistics about the current completion cache.

.DESCRIPTION
    Get-CompletionCacheStats returns information about the current state of the completion cache, including counts for each object type.

.EXAMPLE
    Get-CompletionCacheStats
    Returns cache statistics.
#>
function Get-CompletionCacheStats {
    [CmdletBinding()]
    param()

    process {
        [PSCustomObject]@{
            Users      = $Script:CompletionCache.Users.Count
            Computers  = $Script:CompletionCache.Computers.Count
            Groups     = $Script:CompletionCache.Groups.Count
            GPOs       = $Script:CompletionCache.GPOs.Count
            Templates  = $Script:CompletionCache.Templates.Count
            Containers = $Script:CompletionCache.Containers.Count
            Total      = ($Script:CompletionCache.Users.Count +
                        $Script:CompletionCache.Computers.Count +
                        $Script:CompletionCache.Groups.Count +
                        $Script:CompletionCache.GPOs.Count +
                        $Script:CompletionCache.Templates.Count +
                        $Script:CompletionCache.Containers.Count)
            CacheExists = ($Script:CompletionCache.Users.Count -gt 0 -or
                          $Script:CompletionCache.Computers.Count -gt 0 -or
                          $Script:CompletionCache.Groups.Count -gt 0 -or
                          $Script:CompletionCache.GPOs.Count -gt 0 -or
                          $Script:CompletionCache.Templates.Count -gt 0 -or
                          $Script:CompletionCache.Containers.Count -gt 0)
        }
    }
}

# =====================================================================
# IMPORTANT: ArgumentCompleter ScriptBlocks run in a DIFFERENT scope
# than the adPEAS module. We need to access the module's script variables
# via Get-Variable -Scope Script, but since the scriptblock executes in
# the caller's scope, we use a closure to capture the current module scope.
# =====================================================================

# Helper function to get adPEAS module variables (called from within the module scope)
function Get-adPEASCompletionState {
    [CmdletBinding()]
    param([string]$ObjectType)

    return @{
        HasConnection = ($null -ne $Script:LdapConnection)
        Cache = $Script:CompletionCache
        CacheAttempted = $Script:CompletionCacheAttempted

        # Naming context roots, for -SearchBase completion. These come from the RootDSE read
        # at bind time, so offering them costs no query - and they are the one thing
        # -SearchBase accepts that is not an OU or container in the domain partition.
        PartitionDNs = @(
            @(
                $Script:LDAPContext.DomainDN
                $Script:LDAPContext.ConfigurationDN
                $Script:LDAPContext.SchemaNamingContext
            ) | Where-Object { $_ }
        )
    }
}

# =====================================================================
# IDENTITY COMPLETER
# Provides tab-completion for every -Identity parameter, plus
# Request-ADCSCertificate -TemplateName. One scriptblock per
# registration, built from a table with a captured object-type list.
# =====================================================================

<#
.SYNOPSIS
    Produces the name completions for an -Identity (or -TemplateName) parameter.

.DESCRIPTION
    The body of the identity completer. Replaces ten near-identical
    Register-ArgumentCompleter blocks that differed only in which cache they read and what
    their tooltip said.

    Named rather than inline for the same two reasons as Get-adPEASContainerCompletion: a
    registered scriptblock cannot be retrieved and called, so inline logic is untestable, and
    a named function resolves in the module scope.

    Builds each requested cache lazily on first use.

.PARAMETER WordToComplete
    The partial value the user has typed. An empty string returns the whole list.

.PARAMETER ObjectTypes
    Which caches to offer. Several may be given, which is what the class-agnostic
    Set-DomainObject and Move-DomainObject need.

.EXAMPLE
    Get-adPEASIdentityCompletion -WordToComplete 'jd' -ObjectTypes @('Users')
    Returns the users whose sAMAccountName starts with 'jd'.

.EXAMPLE
    Get-adPEASIdentityCompletion -WordToComplete '' -ObjectTypes @('Users', 'Computers', 'Groups')
    The class-agnostic list, as Set-DomainObject and Move-DomainObject offer it.

.OUTPUTS
    [System.Management.Automation.CompletionResult] objects, at most 50.
#>
function Get-adPEASIdentityCompletion {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.CompletionResult])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$WordToComplete = '',

        [Parameter(Mandatory = $true)]
        [ValidateSet('Users', 'Computers', 'Groups', 'GPOs', 'Templates')]
        [string[]]$ObjectTypes
    )

    # Tooltip label per cache, singular - what the per-command blocks hard-coded.
    $labels = @{
        Users     = 'User'
        Computers = 'Computer'
        Groups    = 'Group'
        GPOs      = 'GPO'
        Templates = 'Template'
    }

    # Get state from the adPEAS module scope
    $state = Get-adPEASCompletionState -ObjectType 'Identity'

    # Lazy loading: build only the caches this registration actually reads, and only once.
    # Both guards short-circuit on a null table, which is the state Clear-SessionState leaves.
    if ($state.HasConnection) {
        $pending = New-Object System.Collections.Generic.List[string]
        foreach ($objectType in $ObjectTypes) {
            $isEmpty = (-not $state.Cache) -or (@($state.Cache[$objectType]).Count -eq 0)
            $isUntried = (-not $state.CacheAttempted) -or (-not $state.CacheAttempted[$objectType])
            if ($isEmpty -and $isUntried) { $pending.Add($objectType) }
        }
        if ($pending.Count -gt 0) {
            Build-CompletionCache -ObjectTypes @($pending)
            # Refresh state after building
            $state = Get-adPEASCompletionState -ObjectType 'Identity'
        }
    }

    $word = $WordToComplete
    if ($null -eq $word) { $word = '' }

    # StartsWith, NOT -like. The prefix semantics are unchanged from the blocks this replaces,
    # but -like reads [ ] * and ? as wildcard syntax, and a GPO displayName is free text: a
    # policy named "[Baseline] Server Hardening" turned '-like "[Baseline]*"' into a CHARACTER
    # CLASS, matching every name that starts with one of B a s e l i n. A half-typed "[Base"
    # threw WildcardPatternException outright, and PowerShell swallows an exception raised
    # inside a completer - so the symptom was silence, with nothing to explain it.
    $comparison = [System.StringComparison]::OrdinalIgnoreCase
    $matching = New-Object System.Collections.Generic.List[object]

    foreach ($objectType in $ObjectTypes) {
        if (-not $state.Cache) { break }
        foreach ($name in @($state.Cache[$objectType])) {
            if ([string]::IsNullOrEmpty($name)) { continue }
            if (-not ([string]$name).StartsWith($word, $comparison)) { continue }
            $matching.Add([PSCustomObject]@{ Name = [string]$name; Label = $labels[$objectType] })
        }
    }

    # Sorted across all requested types before the cap, not per type. Concatenating the caches
    # and then taking the first 50 meant a domain with 50 or more users never offered a single
    # computer or group on Set-DomainObject.
    foreach ($entry in @($matching | Sort-Object -Property Name -Unique | Select-Object -First 50)) {
        $name = [string]$entry.Name

        # Whitelist, not blacklist - the principle this file's header states. A bareword is safe
        # only as letters, digits, underscore, dot or hyphen, and not leading with a hyphen,
        # which PowerShell would read as a parameter name. Everything else is single-quoted.
        #
        # The blacklist this replaces, [\s'"$`], missed the comma: a GPO named "Baseline,Tier0"
        # has no whitespace, so it went out unquoted and bound as a two-element array instead of
        # a name. Single quotes rather than double, because they also keep $ and ` literal.
        $completionText = $name
        if ($name -notmatch '^[A-Za-z0-9_.][A-Za-z0-9_.-]*$') {
            $completionText = "'" + ($name -replace "'", "''") + "'"
        }

        [System.Management.Automation.CompletionResult]::new(
            $completionText,
            $name,
            'ParameterValue',
            "$($entry.Label): $name"
        )
    }
}

<#
.SYNOPSIS
    The identity completer registration table: which caches each parameter offers.

.DESCRIPTION
    Data, as its own function, so the completer can look up its object types at completion time
    and a test can assert the mapping without reaching into a registered scriptblock.

.OUTPUTS
    [hashtable[]] with Command, Parameter and ObjectTypes.
#>
function Get-adPEASIdentityCompleterRegistrations {
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param()

    return @(
        @{ Command = 'Get-DomainUser';          Parameter = 'Identity';     ObjectTypes = @('Users') }
        @{ Command = 'Get-DomainComputer';      Parameter = 'Identity';     ObjectTypes = @('Computers') }
        @{ Command = 'Get-DomainGroup';         Parameter = 'Identity';     ObjectTypes = @('Groups') }
        @{ Command = 'Get-DomainGPO';           Parameter = 'Identity';     ObjectTypes = @('GPOs') }
        @{ Command = 'Set-DomainUser';          Parameter = 'Identity';     ObjectTypes = @('Users') }
        @{ Command = 'Set-DomainComputer';      Parameter = 'Identity';     ObjectTypes = @('Computers') }
        @{ Command = 'Set-DomainGroup';         Parameter = 'Identity';     ObjectTypes = @('Groups') }
        @{ Command = 'Set-DomainGPO';           Parameter = 'Identity';     ObjectTypes = @('GPOs') }
        # Class-agnostic: both accept any object, so both offer every principal cache.
        @{ Command = 'Set-DomainObject';        Parameter = 'Identity';     ObjectTypes = @('Users', 'Computers', 'Groups') }
        @{ Command = 'Move-DomainObject';       Parameter = 'Identity';     ObjectTypes = @('Users', 'Computers', 'Groups') }
        @{ Command = 'Request-ADCSCertificate'; Parameter = 'TemplateName'; ObjectTypes = @('Templates') }
    )
}

<#
.SYNOPSIS
    Resolves which caches a given command and parameter should offer.

.DESCRIPTION
    Looked up at completion time from $commandName and $parameterName, which PowerShell hands
    every completer. This is what lets ONE shared scriptblock serve all eleven registrations.

    Deliberately NOT a closure per registration. GetNewClosure would capture the object types
    correctly, but it also rebinds the scriptblock to a fresh scope that does not chain to the
    one it was defined in - so Get-adPEASIdentityCompletion stops resolving wherever adPEAS was
    not loaded into the global scope, and the completer dies with CommandNotFoundException.
    PowerShell swallows a completer's exception, so the symptom would be silence.

.PARAMETER CommandName
    The command being completed, as PowerShell passes it to the completer.

.PARAMETER ParameterName
    The parameter being completed.

.OUTPUTS
    [string[]] cache names, empty if the pair is not registered.
#>
function Get-adPEASIdentityCompleterTypes {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$CommandName,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$ParameterName
    )

    foreach ($registration in Get-adPEASIdentityCompleterRegistrations) {
        if ($registration.Command -eq $CommandName -and $registration.Parameter -eq $ParameterName) {
            # Returned unrolled, NOT comma-protected. ',$array' hands the array back as a single
            # object, so the caller's @(...) wraps it into a one-element array holding an array -
            # and ObjectTypes then receives the string 'Users Computers Groups', which fails its
            # ValidateSet. A completer's exception is swallowed by PowerShell, so that fails as
            # silence. Callers wrap in @(), which rebuilds a one-element list correctly.
            return @($registration.ObjectTypes)
        }
    }

    return @()
}

<#
.SYNOPSIS
    Registers the identity completer for every parameter that takes an object name.

.DESCRIPTION
    Eleven registrations sharing ONE plain scriptblock, which resolves its object types per
    call from the command and parameter name. Eleven hand-written blocks would be eleven copies
    of the completer body, and eleven closures would break command resolution - see
    Get-adPEASIdentityCompleterTypes.

.EXAMPLE
    Register-adPEASIdentityCompleters
    Called once at module load, immediately below.
#>
function Register-adPEASIdentityCompleters {
    [CmdletBinding()]
    param()

    $identityCompleter = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

        $objectTypes = @(Get-adPEASIdentityCompleterTypes -CommandName $commandName -ParameterName $parameterName)
        if ($objectTypes.Count -eq 0) { return }

        Get-adPEASIdentityCompletion -WordToComplete $wordToComplete -ObjectTypes $objectTypes
    }

    $registrations = @(Get-adPEASIdentityCompleterRegistrations)
    foreach ($registration in $registrations) {
        Register-ArgumentCompleter -CommandName $registration.Command `
            -ParameterName $registration.Parameter -ScriptBlock $identityCompleter
    }

    Write-Log "[Register-adPEASIdentityCompleters] Registered identity completion for $($registrations.Count) parameter(s)"
}

Register-adPEASIdentityCompleters

# =====================================================================
# CONTAINER DN COMPLETER
# Provides tab-completion for every parameter that takes an OU or
# container distinguishedName: -SearchBase, -OrganizationalUnit and
# -DestinationOU.
# =====================================================================

<#
.SYNOPSIS
    Resolves the RFC 4514 escapes in one RDN value.

.DESCRIPTION
    A DN escapes the characters that would otherwise be syntax - a comma, a plus, a leading
    space - either as a backslash pair or as a backslash and two hex digits. The completer
    compares what the user typed against an RDN value, and the user types the name as it
    reads in the console, not as the directory encodes it: 'Tier 0' rather than 'Tier\ 0'.

    One pass, both forms. Unescaping in two passes would turn '\5C' into a backslash that
    the second pass then reads as an escape of whatever followed it.

.PARAMETER Value
    The raw RDN value.

.OUTPUTS
    [string]
#>
function Expand-adPEASDNEscape {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Value = ''
    )

    if ([string]::IsNullOrEmpty($Value)) { return '' }
    if ($Value.IndexOf('\') -lt 0) { return $Value }

    return [regex]::Replace($Value, '\\([0-9A-Fa-f]{2}|.)', {
        param($match)
        $token = $match.Groups[1].Value
        if ($token.Length -eq 2) { [string][char][Convert]::ToInt32($token, 16) } else { $token }
    })
}

<#
.SYNOPSIS
    Splits a DN into the value of its left-most RDN and the number of RDNs it has.

.DESCRIPTION
    The two facts the container completer ranks on: what the container is called, and how
    deep it sits.

    Parsed by walking the string rather than with Split(','), because a comma inside an RDN
    value is legal when escaped. 'CN=Doe\, Jane (Contractor),OU=Sales,DC=contoso,DC=com'
    would otherwise yield a leaf of 'CN=Doe\' - a value that matches nothing a user would
    type - and a depth one greater than the container actually has, which moves it down the
    list for a reason that does not exist. The same class of defect as interpolating an
    unescaped DN into an LDAP filter.

    Not handled: the legacy quoted form, "CN=some, name". Active Directory does not emit it,
    and half-reading it would be worse than reading it as the literal text it appears to be.

.PARAMETER DistinguishedName
    The DN to parse.

.OUTPUTS
    [PSCustomObject] with LeafValue (escapes resolved) and Depth (RDN count, so
    DC=contoso,DC=com is 2 and an OU directly below it is 3).
#>
function Get-adPEASDNLeaf {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$DistinguishedName = ''
    )

    if ([string]::IsNullOrEmpty($DistinguishedName)) {
        return [PSCustomObject]@{ LeafValue = ''; Depth = 0 }
    }

    $depth = 1
    $firstComma = -1
    $index = 0
    while ($index -lt $DistinguishedName.Length) {
        $char = $DistinguishedName[$index]
        if ($char -eq '\') { $index += 2; continue }
        if ($char -eq ',') {
            $depth++
            if ($firstComma -lt 0) { $firstComma = $index }
        }
        $index++
    }

    $leafRDN = if ($firstComma -ge 0) {
        $DistinguishedName.Substring(0, $firstComma)
    } else {
        $DistinguishedName
    }

    # The value is what follows the first unescaped '='. An RDN carrying none is malformed;
    # it is kept whole rather than dropped, so a hand-built cache entry still ranks somewhere
    # instead of vanishing from the list.
    $leafValue = $leafRDN
    $cursor = 0
    while ($cursor -lt $leafRDN.Length) {
        if ($leafRDN[$cursor] -eq '\') { $cursor += 2; continue }
        if ($leafRDN[$cursor] -eq '=') {
            $leafValue = $leafRDN.Substring($cursor + 1)
            break
        }
        $cursor++
    }

    return [PSCustomObject]@{
        LeafValue = (Expand-adPEASDNEscape -Value $leafValue)
        Depth     = $depth
    }
}

<#
.SYNOPSIS
    Produces the container-DN completions for a given word and parameter name.

.DESCRIPTION
    The body of the container completer, as a named function rather than inline in the
    registered scriptblock. Two reasons: a registered scriptblock cannot be retrieved and
    called, so inline logic is untestable; and a named function resolves in the module scope,
    which is the same reason Get-adPEASCompletionState exists.

    Builds the Containers cache lazily on first use, exactly like the Identity completers.

.PARAMETER WordToComplete
    The partial value the user has typed. An empty string returns the whole list.

.PARAMETER ParameterName
    The parameter being completed. 'SearchBase' additionally offers the Configuration and
    Schema naming contexts; the other parameters must not, because those partitions cannot
    hold a user, computer or group.

.EXAMPLE
    Get-adPEASContainerCompletion -WordToComplete 'Sales' -ParameterName 'DestinationOU'
    Returns the OUs whose DN contains 'Sales'.

.OUTPUTS
    [System.Management.Automation.CompletionResult] objects, at most 50.
#>
function Get-adPEASContainerCompletion {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.CompletionResult])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$WordToComplete = '',

        [Parameter(Mandatory = $false)]
        [string]$ParameterName
    )

    # Get state from the adPEAS module scope
    $state = Get-adPEASCompletionState -ObjectType 'Containers'

    # Lazy loading: Build cache on first TAB press if connection exists and not yet attempted
    if ($state.HasConnection -and
        (-not $state.Cache -or $state.Cache.Containers.Count -eq 0) -and
        (-not $state.CacheAttempted -or -not $state.CacheAttempted.Containers)) {
        # Build cache for Containers only (lazy, on-demand)
        Build-CompletionCache -ObjectTypes @('Containers')
        # Refresh state after building
        $state = Get-adPEASCompletionState -ObjectType 'Containers'
    }

    $candidates = New-Object System.Collections.Generic.List[string]
    if ($state.Cache -and $state.Cache.Containers) {
        foreach ($containerDN in $state.Cache.Containers) {
            $candidates.Add([string]$containerDN)
        }
    }

    # -SearchBase is the only one of these parameters that may point at another partition.
    # Offering the Configuration and Schema roots for -OrganizationalUnit or -DestinationOU
    # would suggest a target that cannot hold the object being created or moved.
    if ($ParameterName -eq 'SearchBase' -and $state.PartitionDNs) {
        foreach ($partitionDN in $state.PartitionDNs) {
            $candidates.Add([string]$partitionDN)
        }
    }

    $word = $WordToComplete
    if ($null -eq $word) { $word = '' }

    # Matched with IndexOf/StartsWith, NOT with -like. -like reads [ ] * and ? as wildcard
    # syntax, and an OU named "[Tier 0] Servers" is an ordinary way to name one:
    #   - '[Tier 0]' as a -like pattern is a CHARACTER CLASS, so it matches every DN that
    #     contains a T, i, e, r, space or 0 - which is all of them.
    #   - a half-typed 'OU=[' makes -like throw WildcardPatternException, and PowerShell
    #     swallows an exception thrown inside a completer, so the user would get no completions
    #     at all and no indication why.
    # Ordinal comparison also matches how AD itself compares DNs.
    $comparison = [System.StringComparison]::OrdinalIgnoreCase

    # Substring match, not prefix: a DN starts with 'OU=' or 'CN=', so prefix-only completion
    # would require typing the DN from the left - but what the user knows is the OU name.
    #
    # Matched against the container's own name with its escapes resolved, and against the raw
    # DN as a fallback. The name is the surface a user types at, and comparing only the raw DN
    # missed every container whose name carries an escape: typing 'Doe, Jane' never found
    # 'CN=Doe\, Jane (Contractor),...', because the stored form has a backslash in it that
    # nobody types.
    #
    # Which makes the ORDER carry the weight, because the filter is deliberately generous.
    # Ranked, then sorted, and the ranking is measured on the left-most RDN - the container's
    # own name - because that is what a user types. Sorting the matches alphabetically, as
    # this did before, let a container whose ANCESTOR matched outrank the one that actually
    # bears the name: for 'computers', 'OU=Archiv,OU=Computers,DC=...' sorted ahead of
    # 'OU=Computers,DC=...' on nothing but the letter A. It usually looked right, which was
    # luck of the alphabet rather than design.
    #
    # It also decides what survives the 50-item cap below. Without a relevance order, the
    # container someone is looking for can fall past the cap in a large domain and simply
    # not be offered, with nothing to say it exists.
    #
    #   1  the name is exactly the word
    #   2  the name starts with it
    #   3  the name contains it
    #   4  only an ancestor matched
    #
    # Relevance outranks depth, never the other way round - otherwise a shallow ancestor
    # match climbs back above a deep exact one, which is the defect being fixed.
    #
    # A word that opens with an attribute type and an equals sign is not a name, it is a path
    # someone is typing out, so it keeps the older DN-prefix-then-substring order. That is an
    # explicitly stated intent and reinterpreting it as a name would match nothing.
    #
    # Recognised by that shape and not by the mere presence of ',' or '=', which was the first
    # attempt and read 'Doe, Jane' as a path - a name may legitimately contain either
    # character, as the escaped-comma case right below proves. A word like 'Tier=0' does look
    # like an assignment and is read as one, so the fragment branch keeps a leaf fallback and
    # no container ends up unreachable either way.
    $wordIsDNFragment = ($word -match '^[A-Za-z][A-Za-z0-9-]*=')

    # One pass: a candidate is kept and ranked together, because the tier a candidate lands
    # in is the same question as whether it matches at all. Tier $null means no match.
    $ranked = New-Object System.Collections.Generic.List[object]
    foreach ($candidate in @($candidates | Sort-Object -Unique)) {
        $parts = Get-adPEASDNLeaf -DistinguishedName $candidate
        $leaf  = [string]$parts.LeafValue

        $tier = $null
        if ($word.Length -eq 0) {
            $tier = 1
        } elseif ($wordIsDNFragment) {
            if ($candidate.StartsWith($word, $comparison))         { $tier = 1 }
            elseif ($candidate.IndexOf($word, $comparison) -ge 0)  { $tier = 2 }
            elseif ($leaf.IndexOf($word, $comparison) -ge 0)       { $tier = 3 }
        } elseif ($leaf.Equals($word, $comparison)) {
            $tier = 1
        } elseif ($leaf.StartsWith($word, $comparison)) {
            $tier = 2
        } elseif ($leaf.IndexOf($word, $comparison) -ge 0) {
            $tier = 3
        } elseif ($candidate.IndexOf($word, $comparison) -ge 0) {
            $tier = 4
        }

        if ($null -eq $tier) { continue }

        $ranked.Add([PSCustomObject]@{
            DN    = $candidate
            Tier  = $tier
            Depth = $parts.Depth
        })
    }

    # Shallower first within a tier. A SearchBase is a scope, and the shallower container is
    # the broader one: asked for 'computers', a reader means the main OU more often than a
    # like-named one parked under an archive or a test structure. At equal depth the DN
    # itself decides, which sorts on the parent from the leaf upwards and so keeps siblings
    # together.
    $ordered = New-Object System.Collections.Generic.List[string]
    foreach ($entry in @($ranked | Sort-Object -Property Tier, Depth, DN)) {
        $ordered.Add([string]$entry.DN)
    }

    foreach ($containerDN in @($ordered | Select-Object -First 50)) {
        # Always quoted, unlike the Identity completers above: a DN contains commas, which
        # PowerShell parses as an array separator in argument position, so an unquoted DN never
        # binds to a [string] parameter. Single quotes because a DN also carries RFC 4514
        # backslash escapes and may contain '$' - both are literal inside single quotes, and
        # only an embedded single quote needs doubling.
        $completionText = "'" + ($containerDN -replace "'", "''") + "'"
        [System.Management.Automation.CompletionResult]::new(
            $completionText,
            $containerDN,
            'ParameterValue',
            "Container: $containerDN"
        )
    }
}

<#
.SYNOPSIS
    The container completer registration table: every parameter that takes a container DN.

.DESCRIPTION
    Data, as its own function, so a test can assert the inventory without reaching into a
    registered scriptblock. Unlike the identity table this needs no per-entry object types -
    every container parameter wants the same candidate list, and -SearchBase is distinguished
    inside Get-adPEASContainerCompletion by the parameter name it is handed.

.OUTPUTS
    [hashtable[]] with Command and Parameter.
#>
function Get-adPEASContainerCompleterRegistrations {
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param()

    return @(
        @{ Command = 'Get-DomainObject';        Parameter = 'SearchBase' }
        @{ Command = 'Get-DomainUser';          Parameter = 'SearchBase' }
        @{ Command = 'Get-DomainComputer';      Parameter = 'SearchBase' }
        @{ Command = 'Get-DomainGroup';         Parameter = 'SearchBase' }
        @{ Command = 'Get-DomainGPO';           Parameter = 'SearchBase' }
        @{ Command = 'Get-CertificateTemplate'; Parameter = 'SearchBase' }
        @{ Command = 'Set-DomainObject';        Parameter = 'SearchBase' }
        @{ Command = 'Invoke-LDAPSearch';       Parameter = 'SearchBase' }
        @{ Command = 'New-DomainUser';          Parameter = 'OrganizationalUnit' }
        @{ Command = 'New-DomainComputer';      Parameter = 'OrganizationalUnit' }
        @{ Command = 'New-DomainGroup';         Parameter = 'OrganizationalUnit' }
        @{ Command = 'Move-DomainObject';       Parameter = 'DestinationOU' }
    )
}

<#
.SYNOPSIS
    Registers the shared container-DN completer for every parameter that takes one.

.DESCRIPTION
    Twelve parameters across eleven functions accept a container distinguishedName. They all
    want the same candidate list, so one plain scriptblock serves all twelve.

.EXAMPLE
    Register-adPEASContainerCompleters
    Called once at module load, immediately below.
#>
function Register-adPEASContainerCompleters {
    [CmdletBinding()]
    param()

    $containerCompleter = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        Get-adPEASContainerCompletion -WordToComplete $wordToComplete -ParameterName $parameterName
    }

    $registrations = @(Get-adPEASContainerCompleterRegistrations)

    foreach ($registration in $registrations) {
        Register-ArgumentCompleter -CommandName $registration.Command `
            -ParameterName $registration.Parameter -ScriptBlock $containerCompleter
    }

    Write-Log "[Register-adPEASContainerCompleters] Registered container completion for $($registrations.Count) parameter(s)"
}

Register-adPEASContainerCompleters
