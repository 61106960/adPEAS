<#
.SYNOPSIS
    Registers tab-completion for adPEAS Get-Domain*, Set-Domain* and Request-ADCSCertificate functions.

.DESCRIPTION
    Register-adPEASCompleters provides tab-completion functionality for:
    - Identity parameters in Get-DomainUser, Get-DomainComputer, Get-DomainGroup, Get-DomainGPO
    - Identity parameters in Set-DomainUser, Set-DomainComputer, Set-DomainGroup, Set-DomainGPO, Set-DomainObject
    - TemplateName parameter in Request-ADCSCertificate

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
        Users     = @("sAMAccountName1", "sAMAccountName2", ...)
        Computers = @("sAMAccountName1", "sAMAccountName2", ...)
        Groups    = @("sAMAccountName1", "sAMAccountName2", ...)
        GPOs      = @("displayName1", "displayName2", ...)
        Templates = @("templateName1", "templateName2", ...)
    }

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

# Initialize completion cache if not exists
if (-not $Script:CompletionCache) {
    $Script:CompletionCache = @{
        Users     = @()
        Computers = @()
        Groups    = @()
        GPOs      = @()
        Templates = @()
    }
}

# Track which object types have been attempted for lazy loading (prevents repeated failed attempts)
if (-not $Script:CompletionCacheAttempted) {
    $Script:CompletionCacheAttempted = @{
        Users     = $false
        Computers = $false
        Groups    = $false
        GPOs      = $false
        Templates = $false
    }
}

<#
.SYNOPSIS
    Builds the tab-completion cache by querying AD for object names.

.DESCRIPTION
    Build-CompletionCache queries Active Directory to populate the completion cache with sAMAccountNames (for Users, Computers, Groups) and displayNames (for GPOs).
    This function is called by Connect-adPEAS when -BuildCompletionCache is specified.

.PARAMETER ObjectTypes
    Array of object types to cache. Valid values: Users, Computers, Groups, GPOs, All.
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
        [ValidateSet('Users', 'Computers', 'Groups', 'GPOs', 'Templates', 'All')]
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

        # Summary
        $totalCached = $Script:CompletionCache.Users.Count +
                       $Script:CompletionCache.Computers.Count +
                       $Script:CompletionCache.Groups.Count +
                       $Script:CompletionCache.GPOs.Count +
                       $Script:CompletionCache.Templates.Count

        Write-Log "[Build-CompletionCache] Cache built: $($Script:CompletionCache.Users.Count) users, $($Script:CompletionCache.Computers.Count) computers, $($Script:CompletionCache.Groups.Count) groups, $($Script:CompletionCache.GPOs.Count) GPOs, $($Script:CompletionCache.Templates.Count) templates (Total: $totalCached)"
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
            Users     = @()
            Computers = @()
            Groups    = @()
            GPOs      = @()
            Templates = @()
        }
        # Reset lazy loading flags so cache can be rebuilt
        $Script:CompletionCacheAttempted = @{
            Users     = $false
            Computers = $false
            Groups    = $false
            GPOs      = $false
            Templates = $false
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
            Users     = $Script:CompletionCache.Users.Count
            Computers = $Script:CompletionCache.Computers.Count
            Groups    = $Script:CompletionCache.Groups.Count
            GPOs      = $Script:CompletionCache.GPOs.Count
            Templates = $Script:CompletionCache.Templates.Count
            Total     = ($Script:CompletionCache.Users.Count +
                        $Script:CompletionCache.Computers.Count +
                        $Script:CompletionCache.Groups.Count +
                        $Script:CompletionCache.GPOs.Count +
                        $Script:CompletionCache.Templates.Count)
            CacheExists = ($Script:CompletionCache.Users.Count -gt 0 -or
                          $Script:CompletionCache.Computers.Count -gt 0 -or
                          $Script:CompletionCache.Groups.Count -gt 0 -or
                          $Script:CompletionCache.GPOs.Count -gt 0 -or
                          $Script:CompletionCache.Templates.Count -gt 0)
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
    }
}

# Get-DomainUser -Identity completer
Register-ArgumentCompleter -CommandName Get-DomainUser -ParameterName Identity -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    # Get state from the adPEAS module scope
    $state = Get-adPEASCompletionState -ObjectType 'Users'

    # Lazy loading: Build cache on first TAB press if connection exists and not yet attempted
    if ($state.HasConnection -and
        (-not $state.Cache -or $state.Cache.Users.Count -eq 0) -and
        (-not $state.CacheAttempted -or -not $state.CacheAttempted.Users)) {
        # Build cache for Users only (lazy, on-demand)
        Build-CompletionCache -ObjectTypes @('Users')
        # Refresh state after building
        $state = Get-adPEASCompletionState -ObjectType 'Users'
    }

    if ($state.Cache -and $state.Cache.Users -and $state.Cache.Users.Count -gt 0) {
        $state.Cache.Users | Where-Object {
            $_ -like "$wordToComplete*"
        } | Select-Object -First 50 | ForEach-Object {
            # Quote with double quotes and escape special characters (handles O'Brien, $vars, etc.)
            $completionText = if ($_ -match "[\s'`"`$``]") {
                '"' + ($_ -replace '"', '""') + '"'
            } else { $_ }
            [System.Management.Automation.CompletionResult]::new(
                $completionText,
                $_,
                'ParameterValue',
                "User: $_"
            )
        }
    }
}

# Get-DomainComputer -Identity completer
Register-ArgumentCompleter -CommandName Get-DomainComputer -ParameterName Identity -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    # Get state from the adPEAS module scope
    $state = Get-adPEASCompletionState -ObjectType 'Computers'

    # Lazy loading: Build cache on first TAB press if connection exists and not yet attempted
    if ($state.HasConnection -and
        (-not $state.Cache -or $state.Cache.Computers.Count -eq 0) -and
        (-not $state.CacheAttempted -or -not $state.CacheAttempted.Computers)) {
        # Build cache for Computers only (lazy, on-demand)
        Build-CompletionCache -ObjectTypes @('Computers')
        # Refresh state after building
        $state = Get-adPEASCompletionState -ObjectType 'Computers'
    }

    if ($state.Cache -and $state.Cache.Computers -and $state.Cache.Computers.Count -gt 0) {
        $state.Cache.Computers | Where-Object {
            $_ -like "$wordToComplete*"
        } | Select-Object -First 50 | ForEach-Object {
            # Quote with double quotes and escape special characters
            $completionText = if ($_ -match "[\s'`"`$``]") {
                '"' + ($_ -replace '"', '""') + '"'
            } else { $_ }
            [System.Management.Automation.CompletionResult]::new(
                $completionText,
                $_,
                'ParameterValue',
                "Computer: $_"
            )
        }
    }
}

# Get-DomainGroup -Identity completer
Register-ArgumentCompleter -CommandName Get-DomainGroup -ParameterName Identity -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    # Get state from the adPEAS module scope
    $state = Get-adPEASCompletionState -ObjectType 'Groups'

    # Lazy loading: Build cache on first TAB press if connection exists and not yet attempted
    if ($state.HasConnection -and
        (-not $state.Cache -or $state.Cache.Groups.Count -eq 0) -and
        (-not $state.CacheAttempted -or -not $state.CacheAttempted.Groups)) {
        # Build cache for Groups only (lazy, on-demand)
        Build-CompletionCache -ObjectTypes @('Groups')
        # Refresh state after building
        $state = Get-adPEASCompletionState -ObjectType 'Groups'
    }

    if ($state.Cache -and $state.Cache.Groups -and $state.Cache.Groups.Count -gt 0) {
        $state.Cache.Groups | Where-Object {
            $_ -like "$wordToComplete*"
        } | Select-Object -First 50 | ForEach-Object {
            # Quote with double quotes and escape special characters
            $completionText = if ($_ -match "[\s'`"`$``]") {
                '"' + ($_ -replace '"', '""') + '"'
            } else { $_ }
            [System.Management.Automation.CompletionResult]::new(
                $completionText,
                $_,
                'ParameterValue',
                "Group: $_"
            )
        }
    }
}

# Get-DomainGPO -Identity completer
Register-ArgumentCompleter -CommandName Get-DomainGPO -ParameterName Identity -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    # Get state from the adPEAS module scope
    $state = Get-adPEASCompletionState -ObjectType 'GPOs'

    # Lazy loading: Build cache on first TAB press if connection exists and not yet attempted
    if ($state.HasConnection -and
        (-not $state.Cache -or $state.Cache.GPOs.Count -eq 0) -and
        (-not $state.CacheAttempted -or -not $state.CacheAttempted.GPOs)) {
        # Build cache for GPOs only (lazy, on-demand)
        Build-CompletionCache -ObjectTypes @('GPOs')
        # Refresh state after building
        $state = Get-adPEASCompletionState -ObjectType 'GPOs'
    }

    if ($state.Cache -and $state.Cache.GPOs -and $state.Cache.GPOs.Count -gt 0) {
        $state.Cache.GPOs | Where-Object {
            $_ -like "$wordToComplete*"
        } | Select-Object -First 50 | ForEach-Object {
            # Quote with double quotes and escape special characters (GPO names often contain spaces)
            $completionText = if ($_ -match "[\s'`"`$``]") {
                '"' + ($_ -replace '"', '""') + '"'
            } else { $_ }
            [System.Management.Automation.CompletionResult]::new(
                $completionText,
                $_,
                'ParameterValue',
                "GPO: $_"
            )
        }
    }
}

# =====================================================================
# SET-DOMAIN* COMPLETERS
# These use the same cache as Get-Domain* functions
# =====================================================================

# Set-DomainUser -Identity completer
Register-ArgumentCompleter -CommandName Set-DomainUser -ParameterName Identity -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    $state = Get-adPEASCompletionState -ObjectType 'Users'

    if ($state.HasConnection -and
        (-not $state.Cache -or $state.Cache.Users.Count -eq 0) -and
        (-not $state.CacheAttempted -or -not $state.CacheAttempted.Users)) {
        Build-CompletionCache -ObjectTypes @('Users')
        $state = Get-adPEASCompletionState -ObjectType 'Users'
    }

    if ($state.Cache -and $state.Cache.Users -and $state.Cache.Users.Count -gt 0) {
        $state.Cache.Users | Where-Object {
            $_ -like "$wordToComplete*"
        } | Select-Object -First 50 | ForEach-Object {
            $completionText = if ($_ -match "[\s'`"`$``]") {
                '"' + ($_ -replace '"', '""') + '"'
            } else { $_ }
            [System.Management.Automation.CompletionResult]::new(
                $completionText,
                $_,
                'ParameterValue',
                "User: $_"
            )
        }
    }
}

# Set-DomainComputer -Identity completer
Register-ArgumentCompleter -CommandName Set-DomainComputer -ParameterName Identity -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    $state = Get-adPEASCompletionState -ObjectType 'Computers'

    if ($state.HasConnection -and
        (-not $state.Cache -or $state.Cache.Computers.Count -eq 0) -and
        (-not $state.CacheAttempted -or -not $state.CacheAttempted.Computers)) {
        Build-CompletionCache -ObjectTypes @('Computers')
        $state = Get-adPEASCompletionState -ObjectType 'Computers'
    }

    if ($state.Cache -and $state.Cache.Computers -and $state.Cache.Computers.Count -gt 0) {
        $state.Cache.Computers | Where-Object {
            $_ -like "$wordToComplete*"
        } | Select-Object -First 50 | ForEach-Object {
            $completionText = if ($_ -match "[\s'`"`$``]") {
                '"' + ($_ -replace '"', '""') + '"'
            } else { $_ }
            [System.Management.Automation.CompletionResult]::new(
                $completionText,
                $_,
                'ParameterValue',
                "Computer: $_"
            )
        }
    }
}

# Set-DomainGroup -Identity completer
Register-ArgumentCompleter -CommandName Set-DomainGroup -ParameterName Identity -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    $state = Get-adPEASCompletionState -ObjectType 'Groups'

    if ($state.HasConnection -and
        (-not $state.Cache -or $state.Cache.Groups.Count -eq 0) -and
        (-not $state.CacheAttempted -or -not $state.CacheAttempted.Groups)) {
        Build-CompletionCache -ObjectTypes @('Groups')
        $state = Get-adPEASCompletionState -ObjectType 'Groups'
    }

    if ($state.Cache -and $state.Cache.Groups -and $state.Cache.Groups.Count -gt 0) {
        $state.Cache.Groups | Where-Object {
            $_ -like "$wordToComplete*"
        } | Select-Object -First 50 | ForEach-Object {
            $completionText = if ($_ -match "[\s'`"`$``]") {
                '"' + ($_ -replace '"', '""') + '"'
            } else { $_ }
            [System.Management.Automation.CompletionResult]::new(
                $completionText,
                $_,
                'ParameterValue',
                "Group: $_"
            )
        }
    }
}

# Set-DomainGPO -Identity completer
Register-ArgumentCompleter -CommandName Set-DomainGPO -ParameterName Identity -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    $state = Get-adPEASCompletionState -ObjectType 'GPOs'

    if ($state.HasConnection -and
        (-not $state.Cache -or $state.Cache.GPOs.Count -eq 0) -and
        (-not $state.CacheAttempted -or -not $state.CacheAttempted.GPOs)) {
        Build-CompletionCache -ObjectTypes @('GPOs')
        $state = Get-adPEASCompletionState -ObjectType 'GPOs'
    }

    if ($state.Cache -and $state.Cache.GPOs -and $state.Cache.GPOs.Count -gt 0) {
        $state.Cache.GPOs | Where-Object {
            $_ -like "$wordToComplete*"
        } | Select-Object -First 50 | ForEach-Object {
            $completionText = if ($_ -match "[\s'`"`$``]") {
                '"' + ($_ -replace '"', '""') + '"'
            } else { $_ }
            [System.Management.Automation.CompletionResult]::new(
                $completionText,
                $_,
                'ParameterValue',
                "GPO: $_"
            )
        }
    }
}

# Set-DomainObject -Identity completer (generic - uses all caches combined)
Register-ArgumentCompleter -CommandName Set-DomainObject -ParameterName Identity -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    $state = Get-adPEASCompletionState -ObjectType 'All'

    # Lazy load all object types for generic Set-DomainObject
    if ($state.HasConnection) {
        if ((-not $state.Cache -or $state.Cache.Users.Count -eq 0) -and
            (-not $state.CacheAttempted -or -not $state.CacheAttempted.Users)) {
            Build-CompletionCache -ObjectTypes @('Users')
        }
        if ((-not $state.Cache -or $state.Cache.Computers.Count -eq 0) -and
            (-not $state.CacheAttempted -or -not $state.CacheAttempted.Computers)) {
            Build-CompletionCache -ObjectTypes @('Computers')
        }
        if ((-not $state.Cache -or $state.Cache.Groups.Count -eq 0) -and
            (-not $state.CacheAttempted -or -not $state.CacheAttempted.Groups)) {
            Build-CompletionCache -ObjectTypes @('Groups')
        }
        $state = Get-adPEASCompletionState -ObjectType 'All'
    }

    if ($state.Cache) {
        # Combine all object types for generic completer
        $allObjects = @()
        if ($state.Cache.Users) { $allObjects += $state.Cache.Users | ForEach-Object { @{ Name = $_; Type = 'User' } } }
        if ($state.Cache.Computers) { $allObjects += $state.Cache.Computers | ForEach-Object { @{ Name = $_; Type = 'Computer' } } }
        if ($state.Cache.Groups) { $allObjects += $state.Cache.Groups | ForEach-Object { @{ Name = $_; Type = 'Group' } } }

        $allObjects | Where-Object {
            $_.Name -like "$wordToComplete*"
        } | Select-Object -First 50 | ForEach-Object {
            $completionText = if ($_.Name -match "[\s'`"`$``]") {
                '"' + ($_.Name -replace '"', '""') + '"'
            } else { $_.Name }
            [System.Management.Automation.CompletionResult]::new(
                $completionText,
                $_.Name,
                'ParameterValue',
                "$($_.Type): $($_.Name)"
            )
        }
    }
}

# =====================================================================
# CERTIFICATE TEMPLATE COMPLETER
# Provides tab-completion for Request-ADCSCertificate -TemplateName
# Templates are collected from all CAs published in Enrollment Services
# =====================================================================

# Request-ADCSCertificate -TemplateName completer
Register-ArgumentCompleter -CommandName Request-ADCSCertificate -ParameterName TemplateName -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    # Get state from the adPEAS module scope
    $state = Get-adPEASCompletionState -ObjectType 'Templates'

    # Lazy loading: Build cache on first TAB press if connection exists and not yet attempted
    if ($state.HasConnection -and
        (-not $state.Cache -or $state.Cache.Templates.Count -eq 0) -and
        (-not $state.CacheAttempted -or -not $state.CacheAttempted.Templates)) {
        # Build cache for Templates only (lazy, on-demand)
        Build-CompletionCache -ObjectTypes @('Templates')
        # Refresh state after building
        $state = Get-adPEASCompletionState -ObjectType 'Templates'
    }

    if ($state.Cache -and $state.Cache.Templates -and $state.Cache.Templates.Count -gt 0) {
        $state.Cache.Templates | Where-Object {
            $_ -like "$wordToComplete*"
        } | Select-Object -First 50 | ForEach-Object {
            # Quote with double quotes and escape special characters
            $completionText = if ($_ -match "[\s'`"`$``]") {
                '"' + ($_ -replace '"', '""') + '"'
            } else { $_ }
            [System.Management.Automation.CompletionResult]::new(
                $completionText,
                $_,
                'ParameterValue',
                "Template: $_"
            )
        }
    }
}
