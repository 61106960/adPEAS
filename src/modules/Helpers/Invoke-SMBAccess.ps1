<#
.SYNOPSIS
    Executes scriptblock with SMB share access using credentials.

.DESCRIPTION
    Universal helper function for authenticated SMB/CIFS share access.

    Features:
    - Automatic credential handling (uses $Script:LDAPCredential or custom credentials)
    - PSDrive mounting for secure credential handling
    - Automatic SYSVOL/NETLOGON path detection
    - Retry logic for transient network errors
    - Comprehensive error handling and logging
    - Automatic cleanup (PSDrive removal)

    Use Cases:
    - SYSVOL access (GPO files, Registry.pol, GptTmpl.inf)
    - NETLOGON access (logon scripts)
    - Administrative shares (C$, ADMIN$)
    - Custom file shares

.PARAMETER ScriptBlock
    The code block to execute with SMB access.

.PARAMETER UNCPath
    Explicit UNC path to the share (e.g., "\\server\share" or "\\dc\C$").
    If not specified, defaults to SYSVOL share of current domain.

.PARAMETER Credential
    PSCredential object for authentication.
    If not specified, credential source is determined automatically:
    1. $Script:LDAPCredential (legacy support)
    2. $Script:LDAPContext['Credential'] - ONLY for SimpleBind sessions
       (Kerberos sessions use PTT, so SMB auth works automatically)
    3. Current user context (no explicit credentials)

.PARAMETER Description
    Optional description for logging/debugging purposes.
    Helps identify what operation is being performed.

.PARAMETER RetryCount
    Number of retry attempts on transient network errors.
    Default: 2

.PARAMETER Timeout
    Timeout in seconds for PSDrive mount operations.
    Default: 5 seconds (sufficient for LAN/VPN, quick failure on unreachable hosts)

.PARAMETER ErrorHandling
    How to handle errors:
    - Silent: Suppress errors, return $null (default)
    - Warn: Write warnings, continue execution
    - Stop: Throw errors, stop execution

.EXAMPLE
    # Basic usage - SYSVOL access with auto-credentials
    Invoke-SMBAccess -ScriptBlock {
        Get-ChildItem "\\$($Script:LDAPContext.Server)\SYSVOL\*" -Recurse
    }

.EXAMPLE
    # Explicit UNC path with description
    Invoke-SMBAccess -UNCPath "\\dc01\SYSVOL" -Description "Scanning GPO files" -ScriptBlock {
        Get-ChildItem $args[0] -Recurse -Filter "*.xml"
    }

.EXAMPLE
    # Custom credentials for administrative share
    $cred = Get-Credential
    Invoke-SMBAccess -UNCPath "\\server\C$" -Credential $cred -ScriptBlock {
        Get-ChildItem "\\server\C$\Windows\Temp"
    }

.EXAMPLE
    # With retry logic and custom timeout
    Invoke-SMBAccess -UNCPath "\\slowserver\share" -RetryCount 5 -Timeout 60 -ScriptBlock {
        Get-Content "\\slowserver\share\file.txt"
    }

.OUTPUTS
    Output of the passed scriptblock

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

# ============================================================================
# SMB Share Access Cache
# ============================================================================
# Caches failed SMB share access attempts to avoid repeated timeouts.
# When a share (e.g., \\server\SYSVOL) fails, all subsequent access attempts
# to the same share return immediately instead of waiting for another timeout.
#
# Reset with: Reset-SMBShareAccessCache (called automatically by Disconnect-adPEAS)

if (-not $Script:SMBShareAccessCache) {
    $Script:SMBShareAccessCache = @{}
}

# ============================================================================
# SYSVOL File Cache
# ============================================================================
# Caches the result of a single recursive Get-ChildItem on the SYSVOL share.
# The first caller triggers the enumeration; all subsequent callers filter
# the cached FileInfo array locally - no additional SMB round-trips.
#
# Reset with: Reset-SYSVOLFileCache (called automatically by Disconnect-adPEAS)

if (-not $Script:SYSVOLFileCache) {
    $Script:SYSVOLFileCache = $null  # $null = not yet populated
}

# Folders the enumeration below could not read, and whether SYSVOL was reachable at all.
# Every Get-ChildItem in the cache builder runs with -ErrorAction SilentlyContinue, which
# is right - one denied GPO folder must not abort the scan - but it used to leave no
# trace. A caller then found zero files in a folder it was never allowed to read and
# printed its "nothing found" line, which in several checks is a green Secure line. For an
# audit tool that is the most expensive kind of defect: the gap is invisible.
if (-not $Script:SYSVOLCacheSkipped) {
    $Script:SYSVOLCacheSkipped = $null  # $null = cache not yet built
}
if (-not $Script:SYSVOLCacheReachable) {
    $Script:SYSVOLCacheReachable = $null  # $null = cache not yet built
}

# Folders under SYSVOL that no domain user can read by design, and that hold no policy
# content. They are left out of the coverage report above - not to make the output
# tidier, but because the report would otherwise be wrong.
#
# What that report is for: "a folder existed that I could not read, so a credential may
# be sitting there unseen". That statement only means something where adPEAS has NARROWER
# rights than an attacker would. DfsrPrivate is DFS Replication's own working directory -
# Staging, ConflictAndDeleted and Installing - restricted to SYSTEM, so nobody at domain
# user level reads it, adPEAS and attacker alike. Counting it as a gap raised a red line
# in every DFSR-replicated domain there is, which is all of them since 2008, and through
# the seven callers that downgrade on it, it also meant the green "no GPP credentials in
# SYSVOL" verdict could never be reached.
#
# Note what this does NOT do: nothing is excluded from the file scan. These folders were
# never readable in the first place - that is why they appear in the error list - so the
# only thing that changes is whether a gap gets claimed that no attacker could use
# either. A folder that is unreadable for any other reason still counts.
$Script:SYSVOLByDesignInaccessible = @(
    'DfsrPrivate'
)

<#
.SYNOPSIS
    Tests whether an unreadable SYSVOL path is one that is inaccessible by design.
.DESCRIPTION
    Compares every segment of the path against $Script:SYSVOLByDesignInaccessible, not
    just the last one: depending on where the ACL bites, the enumeration error names
    DfsrPrivate itself or something below it such as DfsrPrivate\ConflictAndDeleted.

    Segments are compared whole. A folder someone really created called
    DfsrPrivateBackup is not exempt and still counts as a gap in coverage.
.PARAMETER Path
    The path the enumeration error reported.
.OUTPUTS
    Boolean - $true if the path is exempt from the coverage report.
#>
function Test-SYSVOLByDesignInaccessible {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Path
    )

    if (-not $Path) { return $false }
    foreach ($segment in ($Path -split '[\\/]')) {
        if ($Script:SYSVOLByDesignInaccessible -contains $segment) { return $true }
    }
    return $false
}

<#
.SYNOPSIS
    Turns suppressed enumeration errors into the list of folders that count as a gap.
.DESCRIPTION
    One denied folder produces one error whose TargetObject is its path. Where the
    provider supplies no TargetObject the category target is used, and failing that the
    exception message - so the count stays right rather than under-reporting.

    Paths that are inaccessible by design are dropped here, which is the one place that
    decision is made.
.PARAMETER ErrorRecords
    The records collected by -ErrorVariable during enumeration.
.OUTPUTS
    String[] - the distinct paths that represent real gaps in coverage.
#>
function Select-SYSVOLCoverageGaps {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object[]]$ErrorRecords
    )

    $gaps = [System.Collections.Generic.List[string]]::new()
    foreach ($err in @($ErrorRecords)) {
        if ($null -eq $err) { continue }

        $path = $null
        if ($err.TargetObject) {
            $path = [string]$err.TargetObject
        } elseif ($err.CategoryInfo -and $err.CategoryInfo.TargetName) {
            $path = [string]$err.CategoryInfo.TargetName
        } elseif ($err.Exception) {
            $path = $err.Exception.Message
        }
        if (-not $path) { continue }

        if (Test-SYSVOLByDesignInaccessible -Path $path) {
            Write-Log "[Select-SYSVOLCoverageGaps] Not counted as a coverage gap - inaccessible by design and holds no policy content: $path"
            continue
        }

        if (-not $gaps.Contains($path)) { [void]$gaps.Add($path) }
    }

    # Emitted as items, not wrapped. The comma idiom looked safer and was not: under
    # Set-StrictMode -Version Latest - which Pester applies to everything a test body
    # calls - ",@($emptyList)" yields a one-element array holding an empty array, so an
    # empty result counted as one unreadable folder. That is precisely the false gap
    # this whole function exists to stop reporting. Callers wrap in @(), which is what
    # Get-CachedSYSVOLFiles does.
    return @($gaps)
}

<#
.SYNOPSIS
    Resets the SYSVOL file listing cache.
.DESCRIPTION
    Clears the cached SYSVOL file listing and the coverage information that goes with it.
    Called automatically by Disconnect-adPEAS when a session ends.
#>
function Reset-SYSVOLFileCache {
    [CmdletBinding()]
    param()
    $Script:SYSVOLFileCache = $null
    $Script:SYSVOLCacheSkipped = $null
    $Script:SYSVOLCacheReachable = $null
    Write-Log "[Reset-SYSVOLFileCache] Cache cleared"
}

<#
.SYNOPSIS
    Reports how complete the cached SYSVOL listing is.
.DESCRIPTION
    Returns the coverage of the SYSVOL file cache so a check can tell "found nothing"
    apart from "was not allowed to look". Returns $null when the cache has not been built
    yet, in which case nothing has been read and no claim should be made either.
.OUTPUTS
    PSCustomObject with Reachable, FileCount, SkippedCount and SkippedPaths,
    or $null if the cache has not been built.
#>
function Get-SYSVOLCacheCoverage {
    [CmdletBinding()]
    param()

    if ($null -eq $Script:SYSVOLFileCache) { return $null }

    # Filter out $null: @($null) is a one-element array in PowerShell, so an unset list
    # would report one unreadable folder that does not exist.
    $skipped = @($Script:SYSVOLCacheSkipped | Where-Object { $_ })

    # Only an explicit $false means unreachable. $null means the cache was populated
    # without going through the builder - a test fixture, or a direct assignment - and in
    # that case something did put files there, so treating it as unreachable would invent
    # a failure.
    $reachable = -not ($Script:SYSVOLCacheReachable -eq $false)

    return [PSCustomObject]@{
        Reachable    = $reachable
        FileCount    = @($Script:SYSVOLFileCache).Count
        SkippedCount = $skipped.Count
        SkippedPaths = $skipped
    }
}

<#
.SYNOPSIS
    Emits a line about incomplete SYSVOL coverage, if there is any.
.DESCRIPTION
    Writes nothing when SYSVOL was read completely, so a caller can place it
    unconditionally in front of its own conclusion. Returns $true when coverage was
    incomplete, which lets a caller downgrade a "Secure" conclusion to a "Note": a green
    line must not be printed over folders that were never read.
.OUTPUTS
    Boolean - $true if SYSVOL coverage is incomplete.
#>
function Show-SYSVOLCoverageNote {
    [CmdletBinding()]
    param()

    $coverage = Get-SYSVOLCacheCoverage
    if ($null -eq $coverage) { return $false }

    if (-not $coverage.Reachable) {
        Show-Line "SYSVOL was not reachable - no file-based check below could run. This is not a clean result." -Class Finding
        return $true
    }

    if ($coverage.SkippedCount -gt 0) {
        Show-Line "$($coverage.SkippedCount) SYSVOL folder(s) could not be read - the result below is incomplete" -Class Finding
        foreach ($path in ($coverage.SkippedPaths | Select-Object -First 10)) {
            Show-Line "  not read: $path" -Class Hint
        }
        if ($coverage.SkippedCount -gt 10) {
            Show-Line "  ... and $($coverage.SkippedCount - 10) more" -Class Hint
        }
        return $true
    }

    return $false
}

<#
.SYNOPSIS
    Returns SYSVOL files matching the specified filter, using a cache to avoid repeated SMB traversals.

.DESCRIPTION
    On the first call, performs a single recursive Get-ChildItem on the SYSVOL share
    and caches ALL file objects. Subsequent calls filter the cached list locally.

    This eliminates redundant SMB directory traversals when multiple Check modules
    each need to search SYSVOL for different file types.

.PARAMETER Filter
    Filename pattern(s) to match. Supports wildcards.
    Examples: "*.xml", "GptTmpl.inf", @("scripts.ini", "psscripts.ini")

.PARAMETER SYSVOLPath
    Base path to search. Defaults to \\<Server>\SYSVOL\<Domain>\Policies.
    If not specified, auto-detects from LDAPContext.

.OUTPUTS
    Array of FileInfo objects matching the filter.
    Returns empty array if SYSVOL is not accessible or no files match.

.EXAMPLE
    $xmlFiles = Get-CachedSYSVOLFiles -Filter "*.xml"

.EXAMPLE
    $iniFiles = Get-CachedSYSVOLFiles -Filter @("scripts.ini", "psscripts.ini")
#>
function Get-CachedSYSVOLFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Filter,

        [Parameter(Mandatory=$false)]
        [string]$SYSVOLPath
    )

    # Auto-detect SYSVOL path if not provided
    if (-not $SYSVOLPath) {
        if (-not $Script:LDAPContext -or -not $Script:LDAPContext.Server) {
            Write-Log "[Get-CachedSYSVOLFiles] No LDAPContext available"
            return @()
        }
        $dcServer = $Script:LDAPContext.Server
        $domainFQDN = $Script:LDAPContext.Domain
        # Cache from domain folder (SYSVOL root is a DFS junction that Get-ChildItem may not traverse)
        $SYSVOLPath = "\\$dcServer\SYSVOL\$domainFQDN"
    }

    # Build cache on first access
    if ($null -eq $Script:SYSVOLFileCache) {
        Write-Log "[Get-CachedSYSVOLFiles] Building SYSVOL file cache from: $SYSVOLPath"

        # Accumulates every folder the enumeration below is not allowed to read, so a
        # caller can tell "found nothing" from "was not allowed to look".
        $enumErrors = @()
        $Script:SYSVOLCacheSkipped = @()
        $Script:SYSVOLCacheReachable = $false

        if (-not (Test-Path $SYSVOLPath)) {
            Write-Log "[Get-CachedSYSVOLFiles] SYSVOL path not accessible: $SYSVOLPath"
            $Script:SYSVOLFileCache = @()
            return @()
        }
        $Script:SYSVOLCacheReachable = $true

        # Enumerate per top-level subdirectory (typically Policies/{GUID} folders) with progress
        # This avoids a single blocking Get-ChildItem -Recurse over the entire SYSVOL tree
        $topLevelDirs = @(Get-ChildItem -Force -Path $SYSVOLPath -Directory -ErrorAction SilentlyContinue -ErrorVariable +enumErrors)
        $allFiles = [System.Collections.Generic.List[object]]::new()

        if ($topLevelDirs.Count -gt 0) {
            # Count total subdirectories for progress (Policies folder typically has one subdir per GPO)
            $subDirs = [System.Collections.Generic.List[object]]::new()
            foreach ($topDir in $topLevelDirs) {
                $childDirs = @(Get-ChildItem -Force -Path $topDir.FullName -Directory -ErrorAction SilentlyContinue -ErrorVariable +enumErrors)
                if ($childDirs.Count -gt 0) {
                    foreach ($cd in $childDirs) { $subDirs.Add($cd) }
                } else {
                    # Top-level dir has no subdirs (e.g., Scripts folder) - treat as single unit
                    $subDirs.Add($topDir)
                }
            }

            $totalDirs = $subDirs.Count
            $currentDirIndex = 0
            $showProgress = $totalDirs -gt $Script:ProgressThreshold

            foreach ($dir in $subDirs) {
                $currentDirIndex++
                if ($showProgress) {
                    Show-Progress -Activity "Building SYSVOL file cache" -Current $currentDirIndex -Total $totalDirs -ObjectName $dir.Name
                }
                $dirFiles = @(Get-ChildItem -Force -Path $dir.FullName -Recurse -ErrorAction SilentlyContinue -ErrorVariable +enumErrors | Where-Object { -not $_.PSIsContainer })
                foreach ($f in $dirFiles) { $allFiles.Add($f) }
            }

            if ($showProgress) {
                Show-Progress -Activity "Building SYSVOL file cache" -Completed
            }

            # Also get files directly in the top-level SYSVOL path (not in subdirectories)
            $rootFiles = @(Get-ChildItem -Force -Path $SYSVOLPath -File -ErrorAction SilentlyContinue -ErrorVariable +enumErrors)
            foreach ($f in $rootFiles) { $allFiles.Add($f) }
        } else {
            # No subdirectories - fall back to flat recursive scan
            $allFiles = [System.Collections.Generic.List[object]]::new(
                @(Get-ChildItem -Force -Path $SYSVOLPath -Recurse -ErrorAction SilentlyContinue -ErrorVariable +enumErrors | Where-Object { -not $_.PSIsContainer })
            )
        }

        # Turn the suppressed enumeration errors into the list of folders that were not
        # read. One denied folder produces one error whose TargetObject is its path; where
        # the provider does not supply one, fall back to the message so the count is still
        # right and the caller does not under-report.
        $Script:SYSVOLCacheSkipped = @(Select-SYSVOLCoverageGaps -ErrorRecords @($enumErrors))

        $Script:SYSVOLFileCache = @($allFiles)
        Write-Log "[Get-CachedSYSVOLFiles] Cached $($Script:SYSVOLFileCache.Count) files from SYSVOL, $($Script:SYSVOLCacheSkipped.Count) folder(s) unreadable"
    }

    # Filter cached results locally
    $filterArray = @($Filter)
    $results = @($Script:SYSVOLFileCache | Where-Object {
        $fileName = $_.Name
        $matched = $false
        foreach ($f in $filterArray) {
            if ($fileName -like $f) {
                $matched = $true
                break
            }
        }
        $matched
    })

    Write-Log "[Get-CachedSYSVOLFiles] Filter '$($filterArray -join "', '")' matched $($results.Count) file(s)"
    return $results
}

<#
.SYNOPSIS
    Returns cached file content from SYSVOL, reading from SMB only on first access.
.DESCRIPTION
    Provides a content-level cache for SYSVOL files (e.g., GptTmpl.inf).
    Multiple check modules that read the same file per GPO will only trigger
    one SMB read - subsequent calls return the cached content.

    This complements Get-CachedSYSVOLFiles (which caches directory listings)
    by also caching the actual file content on demand.
.PARAMETER Path
    Full UNC path to the file to read.
.OUTPUTS
    [string] Raw file content, or $null if file does not exist.
#>
function Get-CachedSYSVOLContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    if (-not $Script:SYSVOLContentCache) {
        $Script:SYSVOLContentCache = @{}
    }

    $cacheKey = $Path.ToLowerInvariant()

    if ($Script:SYSVOLContentCache.ContainsKey($cacheKey)) {
        return $Script:SYSVOLContentCache[$cacheKey]
    }

    if (-not (Test-Path $Path)) {
        return $null
    }

    $content = Get-Content -Path $Path -Raw -ErrorAction SilentlyContinue
    if ($null -ne $content) {
        $Script:SYSVOLContentCache[$cacheKey] = $content
    }

    return $content
}

<#
.SYNOPSIS
    Returns the NTFS access rules of a directory, keyed by SID.

.DESCRIPTION
    A GPO has two halves: the directory object and the folder under
    \\<domain>\SYSVOL\<domain>\Policies\{GUID}\ that holds its actual content. Write access
    to that folder is enough to rewrite Registry.pol, GptTmpl.inf, the Scripts folder,
    ScheduledTasks.xml and GPT.ini - which is code execution on every machine the policy
    reaches, with no permission on the directory object at all. Nothing in the project read
    it, so Get-GPOPermissions assessed one half and its Secure line spoke for both.

    The rules come back identified by SID rather than by account name. A name is localized,
    an orphaned trustee has none at all, and every identity classification in adPEAS is SID
    based.

    Three return states, which the caller has to tell apart:
      an array  - the rules, possibly empty
      $null     - the folder could not be read, which is not the same as "no rules"

.PARAMETER Path
    The directory to read. Must be a path Invoke-SMBAccess has made reachable.

.OUTPUTS
    [System.Security.AccessControl.FileSystemAccessRule[]] or $null.

.NOTES
    Internal helper. Lives beside the SYSVOL cache because it reaches the file system: a
    suite that stubs this file gets a stub for this too, which is what a unit test wants.

    Two runtimes, two ways to the same descriptor. Windows PowerShell 5.1 - the target -
    has DirectoryInfo.GetAccessControl() as an instance method. PowerShell 7 moved it into
    System.IO.FileSystemAclExtensions, so the instance call raises a MethodNotFound there
    and the extension type is the fallback. Get-Acl would need
    Microsoft.PowerShell.Security, which is not loadable on every host this runs on.
#>
function Get-DirectoryAccessRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $directoryInfo = New-Object System.IO.DirectoryInfo($Path)
        if (-not $directoryInfo.Exists) {
            Write-Log "[Get-DirectoryAccessRules] '$Path' does not exist or is not reachable"
            return $null
        }

        $security = $null
        try {
            $security = $directoryInfo.GetAccessControl()
        } catch {
            $security = [System.IO.FileSystemAclExtensions]::GetAccessControl($directoryInfo)
        }

        if (-not $security) {
            Write-Log "[Get-DirectoryAccessRules] No security descriptor returned for '$Path'"
            return $null
        }

        # Inherited rules included: SYSVOL inheritance is where a delegation set once at
        # the Policies folder reaches every policy below it, and that is the mistake worth
        # finding rather than one to filter out.
        #
        # The unary comma is load-bearing. An empty array unrolls to nothing on the way out
        # of a function, so a folder whose DACL holds no rule at all would arrive at the
        # caller as $null - which is this function's way of saying "could not be read", and
        # the opposite statement.
        return ,@($security.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    } catch {
        Write-Log "[Get-DirectoryAccessRules] Could not read the NTFS permissions of '$Path': $_"
        return $null
    }
}

<#
.SYNOPSIS
    Returns the NTFS access rules of a file, keyed by SID.

.DESCRIPTION
    The file counterpart of Get-DirectoryAccessRules, with the same three return states:
    an array of rules, possibly empty, or $null when the path is not a file that could be
    read - a folder, a missing file, or one whose descriptor the caller may not read.

    Get-GPOScheduledTasks reads with it the program a SYSTEM task starts from a share:
    whoever can write that file controls what runs as SYSTEM on every computer the policy
    reaches.

.PARAMETER Path
    The file to read. Must be a path Invoke-SMBAccess has made reachable.

.OUTPUTS
    [System.Security.AccessControl.FileSystemAccessRule[]] or $null.

.NOTES
    Internal helper, beside Get-DirectoryAccessRules for the same reason: a suite that
    stubs the file system reach of this file gets a stub for this too. The same two
    runtimes as well - FileInfo.GetAccessControl() in Windows PowerShell 5.1, the
    FileSystemAclExtensions fallback in PowerShell 7.
#>
function Get-FileAccessRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $fileInfo = New-Object System.IO.FileInfo($Path)
        if (-not $fileInfo.Exists) {
            Write-Log "[Get-FileAccessRules] '$Path' is not a file that exists and is reachable"
            return $null
        }

        $security = $null
        try {
            $security = $fileInfo.GetAccessControl()
        } catch {
            $security = [System.IO.FileSystemAclExtensions]::GetAccessControl($fileInfo)
        }

        if (-not $security) {
            Write-Log "[Get-FileAccessRules] No security descriptor returned for '$Path'"
            return $null
        }

        # Inherited rules included, and the unary comma for the reason given in
        # Get-DirectoryAccessRules: an empty rule set must not arrive as $null.
        return ,@($security.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    } catch {
        Write-Log "[Get-FileAccessRules] Could not read the NTFS permissions of '$Path': $_"
        return $null
    }
}

<#
.SYNOPSIS
    Resets the SMB share access cache.
.DESCRIPTION
    Clears the cache of failed SMB share access attempts,
    the SYSVOL file listing cache, and the SYSVOL content cache.
    Called automatically by Disconnect-adPEAS when a session ends.
    Can also be called manually to retry previously failed shares.
#>
function Reset-SMBShareAccessCache {
    [CmdletBinding()]
    param()
    $Script:SMBShareAccessCache = @{}
    $Script:SYSVOLContentCache = @{}
    Write-Log "[Reset-SMBShareAccessCache] Cache cleared"
}

<#
.SYNOPSIS
    Tests if SYSVOL is accessible based on cached access results.
.DESCRIPTION
    Returns $true if SYSVOL has not been marked as inaccessible in the cache.
    Returns $false if a previous SYSVOL access attempt failed.
    Returns $null if SYSVOL access has not been attempted yet.

    Use this in Check modules to skip SYSVOL-dependent logic early
    without incurring another SMB timeout.
.EXAMPLE
    $sysvolStatus = Test-SysvolAccessible
    if ($sysvolStatus -eq $false) {
        Show-Line "Skipping - SYSVOL not accessible" -Class Hint
        return
    }
#>
function Test-SysvolAccessible {
    [CmdletBinding()]
    param()

    if (-not $Script:LDAPContext -or -not $Script:LDAPContext.Server) {
        return $null  # No session - unknown
    }

    # Build the SYSVOL share key the same way Invoke-SMBAccess does
    $smbServer = $Script:LDAPContext.Server
    $kerberosUsed = $Script:LDAPContext['KerberosUsed']

    if (-not $kerberosUsed -and $Script:LDAPContext['DnsServer']) {
        # SimpleBind with custom DNS uses IP
        if ($Script:LDAPContext['ServerIP']) {
            $smbServer = $Script:LDAPContext['ServerIP']
        }
    }

    $shareKey = "\\$smbServer\SYSVOL".ToLower()

    if ($Script:SMBShareAccessCache.ContainsKey($shareKey)) {
        return $false  # Previously failed
    }

    return $null  # Not attempted yet (or succeeded)
}

function Invoke-SMBAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory=$false)]
        [string]$UNCPath,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [string]$Description,

        [Parameter(Mandatory=$false)]
        [ValidateRange(0, 10)]
        [int]$RetryCount = 2,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1, 300)]
        [int]$Timeout = 5,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Silent', 'Warn', 'Stop')]
        [string]$ErrorHandling = 'Silent'
    )

    begin {
        $operationDesc = if ($Description) { $Description } else { "SMB access" }
        Write-Log "[Invoke-SMBAccess] Starting: $operationDesc"
    }

    process {
        $driveName = $null
        $driveMounted = $false
        $credToUse = $null

        try {
            if ($Credential) {
                $credToUse = $Credential
                Write-Log "[Invoke-SMBAccess] Using provided credentials: $($Credential.UserName)"
            }
            elseif ($Script:LDAPCredential) {
                $credToUse = $Script:LDAPCredential
                Write-Log "[Invoke-SMBAccess] Using stored credentials: $($Script:LDAPCredential.UserName)"
            }
            elseif ($Script:LDAPContext -and $Script:LDAPContext['Credential']) {
                # Check if Kerberos was used - if yes, SMB should work automatically via PTT
                if ($Script:LDAPContext['KerberosUsed']) {
                    # Kerberos session - ticket already injected into Windows session
                    # SMB will use Kerberos auth automatically, no need for explicit credentials
                    Write-Log "[Invoke-SMBAccess] Kerberos session active - SMB will use Kerberos auth automatically"
                    $credToUse = $null
                }
                else {
                    # SimpleBind session - need to use stored credentials for SMB
                    $credToUse = $Script:LDAPContext['Credential']
                    Write-Log "[Invoke-SMBAccess] SimpleBind session - using stored credentials for SMB: $($credToUse.UserName)"
                }
            }
            else {
                Write-Log "[Invoke-SMBAccess] No credentials available, using current user context"
            }

            # Determine UNC path
            $targetPath = $UNCPath

            # Validate UNC path using central validation function (security check)
            # This prevents path traversal attacks and validates host/share format
            if ($targetPath) {
                if (-not (Test-ValidUNCPath -UNCPath $targetPath)) {
                    $errorMsg = "Invalid or potentially malicious UNC path: '$targetPath'. Path traversal or invalid format detected."
                    Write-Log "[Invoke-SMBAccess] Security: $errorMsg"

                    switch ($ErrorHandling) {
                        'Warn' { Write-Warning $errorMsg; return $null }
                        'Stop' { throw $errorMsg }
                        default { return $null }
                    }
                }
            }

            if (-not $targetPath) {
                # Auto-detect SYSVOL path
                if ($Script:LDAPContext -and $Script:LDAPContext.Server) {
                    $smbServer = $Script:LDAPContext.Server
                    $kerberosUsed = $Script:LDAPContext['KerberosUsed']
                    $hostsPatched = $Script:LDAPContext['EarlyHostsPatched']

                    if ($kerberosUsed -and $hostsPatched) {
                        # Kerberos with hosts file patching - MUST use hostname for SPN matching
                        Write-Log "[Invoke-SMBAccess] Kerberos+HostsPatched mode: Using hostname for SMB (SPN matching): $smbServer"
                    }
                    elseif ($kerberosUsed) {
                        # Kerberos without hosts patching - still use hostname (system DNS should work)
                        Write-Log "[Invoke-SMBAccess] Kerberos mode: Using hostname for SMB (SPN matching): $smbServer"
                    }
                    elseif ($Script:LDAPContext['DnsServer']) {
                        # SimpleBind with custom DNS - use IP address (system DNS can't resolve)
                        $resolvedIP = $null

                        # Source 1: ServerIP (set after successful connect)
                        if ($Script:LDAPContext['ServerIP']) {
                            $resolvedIP = $Script:LDAPContext['ServerIP']
                            Write-Log "[Invoke-SMBAccess] Using cached ServerIP: $resolvedIP"
                        }
                        # Source 2: DnsCache (populated during DNS resolution)
                        elseif ($Script:LDAPContext['DnsCache'] -and $Script:LDAPContext['DnsCache'].ContainsKey($smbServer.ToLower())) {
                            $resolvedIP = $Script:LDAPContext['DnsCache'][$smbServer.ToLower()]
                            Write-Log "[Invoke-SMBAccess] Using IP from DnsCache: $resolvedIP"
                        }
                        # Source 3: Try to resolve via custom DNS
                        else {
                            $resolvedIP = Resolve-adPEASName -Name $smbServer
                            if ($resolvedIP) {
                                Write-Log "[Invoke-SMBAccess] Resolved server via custom DNS: $resolvedIP"
                            }
                        }

                        if ($resolvedIP) {
                            $smbServer = $resolvedIP
                            Write-Log "[Invoke-SMBAccess] SimpleBind+CustomDNS mode: Using IP address for SMB: $smbServer"
                        }
                        else {
                            Write-Log "[Invoke-SMBAccess] WARNING: Custom DNS configured but could not resolve $smbServer - SMB may fail"
                        }
                    }
                    else {
                        # SimpleBind without custom DNS - use hostname (system DNS works)
                        Write-Log "[Invoke-SMBAccess] SimpleBind mode: Using hostname for SMB: $smbServer"
                    }

                    $targetPath = "\\$smbServer\SYSVOL"
                    Write-Log "[Invoke-SMBAccess] Auto-detected SYSVOL path: $targetPath"
                } else {
                    $errorMsg = "No UNC path specified and cannot auto-detect SYSVOL (LDAPContext not available)"
                    Write-Log "[Invoke-SMBAccess] $errorMsg"

                    switch ($ErrorHandling) {
                        'Warn' { Write-Warning $errorMsg }
                        'Stop' { throw $errorMsg }
                    }

                    # Fallback: Execute without path context
                    return & $ScriptBlock
                }
            }
            else {
                # If UNC path is provided but contains a hostname and custom DNS is active, may need to resolve it but for Kerberos, we MUST keep the hostname for SPN matching!
                $kerberosUsed = $Script:LDAPContext -and $Script:LDAPContext['KerberosUsed']

                if (-not $kerberosUsed -and $Script:LDAPContext -and $Script:LDAPContext['DnsServer'] -and $UNCPath -match '^\\\\([^\\]+)\\') {
                    # SimpleBind with custom DNS - need to convert hostname to IP
                    $uncHost = $Matches[1]
                    # Check if it's not already an IP address
                    $ipTest = $null
                    if (-not [System.Net.IPAddress]::TryParse($uncHost, [ref]$ipTest)) {
                        # Try to resolve using cached IP or DNS lookup
                        $resolvedIP = $null

                        # Source 1: DnsCache (use lowercase key for case-insensitive lookup)
                        if ($Script:LDAPContext['DnsCache'] -and $Script:LDAPContext['DnsCache'].ContainsKey($uncHost.ToLower())) {
                            $resolvedIP = $Script:LDAPContext['DnsCache'][$uncHost.ToLower()]
                        }
                        # Source 2: ServerIP (if hostname matches server or domain, case-insensitive)
                        elseif ($Script:LDAPContext['ServerIP'] -and ($uncHost.ToLower() -eq $Script:LDAPContext.Server.ToLower() -or $uncHost.ToLower() -eq $Script:LDAPContext.Domain.ToLower())) {
                            $resolvedIP = $Script:LDAPContext['ServerIP']
                        }
                        # Source 3: Try to resolve via custom DNS
                        else {
                            $resolvedIP = Resolve-adPEASName -Name $uncHost
                        }

                        if ($resolvedIP) {
                            $targetPath = $UNCPath -replace "^\\\\[^\\]+\\", "\\$resolvedIP\"
                            Write-Log "[Invoke-SMBAccess] SimpleBind: Converted hostname to IP in UNC path: $uncHost -> $resolvedIP"
                        }
                    }
                }
                elseif ($kerberosUsed) {
                    # Kerberos - keep hostname as-is for SPN matching
                    Write-Log "[Invoke-SMBAccess] Kerberos: Keeping hostname in UNC path for SPN matching"
                }
            }

            # Check share access cache - skip if this share previously failed
            # Extract share root (\\server\share) for cache lookup
            $shareKey = $null
            if ($targetPath -match '^(\\\\[^\\]+\\[^\\]+)') {
                $shareKey = $Matches[1].ToLower()
            }
            if ($shareKey -and $Script:SMBShareAccessCache.ContainsKey($shareKey)) {
                $cachedError = $Script:SMBShareAccessCache[$shareKey]
                Write-Log "[Invoke-SMBAccess] SKIPPED (cached failure): $operationDesc - Share '$shareKey' previously failed: $cachedError"

                switch ($ErrorHandling) {
                    'Warn' { Write-Warning "SMB access skipped (previously failed): $cachedError"; return $null }
                    'Stop' { throw "SMB access skipped (previously failed): $cachedError" }
                    default { return $null }
                }
            }

            # Execute with PSDrive mounting (secure credential handling)
            $attempt = 0
            $success = $false
            $lastError = $null

            # Determine if we should use runspace for timeout control
            # For Kerberos sessions, we MUST NOT use runspace because:
            # 1. Runspace is an isolated execution context
            # 2. Kerberos tickets in LSA cache are per-logon-session but runspace doesn't inherit proper context
            # 3. Direct mount in main process uses the injected Kerberos ticket correctly
            $kerberosSession = $Script:LDAPContext -and $Script:LDAPContext['KerberosUsed']

            if ($kerberosSession) {
                Write-Log "[Invoke-SMBAccess] Kerberos session detected - using direct mount (no runspace) to preserve ticket context"
            }

            while (-not $success -and $attempt -le $RetryCount) {
                $attempt++

                if ($attempt -gt 1) {
                    Write-Log "[Invoke-SMBAccess] Retry attempt $attempt of $RetryCount"
                    Start-Sleep -Seconds 2
                }

                try {
                    # PSDrive mounting for secure credential handling
                    $driveName = "adPEAS_SMB_$(Get-Random -Minimum 1000 -Maximum 9999)"

                    Write-Log "[Invoke-SMBAccess] Mounting PSDrive: $targetPath as ${driveName}:"

                    if ($kerberosSession -or $credToUse) {
                        # Direct mount in main process for:
                        # 1. Kerberos sessions (preserve ticket context from LSA cache)
                        # 2. Sessions with explicit credentials (credential object works in main process)
                        try {
                            if ($credToUse) {
                                Write-Log "[Invoke-SMBAccess] Direct mount with credentials"
                                New-PSDrive -Name $driveName -PSProvider FileSystem -Root $targetPath -Credential $credToUse -Scope Script -ErrorAction Stop | Out-Null
                            } else {
                                # Kerberos - no credentials needed, ticket in LSA cache is used automatically
                                Write-Log "[Invoke-SMBAccess] Direct mount with Kerberos (ticket from LSA cache)"
                                New-PSDrive -Name $driveName -PSProvider FileSystem -Root $targetPath -Scope Script -ErrorAction Stop | Out-Null
                            }
                            $driveMounted = $true
                            Write-Log "[Invoke-SMBAccess] PSDrive mounted successfully (direct)"

                            # Execute scriptblock
                            & $ScriptBlock $targetPath
                            $success = $true
                        } catch {
                            throw $_.Exception.Message
                        }
                    } else {
                        # Use runspace for timeout control when no credentials and no Kerberos
                        # This is for current user context where we want timeout protection
                        try {
                            # Mount PSDrive with timeout using runspace
                            # Note: Runspace provides true timeout control for slow/unreachable SMB targets
                            $runspace = [runspacefactory]::CreateRunspace()
                            $runspace.Open()

                            $powershell = [powershell]::Create()
                            $powershell.Runspace = $runspace

                            # Build the script dynamically
                            $scriptText = @"
param(`$driveName, `$targetPath)
try {
    New-PSDrive -Name `$driveName -PSProvider FileSystem -Root `$targetPath -Scope Global -ErrorAction Stop | Out-Null
    return @{ Success = `$true; Error = `$null }
} catch {
    return @{ Success = `$false; Error = `$_.Exception.Message }
}
"@
                            $null = $powershell.AddScript($scriptText)
                            $null = $powershell.AddParameter('driveName', $driveName)
                            $null = $powershell.AddParameter('targetPath', $targetPath)

                            $asyncResult = $powershell.BeginInvoke()

                            # Wait with actual timeout
                            $timeoutMs = $Timeout * 1000
                            $completed = $asyncResult.AsyncWaitHandle.WaitOne($timeoutMs)

                            if ($completed) {
                                # Operation completed within timeout
                                $result = $powershell.EndInvoke($asyncResult)

                                if ($result -and $result.Success) {
                                    $driveMounted = $true
                                    Write-Log "[Invoke-SMBAccess] PSDrive mounted successfully (runspace)"

                                    # Execute scriptblock
                                    & $ScriptBlock $targetPath
                                } else {
                                    $errorMsg = if ($result -and $result.Error) { $result.Error } else { "Unknown error during PSDrive mount" }
                                    throw $errorMsg
                                }
                            } else {
                                # True timeout - operation did not complete
                                Write-Log "[Invoke-SMBAccess] PSDrive mount timeout after $Timeout seconds - aborting runspace"
                                throw "PSDrive mount timeout after $Timeout seconds (SMB connection could not be established)"
                            }
                        } finally {
                            # Cleanup runspace resources
                            if ($powershell) {
                                $powershell.Stop()
                                $powershell.Dispose()
                            }
                            if ($runspace) {
                                $runspace.Close()
                                $runspace.Dispose()
                            }
                        }

                        $success = $true
                    }

                } catch {
                    $lastError = $_
                    Write-Log "[Invoke-SMBAccess] Error on attempt ${attempt}: $_"

                    # Check if error is retryable using central error code module
                    $errorInfo = Get-ExceptionErrorInfo -Exception $_.Exception -Context "SMB"
                    Write-Log "[Invoke-SMBAccess] Error analysis: $($errorInfo.Name) - $($errorInfo.Message) (Retryable: $($errorInfo.IsRetryable))"

                    if (-not $errorInfo.IsRetryable -or $attempt -gt $RetryCount) {
                        # Non-retryable error or max retries reached
                        throw
                    }
                }
            }

            if (-not $success) {
                throw $lastError
            }

        } catch {
            $errorMsg = "SMB access failed: $_"
            Write-Log "[Invoke-SMBAccess] $errorMsg"

            # Cache the failed share to prevent repeated timeout attempts
            if ($shareKey) {
                $Script:SMBShareAccessCache[$shareKey] = [string]$_
                Write-Log "[Invoke-SMBAccess] Cached failed share: $shareKey"
            }

            switch ($ErrorHandling) {
                'Silent' {
                    Write-Log "[Invoke-SMBAccess] Error suppressed (Silent mode)"
                    return $null
                }
                'Warn' {
                    Write-Warning $errorMsg
                    return $null
                }
                'Stop' {
                    throw $errorMsg
                }
            }

        } finally {
            # Cleanup: Close any open progress bars left by the scriptblock (e.g., on exception)
            if ($Script:LastProgressUpdate -and $Script:LastProgressUpdate.Count -gt 0) {
                foreach ($activityKey in @($Script:LastProgressUpdate.Keys)) {
                    try { Write-Progress -Activity $activityKey -Completed } catch { }
                }
                $Script:LastProgressUpdate = @{}
            }

            # Cleanup: Remove PSDrive if mounted
            if ($driveMounted -and $driveName) {
                try {
                    Write-Log "[Invoke-SMBAccess] Removing PSDrive ${driveName}:"
                    Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
                } catch {
                    Write-Log "[Invoke-SMBAccess] Failed to remove PSDrive: $_"
                }
            }
        }
    }

    end {
        Write-Log "[Invoke-SMBAccess] Completed: $operationDesc"
    }
}
