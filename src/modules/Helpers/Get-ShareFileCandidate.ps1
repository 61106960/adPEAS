<#
.SYNOPSIS
    Walks one share for the files a credential scan should read, under hard limits.

.DESCRIPTION
    A file server is not SYSVOL. SYSVOL has a known shape and a few thousand files, and
    Get-CredentialExposure walks all of it; a share can hold millions of files, a recursive
    mount point, and folders the scanning account may not open. A walk without limits
    therefore has no upper bound on its running time, which is the one thing a scan over a
    whole domain cannot afford.

    So the walk is breadth-first and bounded four ways - depth, entries examined, elapsed
    time and file size - and every limit it reaches is reported rather than passed over in
    silence. A reader who is told "the walk stopped at 50000 entries" knows the share was
    not covered; a reader told nothing assumes it was.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function Test-SharePathReadable {
    <#
    .SYNOPSIS
    Tells whether a directory can be listed by the account this runs as.

    .DESCRIPTION
    Nothing is listed: the call that asks for the listing is what answers the question.
    Measured on .NET Framework 4.x, Directory.EnumerateFileSystemEntries opens the
    directory before it returns anything, and throws there - UnauthorizedAccessException
    for a directory the account may not open, DirectoryNotFoundException for one that is
    not there. Stepping the enumerator afterwards told nothing the call had not already
    said, which is why it is not done: over hundreds of shares, not listing is the point.

    An empty directory that can be listed is readable - having nothing to return is not an
    error.

    .PARAMETER Path
    The UNC path or local directory.

    .OUTPUTS
    PSCustomObject: Readable and Error ($null when readable).

    .EXAMPLE
    Test-SharePathReadable -Path '\\fs01\finance'

    .NOTES
    Internal helper function
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        [void][System.IO.Directory]::EnumerateFileSystemEntries($Path)
        return [PSCustomObject]@{ Readable = $true; Error = $null }
    } catch {
        # The error record is captured first, and the real exception taken out of it. Two
        # reasons, both of which made this read the wrong thing: PowerShell wraps an
        # exception from a .NET method in a MethodInvocationException, so the type to
        # switch on is the base exception and never the outer one; and inside a switch
        # body $_ is the value being switched on - the type name - not the error record,
        # so "$($_.Exception.Message)" came out empty.
        $errorRecord = $_
        $exception = $errorRecord.Exception.GetBaseException()
        $reason = switch ($exception.GetType().Name) {
            'UnauthorizedAccessException' { 'Access denied' }
            'DirectoryNotFoundException'  { 'Not found' }
            'IOException'                 { "Not reachable: $($exception.Message)" }
            default                       { $exception.Message }
        }
        Write-Log "[Test-SharePathReadable] $Path : $reason"
        return [PSCustomObject]@{ Readable = $false; Error = $reason }
    }
}

function Get-WalkClock {
    <#
    .SYNOPSIS
    The current time in UTC, as the walk reads it.

    .DESCRIPTION
    A seam of one line. The walk checks the clock in two places - once per directory and
    once every few hundred files - and the second is otherwise unreachable from a test: it
    needs a directory with hundreds of files AND a deadline that falls due while they are
    being counted, which no test can arrange deterministically. With the clock behind a
    function, a test says what time it is.

    .OUTPUTS
    [datetime] in UTC.

    .NOTES
    Internal helper function
    #>
    [CmdletBinding()]
    [OutputType([datetime])]
    param()

    return [DateTime]::UtcNow
}

function Get-ShareFileCandidate {
    <#
    .SYNOPSIS
    The files of one share that a credential scan should read, under hard limits.

    .DESCRIPTION
    A breadth-first walk from Path, returning the files whose extension or name is asked
    for. Breadth-first on purpose: the files that carry credentials on a share sit near the
    top - a script folder, a deployment share, an administrator's notes - and a
    depth-first walk spends its whole budget in the first branch it enters.

    Four limits, each reported when it is reached:

    - MaxDepth: how far below Path the walk goes. Path itself is depth 0.
    - MaxEntries: how many files it looks at, matching or not.
    - TimeoutSeconds: how long it may take.
    - MaxFileSizeKB: files above it are counted, not returned. A credential sits in a
      script or a configuration file, not in a 2 GB archive, and reading one such file
      costs more than the rest of the share together.

    A directory that cannot be listed is counted and skipped, not retried and not fatal:
    on a real share this is the normal case for a handful of folders and says nothing about
    the rest.

    .PARAMETER Path
    The share or directory to walk.

    .PARAMETER Extension
    Extensions and file names to return, as patterns ('*.txt') or plain names
    ('Registry.pol'). A pattern is matched by its extension, a name whole and without
    regard to case.

    .PARAMETER ExcludeDirectory
    Directory names to skip wherever they occur, with their subtree. Default: the Windows
    directories that hold no secret of their own and would otherwise take the whole budget
    on a share that is a system drive.

    .PARAMETER MaxDepth
    Default 5.

    .PARAMETER MaxEntries
    Default 50000.

    .PARAMETER TimeoutSeconds
    Default 120.

    .PARAMETER Deadline
    A point in time (UTC) to stop at, instead of TimeoutSeconds from now. What it is for is
    a budget shared across shares: a caller walking forty of them wants a limit on the whole
    pass, not forty independent ones. A deadline already past stops the walk before it
    looks at anything.

    .PARAMETER MaxFileSizeKB
    Default 1024.

    .OUTPUTS
    PSCustomObject:
    - Files: the candidates, as FileInfo
    - Examined: how many files were looked at
    - Directories: how many directories were listed
    - Denied: how many could not be listed
    - SkippedLarge: how many candidates were too large
    - Truncated: which limit stopped the walk, or $null if it finished

    .EXAMPLE
    Get-ShareFileCandidate -Path '\\fs01\finance' -Extension '*.ps1', '*.xml'

    .NOTES
    Internal helper function
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Extension,

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [string[]]$ExcludeDirectory = @(
            'Windows', 'WinSxS', 'Program Files', 'Program Files (x86)', 'ProgramData',
            '$Recycle.Bin', 'System Volume Information', 'Recovery', 'PerfLogs'
        ),

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 64)]
        [int]$MaxDepth = 5,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10000000)]
        [int]$MaxEntries = 50000,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 86400)]
        [int]$TimeoutSeconds = 120,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 1048576)]
        [int]$MaxFileSizeKB = 1024,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [Nullable[datetime]]$Deadline,

        # How often the clock is read inside one directory. Not every file: a directory of
        # a million files would otherwise read it a million times, and one of five would
        # read it at all only because the check before the directory already did.
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 100000)]
        [int]$ClockEvery = 512
    )

    # The two ways a file is asked for, separated once rather than per file: a pattern by
    # its extension, a plain name whole.
    $wanted = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $wantedName = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    # No guard for an empty or absent entry: it lands in the name set, where no file name
    # ever equals it, and -like short-circuits before StartsWith is reached.
    foreach ($one in @($Extension)) {
        if ($one -like '*.*' -and $one.StartsWith('*')) {
            [void]$wanted.Add($one.Substring(1))
        } else {
            [void]$wantedName.Add($one)
        }
    }
    $excluded = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($one in @($ExcludeDirectory)) { if ($one) { [void]$excluded.Add($one) } }

    $files = New-Object System.Collections.Generic.List[object]
    $examined = 0
    $directories = 0
    $denied = 0
    $skippedLarge = 0
    # Two different things, which one variable used to conflate: a limit that STOPPED the
    # walk (time, entries) and one that only left something out of it (depth). Setting the
    # stop flag for the depth limit abandoned the rest of the level being walked.
    $truncated = $null
    $depthLimited = $false
    $maxBytes = [long]$MaxFileSizeKB * 1024
    $stopAt = if ($PSBoundParameters.ContainsKey('Deadline') -and $null -ne $Deadline) { [datetime]$Deadline } else { (Get-WalkClock).AddSeconds($TimeoutSeconds) }

    # Breadth-first: the current level, then the one below it.
    $level = New-Object System.Collections.Generic.List[string]
    $level.Add($Path)
    $depth = 0

    # The deadline is checked before the first directory as well, so a budget that is
    # already spent stops the walk rather than costing one more share.
    while ($level.Count -gt 0 -and -not $truncated) {
        $next = New-Object System.Collections.Generic.List[string]

        foreach ($directory in $level) {
            if ((Get-WalkClock) -gt $stopAt) { $truncated = 'the time limit'; break }

            # Files of this directory. A directory that cannot be listed throws on the
            # first step of the enumerator, which is why the whole loop is in the try.
            #
            # Counted once per directory, whichever of the two listings below fails: for a
            # directory that cannot be opened at all both do, and Denied was twice the
            # number of directories the walk had missed.
            $listingFailed = $false
            try {
                $directories++
                foreach ($file in [System.IO.Directory]::EnumerateFiles($directory)) {
                    $examined++
                    if ($examined -ge $MaxEntries) { $truncated = "the limit of $MaxEntries file(s)"; break }
                    if (($examined % $ClockEvery) -eq 0 -and (Get-WalkClock) -gt $stopAt) { $truncated = 'the time limit'; break }

                    $info = $null
                    try { $info = New-Object System.IO.FileInfo $file } catch { continue }
                    if (-not ($wanted.Contains($info.Extension) -or $wantedName.Contains($info.Name))) { continue }
                    if ($info.Length -gt $maxBytes) { $skippedLarge++; continue }
                    $files.Add($info)
                }
            } catch {
                $denied++
                $listingFailed = $true
                Write-Log "[Get-ShareFileCandidate] $directory could not be listed: $($_.Exception.Message)"
            }
            if ($truncated) { break }

            # The level below, unless this is as deep as the walk goes.
            if ($depth -lt $MaxDepth) {
                try {
                    foreach ($child in [System.IO.Directory]::EnumerateDirectories($directory)) {
                        $leaf = [System.IO.Path]::GetFileName($child)
                        if ($excluded.Contains($leaf)) { continue }
                        # A reparse point is where a walk starts going in circles - a
                        # junction back to the root of the same share - and following one
                        # adds nothing that is not reachable without it.
                        $attributes = [System.IO.FileAttributes]0
                        try { $attributes = [System.IO.File]::GetAttributes($child) } catch { }
                        if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                            Write-Log "[Get-ShareFileCandidate] $child is a reparse point - not followed"
                            continue
                        }
                        $next.Add($child)
                    }
                } catch {
                    if (-not $listingFailed) { $denied++ }
                    Write-Log "[Get-ShareFileCandidate] The subdirectories of $directory could not be listed: $($_.Exception.Message)"
                }
            } elseif (-not $depthLimited) {
                # Only where there is something below to leave out, and asked once: the
                # walk goes on either way, so this is a note and not a stop.
                try {
                    if (@([System.IO.Directory]::EnumerateDirectories($directory) | Select-Object -First 1).Count -gt 0) { $depthLimited = $true }
                } catch { }
            }
        }

        $level = $next
        $depth++
    }

    # A hard limit is reported over the depth, because it says less was covered.
    if (-not $truncated -and $depthLimited) { $truncated = "the depth limit of $MaxDepth" }

    return [PSCustomObject]@{
        Files        = $files.ToArray()
        Examined     = $examined
        Directories  = $directories
        Denied       = $denied
        SkippedLarge = $skippedLarge
        Truncated    = $truncated
    }
}
