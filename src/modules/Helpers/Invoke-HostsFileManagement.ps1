<#
.SYNOPSIS
    Manages Windows hosts file entries for adPEAS DNS resolution.

.DESCRIPTION
    Provides functions to add and remove entries from the Windows hosts file.
    This is useful when:
    - System DNS cannot resolve target AD hostnames
    - Custom DNS server is specified but Kerberos/SMB needs system-level resolution
    - Non-domain-joined system accessing AD over VPN

    IMPORTANT: Requires Administrator privileges to modify hosts file!

    The hosts file is located at: C:\Windows\System32\drivers\etc\hosts
    Entries are marked with a comment tag for cleanup.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

# Marker comment for adPEAS hosts entries (for cleanup)
$Script:HostsFileMarker = "# adPEAS-managed entry"

# Mutex name for cross-process synchronization when modifying hosts file
# Uses Global\ prefix to work across all sessions on the system
$Script:HostsFileMutexName = "Global\adPEAS_HostsFile_Mutex"

# Default mutex timeout in milliseconds (5 seconds)
$Script:HostsFileMutexTimeoutMs = 5000

# Regex pattern for IP addresses (IPv4 and IPv6)
# IPv4: 192.168.1.1
# IPv6: ::1, fe80::1, 2001:db8::1, etc.
$Script:IPAddressPattern = '(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?::[0-9a-fA-F]{1,4}){1,7}|::(?:[fF]{4}:)?(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'

<#
.SYNOPSIS
    Tests if the current session has Administrator privileges.

.DESCRIPTION
    Quick check to determine if hosts file modification is possible.

.OUTPUTS
    $true if running as Administrator, $false otherwise.
#>
function Test-adPEASAdminPrivileges {
    [CmdletBinding()]
    param()

    process {
        return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}

<#
.SYNOPSIS
    Validates a hostname format.

.DESCRIPTION
    Checks if a hostname is valid according to RFC 1123.
    Valid hostnames:
    - Contain only alphanumeric characters, hyphens, and dots
    - Each label is 1-63 characters
    - Total length is max 253 characters
    - Labels don't start or end with hyphens

.PARAMETER Hostname
    The hostname to validate.

.OUTPUTS
    $true if valid, $false otherwise.
#>
function Test-ValidHostname {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Hostname
    )

    process {
        # Check total length
        if ($Hostname.Length -gt 253 -or $Hostname.Length -eq 0) {
            return $false
        }

        # Split into labels and validate each
        $labels = $Hostname.Split('.')
        foreach ($label in $labels) {
            # Each label must be 1-63 characters
            if ($label.Length -eq 0 -or $label.Length -gt 63) {
                return $false
            }
            # Labels must not start or end with hyphen
            if ($label.StartsWith('-') -or $label.EndsWith('-')) {
                return $false
            }
            # Labels must contain only alphanumeric and hyphens
            if ($label -notmatch '^[a-zA-Z0-9-]+$') {
                return $false
            }
        }

        return $true
    }
}

<#
.SYNOPSIS
    Executes a scriptblock with hosts file locking and retry logic.

.DESCRIPTION
    Internal helper function that handles:
    - Mutex acquisition for cross-process synchronization
    - File locking with retry logic
    - Proper resource cleanup

.PARAMETER ScriptBlock
    The scriptblock to execute. Receives $fileStream as parameter.

.PARAMETER TimeoutMs
    Mutex timeout in milliseconds.

.PARAMETER ReadOnly
    If true, opens file for read-only access with shared read.

.OUTPUTS
    Returns whatever the scriptblock returns.
#>
function Invoke-WithHostsFileLock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory=$false)]
        [int]$TimeoutMs = $Script:HostsFileMutexTimeoutMs,

        [Parameter(Mandatory=$false)]
        [switch]$ReadOnly
    )

    process {
        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        $mutex = $null
        $mutexAcquired = $false
        $fileStream = $null

        try {
            # Create or open system-wide mutex
            $mutex = New-Object System.Threading.Mutex($false, $Script:HostsFileMutexName)

            # Wait to acquire mutex
            $mutexAcquired = $mutex.WaitOne($TimeoutMs)

            if (-not $mutexAcquired) {
                throw "Timeout waiting for hosts file lock (another instance may be modifying it)"
            }

            # Retry logic for file locking issues (other non-adPEAS processes)
            $maxRetries = 3
            $retryDelayMs = 100
            $lastException = $null

            for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
                try {
                    if ($ReadOnly) {
                        # Open for reading with shared read access
                        $fileStream = [System.IO.File]::Open(
                            $hostsPath,
                            [System.IO.FileMode]::Open,
                            [System.IO.FileAccess]::Read,
                            [System.IO.FileShare]::Read
                        )
                    }
                    else {
                        # Open with exclusive access for writing
                        $fileStream = [System.IO.File]::Open(
                            $hostsPath,
                            [System.IO.FileMode]::Open,
                            [System.IO.FileAccess]::ReadWrite,
                            [System.IO.FileShare]::None
                        )
                    }

                    # Execute the scriptblock with the filestream
                    $result = & $ScriptBlock $fileStream
                    return $result
                }
                catch [System.IO.IOException] {
                    $lastException = $_
                    # File is locked by another process, retry after delay
                    if ($attempt -lt $maxRetries) {
                        Write-Log "[Invoke-WithHostsFileLock] File locked, retry $attempt of $maxRetries in ${retryDelayMs}ms..."
                        Start-Sleep -Milliseconds $retryDelayMs
                        $retryDelayMs = $retryDelayMs * 2  # Exponential backoff
                    }
                }
                finally {
                    if ($fileStream) {
                        try { $fileStream.Dispose() } catch { }
                        $fileStream = $null
                    }
                }
            }

            # All retries exhausted
            throw "Failed to access hosts file after $maxRetries attempts (file locked): $($lastException.Exception.Message)"
        }
        finally {
            # Always release mutex
            if ($mutexAcquired -and $mutex) {
                try { $mutex.ReleaseMutex() } catch { }
            }
            if ($mutex) {
                try { $mutex.Dispose() } catch { }
            }
        }
    }
}

<#
.SYNOPSIS
    Adds an entry to the Windows hosts file.

.DESCRIPTION
    Adds a hostname-to-IP mapping to the Windows hosts file.
    Requires Administrator privileges.
    Entries are marked with a comment for later cleanup.

.PARAMETER IPAddress
    The IP address to map to (IPv4 or IPv6).

.PARAMETER Hostname
    The hostname to add (e.g., "dc01.contoso.com").

.PARAMETER Force
    Overwrite existing entry if present.

.EXAMPLE
    Add-adPEASHostsEntry -IPAddress "10.10.10.5" -Hostname "dc01.contoso.com"

.EXAMPLE
    Add-adPEASHostsEntry -IPAddress "::1" -Hostname "localhost6"

.OUTPUTS
    [PSCustomObject] with Success, Message, and RequiresElevation properties.
#>
function Add-adPEASHostsEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$IPAddress,

        [Parameter(Mandatory=$true)]
        [string]$Hostname,

        [Parameter(Mandatory=$false)]
        [switch]$Force
    )

    process {
        $Result = [PSCustomObject]@{
            Success = $false
            Message = ""
            RequiresElevation = $false
            Entry = ""
        }

        $entry = "$IPAddress`t$Hostname`t$Script:HostsFileMarker"

        # Validate IP address (IPv4 or IPv6)
        $ip = $null
        if (-not [System.Net.IPAddress]::TryParse($IPAddress, [ref]$ip)) {
            $Result.Message = "Invalid IP address format: $IPAddress"
            Write-Warning "[Add-adPEASHostsEntry] $($Result.Message)"
            return $Result
        }

        # Validate hostname format
        if (-not (Test-ValidHostname -Hostname $Hostname)) {
            $Result.Message = "Invalid hostname format: $Hostname (must be valid RFC 1123 hostname)"
            Write-Warning "[Add-adPEASHostsEntry] $($Result.Message)"
            return $Result
        }

        # Check if running as Administrator
        if (-not (Test-adPEASAdminPrivileges)) {
            $Result.RequiresElevation = $true
            $Result.Message = "Administrator privileges required to modify hosts file"
            Write-Warning "[Add-adPEASHostsEntry] $($Result.Message)"
            return $Result
        }

        try {
            $Result = Invoke-WithHostsFileLock -ScriptBlock {
                param($fileStream)

                $innerResult = [PSCustomObject]@{
                    Success = $false
                    Message = ""
                    RequiresElevation = $false
                    Entry = ""
                }

                $streamReader = $null
                $streamWriter = $null

                try {
                    # Read all content
                    $streamReader = New-Object System.IO.StreamReader($fileStream, [System.Text.Encoding]::ASCII, $true, 4096, $true)
                    $fullContent = $streamReader.ReadToEnd()
                    $hostsContent = @($fullContent -split "`r?`n")

                    # Check if entry already exists (IPv4 or IPv6 pattern)
                    $escapedHostname = [regex]::Escape($Hostname)
                    $existingEntry = $hostsContent | Where-Object { $_ -match "^\s*($Script:IPAddressPattern)\s+$escapedHostname\s*" }

                    if ($existingEntry -and -not $Force) {
                        $innerResult.Message = "Entry for $Hostname already exists. Use -Force to overwrite."
                        Write-Log "[Add-adPEASHostsEntry] $($innerResult.Message)"
                        $innerResult.Success = $true  # Not an error, just already exists
                        return $innerResult
                    }

                    if ($existingEntry -and $Force) {
                        # Remove existing entry
                        $hostsContent = @($hostsContent | Where-Object { $_ -notmatch "^\s*($Script:IPAddressPattern)\s+$escapedHostname\s*" })
                        Write-Log "[Add-adPEASHostsEntry] Removed existing entry for $Hostname"
                    }

                    # Add new entry
                    $hostsContent += $entry

                    # Close reader before writing (releases internal buffer reference)
                    $streamReader.Dispose()
                    $streamReader = $null

                    # Reset stream for writing
                    $fileStream.SetLength(0)
                    $fileStream.Position = 0

                    # Write back to hosts file with trailing newline
                    $streamWriter = New-Object System.IO.StreamWriter($fileStream, [System.Text.Encoding]::ASCII, 4096, $true)
                    $streamWriter.Write(($hostsContent -join "`r`n"))
                    $streamWriter.Write("`r`n")  # Trailing newline
                    $streamWriter.Flush()

                    $innerResult.Success = $true
                    $innerResult.Entry = $entry
                    $innerResult.Message = "Added hosts entry: $IPAddress -> $Hostname"
                    Write-Log "[Add-adPEASHostsEntry] $($innerResult.Message)"

                    return $innerResult
                }
                finally {
                    if ($streamWriter) { try { $streamWriter.Dispose() } catch { } }
                    if ($streamReader) { try { $streamReader.Dispose() } catch { } }
                }
            }

            # Track the entry in LDAPContext for cleanup (only if successful)
            if ($Result.Success -and $Result.Entry) {
                if (-not $Script:LDAPContext) {
                    $Script:LDAPContext = @{}
                }
                if (-not $Script:LDAPContext['HostsEntries']) {
                    $Script:LDAPContext['HostsEntries'] = @()
                }
                $Script:LDAPContext['HostsEntries'] += $Hostname
            }

            return $Result
        }
        catch {
            $Result.Message = "Failed to modify hosts file: $_"
            Write-Warning "[Add-adPEASHostsEntry] $($Result.Message)"
            return $Result
        }
    }
}

<#
.SYNOPSIS
    Removes adPEAS-managed entries from the Windows hosts file.

.DESCRIPTION
    Removes hostname entries that were added by adPEAS.
    Can remove a specific hostname or all adPEAS-managed entries.
    Requires Administrator privileges.

.PARAMETER Hostname
    Optional. Specific hostname to remove.
    If not specified, removes ALL adPEAS-managed entries.

.PARAMETER All
    Remove all adPEAS-managed entries (marked with the adPEAS comment).

.EXAMPLE
    Remove-adPEASHostsEntry -Hostname "dc01.contoso.com"
    Removes the specific entry.

.EXAMPLE
    Remove-adPEASHostsEntry -All
    Removes all adPEAS-managed entries.

.OUTPUTS
    [PSCustomObject] with Success, Message, RemovedCount, and RequiresElevation properties.
#>
function Remove-adPEASHostsEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Hostname,

        [Parameter(Mandatory=$false)]
        [switch]$All
    )

    process {
        $Result = [PSCustomObject]@{
            Success = $false
            Message = ""
            RemovedCount = 0
            RequiresElevation = $false
        }

        # Check if running as Administrator
        if (-not (Test-adPEASAdminPrivileges)) {
            $Result.RequiresElevation = $true
            $Result.Message = "Administrator privileges required to modify hosts file"
            Write-Warning "[Remove-adPEASHostsEntry] $($Result.Message)"
            return $Result
        }

        # Check if there's anything to remove (early exit for tracked entries)
        if (-not $All -and -not $Hostname) {
            if (-not $Script:LDAPContext -or -not $Script:LDAPContext['HostsEntries'] -or $Script:LDAPContext['HostsEntries'].Count -eq 0) {
                $Result.Message = "No entries to remove (no tracked entries and no -Hostname/-All specified)"
                $Result.Success = $true
                return $Result
            }
        }

        try {
            $Result = Invoke-WithHostsFileLock -ScriptBlock {
                param($fileStream)

                $innerResult = [PSCustomObject]@{
                    Success = $false
                    Message = ""
                    RemovedCount = 0
                    RequiresElevation = $false
                }

                $streamReader = $null
                $streamWriter = $null

                try {
                    # Read all content
                    $streamReader = New-Object System.IO.StreamReader($fileStream, [System.Text.Encoding]::ASCII, $true, 4096, $true)
                    $fullContent = $streamReader.ReadToEnd()
                    $hostsContent = @($fullContent -split "`r?`n")
                    $originalCount = $hostsContent.Count

                    if ($All) {
                        # Remove all adPEAS-managed entries
                        $hostsContent = @($hostsContent | Where-Object { $_ -notmatch [regex]::Escape($Script:HostsFileMarker) })
                        $innerResult.RemovedCount = $originalCount - $hostsContent.Count
                        $innerResult.Message = "Removed $($innerResult.RemovedCount) adPEAS-managed entries"
                    }
                    elseif ($Hostname) {
                        # Remove specific hostname (supports IPv4 and IPv6)
                        $escapedHostname = [regex]::Escape($Hostname)
                        $escapedMarker = [regex]::Escape($Script:HostsFileMarker)
                        $pattern = "^\s*($Script:IPAddressPattern)\s+$escapedHostname\s*.*$escapedMarker"
                        $hostsContent = @($hostsContent | Where-Object { $_ -notmatch $pattern })
                        $innerResult.RemovedCount = $originalCount - $hostsContent.Count
                        $innerResult.Message = "Removed entry for $Hostname"
                    }
                    else {
                        # Remove entries tracked in LDAPContext
                        foreach ($trackedHost in $Script:LDAPContext['HostsEntries']) {
                            $escapedHostname = [regex]::Escape($trackedHost)
                            $pattern = "^\s*($Script:IPAddressPattern)\s+$escapedHostname\s*"
                            $hostsContent = @($hostsContent | Where-Object { $_ -notmatch $pattern })
                        }
                        $innerResult.RemovedCount = $originalCount - $hostsContent.Count
                        $Script:LDAPContext['HostsEntries'] = @()
                        $innerResult.Message = "Removed $($innerResult.RemovedCount) tracked entries"
                    }

                    # Write back to hosts file if changes were made
                    if ($innerResult.RemovedCount -gt 0) {
                        # Close reader before writing
                        $streamReader.Dispose()
                        $streamReader = $null

                        # Reset stream for writing
                        $fileStream.SetLength(0)
                        $fileStream.Position = 0

                        $streamWriter = New-Object System.IO.StreamWriter($fileStream, [System.Text.Encoding]::ASCII, 4096, $true)
                        $streamWriter.Write(($hostsContent -join "`r`n"))
                        $streamWriter.Write("`r`n")  # Trailing newline
                        $streamWriter.Flush()
                    }

                    $innerResult.Success = $true
                    Write-Log "[Remove-adPEASHostsEntry] $($innerResult.Message)"
                    return $innerResult
                }
                finally {
                    if ($streamWriter) { try { $streamWriter.Dispose() } catch { } }
                    if ($streamReader) { try { $streamReader.Dispose() } catch { } }
                }
            }

            return $Result
        }
        catch {
            $Result.Message = "Failed to modify hosts file: $_"
            Write-Warning "[Remove-adPEASHostsEntry] $($Result.Message)"
            return $Result
        }
    }
}

<#
.SYNOPSIS
    Shows current adPEAS-managed hosts entries.

.DESCRIPTION
    Lists all hosts file entries that were added by adPEAS.

.OUTPUTS
    Array of PSCustomObjects with IPAddress, Hostname, and Line properties.
#>
function Get-adPEASHostsEntries {
    [CmdletBinding()]
    param()

    process {
        try {
            $entries = Invoke-WithHostsFileLock -ReadOnly -ScriptBlock {
                param($fileStream)

                $result = @()
                $streamReader = $null

                try {
                    $streamReader = New-Object System.IO.StreamReader($fileStream, [System.Text.Encoding]::ASCII, $true, 4096, $true)
                    $fullContent = $streamReader.ReadToEnd()
                    $hostsContent = @($fullContent -split "`r?`n")

                    foreach ($line in $hostsContent) {
                        if ($line -match [regex]::Escape($Script:HostsFileMarker)) {
                            # Match IPv4 or IPv6 address followed by hostname
                            if ($line -match "^\s*($Script:IPAddressPattern)\s+(\S+)\s*") {
                                $result += [PSCustomObject]@{
                                    IPAddress = $Matches[1]
                                    Hostname = $Matches[2]
                                    Line = $line
                                }
                            }
                        }
                    }

                    return $result
                }
                finally {
                    if ($streamReader) { try { $streamReader.Dispose() } catch { } }
                }
            }

            return $entries
        }
        catch {
            Write-Warning "[Get-adPEASHostsEntries] Failed to read hosts file: $_"
            return @()
        }
    }
}
