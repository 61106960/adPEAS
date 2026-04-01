<#
.SYNOPSIS
    Unified logging function that outputs to console and optionally to file.

.DESCRIPTION
    Write-Log provides a centralized logging mechanism that:
    - Outputs to console using appropriate PowerShell cmdlets (Write-Verbose, Write-Debug, etc.)
    - Optionally writes to a log file when $Script:adPEAS_Outputfile is set AND $Script:adPEAS_VerboseLogging is enabled
    - Adds timestamps to file output for troubleshooting
    - Respects PowerShell preference variables ($VerbosePreference, $DebugPreference, etc.)

    This function is a drop-in replacement for Write-Verbose that also writes to the output file.

.PARAMETER Message
    The log message to output.

.PARAMETER Level
    The severity level of the message:
    - Info: General information (Write-Host)
    - Verbose: Detailed information (Write-Verbose) - DEFAULT
    - Debug: Debug information (Write-Debug)
    - Warning: Warning messages (Write-Warning)
    - Error: Error messages (Write-Warning with [ERROR] prefix)

.EXAMPLE
    Write-Log "[Get-DomainUser] Querying users..."
    # Equivalent to Write-Verbose, but also writes to file if VerboseLogging enabled

.EXAMPLE
    Write-Log -Message "Connection established" -Level Info

.EXAMPLE
    Write-Log -Message "Invalid parameter" -Level Warning

.NOTES
    Author: Alexander Sturz (@_61106960_)

    File output is only active when BOTH conditions are met:
    1. $Script:adPEAS_Outputfile is set (via -Outputfile parameter)
    2. $Script:adPEAS_VerboseLogging is $true (via -VerboseLogging parameter)

    The file output includes timestamps for each entry in format:
    yyyy-MM-dd HH:mm:ss [Level] Message
#>

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Verbose', 'Debug', 'Warning', 'Error')]
        [string]$Level = 'Verbose'
    )

    # Console output (respects PowerShell preference variables)
    switch ($Level) {
        'Verbose' { Write-Verbose $Message }
        'Debug'   { Write-Debug $Message }
        'Warning' { Write-Warning $Message }
        'Error'   { Write-Warning $Message }
        default   { Write-Host $Message }
    }

    # File output (only if Outputfile is active AND VerboseLogging is enabled)
    if ($Script:adPEAS_Outputfile -and $Script:adPEAS_VerboseLogging) {
        try {
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            "$timestamp [$Level] $Message" | Add-Content -Path $Script:adPEAS_Outputfile -ErrorAction SilentlyContinue
        }
        catch {
            # Silently ignore file write errors to not disrupt main operations
        }
    }
}
