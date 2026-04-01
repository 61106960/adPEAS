<#
.SYNOPSIS
    Central Software Lifecycle definitions for adPEAS.

.DESCRIPTION
    This file serves as the Single Source of Truth for software End-of-Life dates.
    Used by Check modules and severity classification (Get-AttributeSeverity).

    Supported Software:
    - Windows Client Operating Systems
    - Windows Server Operating Systems
    - Microsoft Exchange Server

.NOTES
    Author: Alexander Sturz (@_61106960_)
    References:
    - Windows: https://learn.microsoft.com/en-us/lifecycle/products/
    - Exchange: https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates

    How to add new software:
    1. Add entry to appropriate $Script:*Lifecycle hashtable below
    2. Add normalization pattern to Get-Normalized*Name function if needed
    3. Update regex patterns in AttributeTransformers.ps1 (Get-AttributeSeverity) if needed for severity classification
#>

# =============================================================================
# WINDOWS LIFECYCLE DATA
# =============================================================================
# Key = Normalized OS name (as returned by Get-NormalizedOSName)
# Value = End-of-Support date (extended support end, not mainstream)
#
# Note: Dates are when ALL support ends (including ESU where applicable)

$Script:WindowsLifecycle = @{
    # ===== Windows Client =====
    'Windows XP'           = '2014-04-08'   # Extended support ended
    'Windows Vista'        = '2017-04-11'   # Extended support ended
    'Windows 7'            = '2023-01-10'   # ESU Year 3 ended (was 2020-01-14 without ESU)
    'Windows 8'            = '2016-01-12'   # No extended support (upgrade to 8.1 required)
    'Windows 8.1'          = '2023-01-10'   # Extended support ended
    'Windows 10'           = '2025-10-14'   # End of support for non-LTSC (final SAC version)

    # Windows 10 LTSC editions have extended support lifecycles
    # Identified by "LTSC" in operatingSystem AND build number in operatingSystemVersion
    'Windows 10 LTSC 2015' = '2025-10-14'   # Build 10240 (version 1507)
    'Windows 10 LTSC 2016' = '2026-10-13'   # Build 14393 (version 1607)
    'Windows 10 LTSC 2019' = '2029-01-09'   # Build 17763 (version 1809)
    'Windows 10 LTSC 2021' = '2027-01-12'   # Build 19044 (version 21H2)

    # ===== Windows Server =====
    'Windows Server 2003'    = '2015-07-14'   # Extended support ended
    'Windows Server 2008'    = '2023-01-10'   # ESU Year 3 ended (was 2020-01-14 without ESU)
    'Windows Server 2008 R2' = '2023-01-10'   # ESU Year 3 ended (was 2020-01-14 without ESU)
    'Windows Server 2012'    = '2026-10-13'   # ESU Year 3 ends (was 2023-10-10 without ESU)
    'Windows Server 2012 R2' = '2026-10-13'   # ESU Year 3 ends (was 2023-10-10 without ESU)
    'Windows Server 2016'    = '2027-01-12'   # Extended support ends

    # ===== Currently Supported (no EOL date yet or far future) =====
    # Windows 11           - Support ongoing (version-dependent)
    # Windows Server 2019  - Extended support: 2029-01-09
    # Windows Server 2022  - Extended support: 2031-10-14
    # Windows Server 2025  - Extended support: TBD
}

# =============================================================================
# EXCHANGE LIFECYCLE DATA
# =============================================================================
# Key = Normalized Exchange version (as returned by Get-NormalizedExchangeVersion)
# Value = Hashtable with EOLDate and optional metadata
#
# Exchange versions are identified by:
# - Version string from msExchVersion attribute
# - Build number prefix (e.g., "15.1" for Exchange 2016)
# - Product name from HTTP detection

$Script:ExchangeLifecycle = @{
    # ===== End-of-Life Versions =====
    # Severity values match Show-Line system: Finding (red), Hint (yellow), Note (green), Secure (highlight)
    'Exchange 2007' = @{
        EOLDate = '2017-04-11'
        BuildPrefix = '8.'
        Severity = 'Finding'      # EOL - critical security risk
    }
    'Exchange 2010' = @{
        EOLDate = '2020-10-13'
        BuildPrefix = '14.'
        Severity = 'Finding'      # EOL - critical security risk
    }
    'Exchange 2013' = @{
        EOLDate = '2023-04-11'
        BuildPrefix = '15.0.'
        Severity = 'Finding'      # EOL - critical security risk
    }
    'Exchange 2016' = @{
        EOLDate = '2025-10-14'
        BuildPrefix = '15.1.'
        Severity = 'Finding'      # EOL October 2025 - upgrade urgently recommended
    }
    'Exchange 2019' = @{
        EOLDate = '2025-10-14'
        BuildPrefix = '15.2.'
        BuildMax = 2561           # Builds below 2562 are Exchange 2019 (CU15 = 15.2.1748.x)
        Severity = 'Hint'         # EOL October 2025 - upgrade to SE recommended
    }

    # ===== Currently Supported =====
    'Exchange SE' = @{
        EOLDate = $null           # Currently supported
        BuildPrefix = '15.2.'
        BuildMin = 2562           # Builds 2562+ are Exchange SE (SE RTM = 15.2.2562.17)
        Severity = 'Standard'     # Current supported version
    }
}

# =============================================================================
# WINDOWS OS NAME NORMALIZATION
# =============================================================================
<#
.SYNOPSIS
    Normalizes an OS name from AD to a lifecycle lookup key.

.DESCRIPTION
    AD stores OS names with version details (e.g., "Windows Server 2019 Datacenter").
    This function extracts the base OS name for lifecycle lookup.

    For Windows 10 LTSC editions, the build number from operatingSystemVersion is used
    to determine the specific LTSC release (2015/2016/2019/2021) since each has a
    different extended support end date.

.PARAMETER OSName
    The operatingSystem attribute value from AD.

.PARAMETER OSVersion
    The operatingSystemVersion attribute from AD (e.g., "10.0 (17763)").
    Required for correct Windows 10 LTSC identification.

.OUTPUTS
    String - Normalized OS name matching $Script:WindowsLifecycle keys.

.EXAMPLE
    Get-NormalizedOSName -OSName "Windows Server 2012 R2 Standard"
    # Returns: "Windows Server 2012 R2"

.EXAMPLE
    Get-NormalizedOSName -OSName "Windows 10 Enterprise LTSC" -OSVersion "10.0 (17763)"
    # Returns: "Windows 10 LTSC 2019"
#>
function Get-NormalizedOSName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OSName,

        [Parameter(Mandatory=$false)]
        [string]$OSVersion
    )

    # Normalize OS name for lifecycle lookup
    switch -Regex ($OSName) {
        # Windows Client - order matters (8.1 before 8)
        '^Windows XP'               { return 'Windows XP' }
        '^Windows Vista'            { return 'Windows Vista' }
        '^Windows 7'                { return 'Windows 7' }
        '^Windows 8\.1'             { return 'Windows 8.1' }
        '^Windows 8[^.]'            { return 'Windows 8' }
        '^Windows 10' {
            # Check for LTSC editions (have much longer support than SAC)
            if ($OSName -match 'LTSC') {
                # Map build number to LTSC release year
                $buildNumber = 0
                if ($OSVersion -match '\((\d+)\)') {
                    $buildNumber = [int]$Matches[1]
                }
                # LTSC 2019: Build 17763 (version 1809) - EOL 2029-01-09
                if ($buildNumber -ge 17763 -and $buildNumber -lt 19044) { return 'Windows 10 LTSC 2019' }
                # LTSC 2021: Build 19044 (version 21H2) - EOL 2027-01-12
                if ($buildNumber -ge 19044) { return 'Windows 10 LTSC 2021' }
                # LTSC 2016: Build 14393 (version 1607) - EOL 2026-10-13
                if ($buildNumber -ge 14393 -and $buildNumber -lt 17763) { return 'Windows 10 LTSC 2016' }
                # LTSC 2015: Build 10240 (version 1507) - EOL 2025-10-14
                if ($buildNumber -ge 10240 -and $buildNumber -lt 14393) { return 'Windows 10 LTSC 2015' }
                # Unknown LTSC build - fall through to generic Windows 10
            }
            return 'Windows 10'
        }
        '^Windows 11'               { return 'Windows 11' }

        # Windows Server - order matters (R2 before base version)
        '^Windows Server 2003'      { return 'Windows Server 2003' }
        '^Windows Server 2008 R2'   { return 'Windows Server 2008 R2' }
        '^Windows Server 2008'      { return 'Windows Server 2008' }
        '^Windows Server 2012 R2'   { return 'Windows Server 2012 R2' }
        '^Windows Server 2012'      { return 'Windows Server 2012' }
        '^Windows Server 2016'      { return 'Windows Server 2016' }
        '^Windows Server 2019'      { return 'Windows Server 2019' }
        '^Windows Server 2022'      { return 'Windows Server 2022' }
        '^Windows Server 2025'      { return 'Windows Server 2025' }

        # Default: return as-is (for unknown OS types)
        default                     { return $OSName }
    }
}

# =============================================================================
# EXCHANGE VERSION NORMALIZATION
# =============================================================================
<#
.SYNOPSIS
    Normalizes an Exchange version/build to a lifecycle lookup key.

.DESCRIPTION
    Exchange versions can be identified by build numbers (e.g., "15.1.2507.27") or product names.
    This function normalizes to a lifecycle key.

.PARAMETER BuildNumber
    The Exchange build number (e.g., "15.1.2507.27" or "15.2.1544.11").

.PARAMETER ProductName
    The Exchange product name (e.g., "Exchange 2016", "Microsoft Exchange Server 2019").

.OUTPUTS
    String - Normalized Exchange version matching $Script:ExchangeLifecycle keys.

.EXAMPLE
    Get-NormalizedExchangeVersion -BuildNumber "15.1.2507.27"
    # Returns: "Exchange 2016"

.EXAMPLE
    Get-NormalizedExchangeVersion -BuildNumber "15.2.2562.1"
    # Returns: "Exchange SE"
#>
function Get-NormalizedExchangeVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$BuildNumber,

        [Parameter(Mandatory=$false)]
        [string]$ProductName
    )

    # Try build number first (most reliable)
    if (-not [string]::IsNullOrEmpty($BuildNumber)) {
        # Exchange 2007: 8.x
        if ($BuildNumber -match '^8\.') {
            return 'Exchange 2007'
        }
        # Exchange 2010: 14.x
        if ($BuildNumber -match '^14\.') {
            return 'Exchange 2010'
        }
        # Exchange 2013: 15.0.x
        if ($BuildNumber -match '^15\.0\.') {
            return 'Exchange 2013'
        }
        # Exchange 2016: 15.1.x
        if ($BuildNumber -match '^15\.1\.') {
            return 'Exchange 2016'
        }
        # Exchange 2019 vs SE: 15.2.x - differentiate by build
        # SE RTM starts at 15.2.2562.17 (July 2025)
        # Exchange 2019 CU15 is 15.2.1748.x
        if ($BuildNumber -match '^15\.2\.(\d+)') {
            $minorBuild = [int]$Matches[1]
            if ($minorBuild -ge 2562) {
                return 'Exchange SE'
            } else {
                return 'Exchange 2019'
            }
        }
    }

    # Fallback to product name
    if (-not [string]::IsNullOrEmpty($ProductName)) {
        if ($ProductName -match 'Exchange.*2007') { return 'Exchange 2007' }
        if ($ProductName -match 'Exchange.*2010') { return 'Exchange 2010' }
        if ($ProductName -match 'Exchange.*2013') { return 'Exchange 2013' }
        if ($ProductName -match 'Exchange.*2016') { return 'Exchange 2016' }
        if ($ProductName -match 'Exchange.*2019') { return 'Exchange 2019' }
        if ($ProductName -match 'Exchange.*SE|Subscription') { return 'Exchange SE' }
    }

    return $null
}

# =============================================================================
# WINDOWS EOL CHECK FUNCTIONS
# =============================================================================
<#
.SYNOPSIS
    Tests if a Windows operating system is past its End-of-Life date.

.DESCRIPTION
    Checks the Windows lifecycle data to determine if an OS has reached EOL.
    Returns detailed information about the EOL status.

    For Windows 10 LTSC editions, the OSVersion parameter is critical for correct
    EOL determination since each LTSC release has a different support end date.

.PARAMETER OSName
    The operatingSystem attribute value from AD (will be normalized internally).

.PARAMETER OSVersion
    The operatingSystemVersion attribute from AD (e.g., "10.0 (17763)").
    Required for correct Windows 10 LTSC identification.

.PARAMETER ReferenceDate
    The date to compare against (default: current date).

.OUTPUTS
    PSCustomObject with properties:
    - IsOutdated: $true if OS is past EOL
    - NormalizedOS: The normalized OS name
    - EOLDate: The EOL date (or $null if not in lifecycle data)
    - DaysSinceEOL: Days since EOL (negative if not yet EOL)
    - HasLifecycleData: $true if OS is in lifecycle database

.EXAMPLE
    Test-IsOutdatedOS -OSName "Windows Server 2012 R2 Standard"
    # Returns object with IsOutdated = $true (as of 2024+)

.EXAMPLE
    Test-IsOutdatedOS -OSName "Windows 10 Enterprise LTSC" -OSVersion "10.0 (17763)"
    # Returns object with IsOutdated = $false (LTSC 2019 EOL is 2029-01-09)
#>
function Test-IsOutdatedOS {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OSName,

        [Parameter(Mandatory=$false)]
        [string]$OSVersion,

        [Parameter(Mandatory=$false)]
        [DateTime]$ReferenceDate = (Get-Date)
    )

    $normalizedOS = Get-NormalizedOSName -OSName $OSName -OSVersion $OSVersion

    $result = [PSCustomObject]@{
        IsOutdated = $false
        NormalizedOS = $normalizedOS
        EOLDate = $null
        DaysSinceEOL = $null
        HasLifecycleData = $false
    }

    if ($Script:WindowsLifecycle.ContainsKey($normalizedOS)) {
        $result.HasLifecycleData = $true
        $eolDate = [DateTime]::ParseExact($Script:WindowsLifecycle[$normalizedOS], 'yyyy-MM-dd', $null)
        $result.EOLDate = $eolDate

        $daysDiff = ($ReferenceDate - $eolDate).Days
        $result.DaysSinceEOL = $daysDiff

        if ($daysDiff -gt 0) {
            $result.IsOutdated = $true
        }
    }

    return $result
}

# =============================================================================
# EXCHANGE EOL CHECK FUNCTIONS
# =============================================================================
<#
.SYNOPSIS
    Gets the recommended severity for an Exchange version.

.PARAMETER BuildNumber
    The Exchange build number.

.PARAMETER ProductName
    The Exchange product name (fallback).

.OUTPUTS
    String - Severity class (Critical, Finding, Hint, Standard)
#>
function Get-ExchangeSeverity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$BuildNumber,

        [Parameter(Mandatory=$false)]
        [string]$ProductName
    )

    $normalizedVersion = Get-NormalizedExchangeVersion -BuildNumber $BuildNumber -ProductName $ProductName

    if ($normalizedVersion -and $Script:ExchangeLifecycle.ContainsKey($normalizedVersion)) {
        return $Script:ExchangeLifecycle[$normalizedVersion].Severity
    }

    return 'Standard'
}