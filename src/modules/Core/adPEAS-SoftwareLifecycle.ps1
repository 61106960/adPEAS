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
# Key   = Normalized OS name (as returned by Get-NormalizedOSName)
# Value = @{ ExtendedEnd = '<yyyy-MM-dd>'; ESUEnd = '<yyyy-MM-dd>' }
#
# TWO dates per product, and the distinction is the whole point.
#
# ExtendedEnd is the day Microsoft stopped shipping security updates to everyone. Past it
# a machine is unpatched unless its owner bought Extended Security Updates, which for
# Server 2012 R2 means an Azure Arc subscription and for Windows 7 a volume licensing
# agreement - neither is the common case.
#
# ESUEnd is the day the paid extension ran out as well, and it is only present where such
# a program existed.
#
# The table used to carry a single date per product, and for five products that date was
# the ESU end. Measured against 2026-10-10, Test-IsOutdatedOS answered
# IsOutdated = False for "Windows Server 2012 R2 Standard" - the most common real
# end-of-life server there is - while the operatingSystem trigger in
# adPEAS-FindingDefinitions.ps1 coloured the same computer red as "End-of-Life Operating
# System" wherever another check rendered it. One report, two answers, and the check
# responsible for the question was the one that said everything was fine.
#
# Dates are the last day of support, as Microsoft's lifecycle pages state them (those
# pages show the following day at 06:59:59 PT, which is the same instant).

$Script:WindowsLifecycle = @{
    # ===== Windows Client =====
    'Windows XP'           = @{ ExtendedEnd = '2014-04-08' }
    'Windows Vista'        = @{ ExtendedEnd = '2017-04-11' }
    'Windows 7'            = @{ ExtendedEnd = '2020-01-14'; ESUEnd = '2023-01-10' }
    'Windows 8'            = @{ ExtendedEnd = '2016-01-12' }   # no extended support, 8.1 was the upgrade
    'Windows 8.1'          = @{ ExtendedEnd = '2023-01-10' }

    # Windows 10 has a consumer ESU year and a commercial one beyond this date.
    # Deliberately not entered: the programs have conditions (a Microsoft account, or a
    # volume agreement) that nothing in Active Directory records, and giving the product
    # an ESUEnd here would move every Windows 10 machine in every domain from a finding
    # to a hint for a year - on an assumption about the customer that adPEAS cannot check.
    'Windows 10'           = @{ ExtendedEnd = '2025-10-14' }

    # The Windows 10 long-term servicing editions have their own, longer lifecycles.
    # Identified by "LTSB" or "LTSC" in operatingSystem AND the build in
    # operatingSystemVersion. The first two are named LTSB here because that is what their
    # operatingSystem string says - the channel was renamed to LTSC with the 2019 release.
    'Windows 10 LTSB 2015' = @{ ExtendedEnd = '2025-10-14' }   # Build 10240 (1507)
    'Windows 10 LTSB 2016' = @{ ExtendedEnd = '2026-10-13' }   # Build 14393 (1607)
    'Windows 10 LTSC 2019' = @{ ExtendedEnd = '2029-01-09' }   # Build 17763 (1809)
    'Windows 10 LTSC 2021' = @{ ExtendedEnd = '2027-01-12' }   # Build 19044 (21H2)

    # ===== Windows 11 =====
    # Per release, keyed by build through $Script:Windows11Builds below. Only the LTSC
    # edition has a single date, because it is not on the annual channel.
    'Windows 11 LTSC 2024' = @{ ExtendedEnd = '2029-10-09' }   # Build 26100, Enterprise LTSC
                                                               # (IoT Enterprise LTSC 2024 runs to 2034-10-10)

    # ===== Windows Server =====
    'Windows Server 2003'    = @{ ExtendedEnd = '2015-07-14' }
    'Windows Server 2008'    = @{ ExtendedEnd = '2020-01-14'; ESUEnd = '2023-01-10' }
    'Windows Server 2008 R2' = @{ ExtendedEnd = '2020-01-14'; ESUEnd = '2023-01-10' }
    'Windows Server 2012'    = @{ ExtendedEnd = '2023-10-10'; ESUEnd = '2026-10-13' }
    'Windows Server 2012 R2' = @{ ExtendedEnd = '2023-10-10'; ESUEnd = '2026-10-13' }
    'Windows Server 2016'    = @{ ExtendedEnd = '2027-01-12' }

    # Still supported, but the end date is published and belongs in the table. A future
    # date already means "not outdated" - that is how the LTSC rows work. Leaving these
    # in a comment made a current server indistinguishable from a network printer:
    # both came back HasLifecycleData = $false.
    'Windows Server 2019'    = @{ ExtendedEnd = '2029-01-09' }
    'Windows Server 2022'    = @{ ExtendedEnd = '2031-10-14' }
}

# =============================================================================
# WINDOWS 11 RELEASES
# =============================================================================
# Windows 11 is versioned per release like the old Windows 10 SAC channel, and each
# release stops receiving updates on its own date - earlier for Home and Pro than for
# Enterprise and Education. The product was in $Script:WindowsSupportedNoEOL, which made
# Test-IsOutdatedOS answer "known, not outdated" for every Windows 11 machine whatever
# build it ran. A fleet sitting on 22000 or 22621 - unpatched since 2023 and 2024 - came
# out silently clean, and operatingSystemVersion was read only in the LTSC branch.
#
# Keyed by build, because the build is what operatingSystemVersion carries and because
# the numbers are not ordered: 26H1 is build 28000 while the later 26H2 is 26300. Nothing
# here may infer "newer" from a larger number.
#
# Dates from Microsoft's Windows 11 release information and the two lifecycle pages,
# stated as the last day of support.
$Script:Windows11Builds = @{
    22000 = @{ Release = '21H2'; ConsumerEnd = '2023-10-10'; EnterpriseEnd = '2024-10-08' }
    22621 = @{ Release = '22H2'; ConsumerEnd = '2024-10-08'; EnterpriseEnd = '2025-10-14' }
    22631 = @{ Release = '23H2'; ConsumerEnd = '2025-11-11'; EnterpriseEnd = '2026-11-10' }
    26100 = @{ Release = '24H2'; ConsumerEnd = '2026-10-13'; EnterpriseEnd = '2027-10-12' }
    26200 = @{ Release = '25H2'; ConsumerEnd = '2027-10-12'; EnterpriseEnd = '2028-10-10' }
    26300 = @{ Release = '26H2'; ConsumerEnd = '2028-10-10'; EnterpriseEnd = '2029-10-09' }
    28000 = @{ Release = '26H1'; ConsumerEnd = '2028-03-14'; EnterpriseEnd = '2029-03-13' }
}

# The editions that follow the longer of the two Windows 11 schedules. Anything else -
# Home, Pro, Pro Education, Pro for Workstations, SE - follows the shorter one.
$Script:Windows11EnterpriseEditions = @(
    'Enterprise'
    'Education'
)

# Products that are recognized but have no date this table can apply:
# Windows Server 2025's lifecycle was not published when this was written, and a Windows
# 11 machine whose build is absent from the table above cannot be placed on the annual
# channel at all. They must not be given an invented date and must not be reported as an
# unknown platform either, so Test-IsOutdatedOS calls them known and not assessable.
$Script:WindowsSupportedNoEOL = @(
    'Windows 11'
    'Windows Server 2025'
)

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
    # EOLDate is the data; the severity is derived from it in Get-ExchangeSeverity.
    #
    # Each version used to carry a hand-written Severity as well, and the two disagreed:
    # Exchange 2016 and Exchange 2019 end on the same day, 2016 was written down as a
    # Finding and 2019 as a Hint. Whoever added the row got it right on the day; nobody
    # came back when the date passed. One source of truth per fact.
    'Exchange 2007' = @{
        EOLDate = '2017-04-11'
        BuildPrefix = '8.'
    }
    'Exchange 2010' = @{
        EOLDate = '2020-10-13'
        BuildPrefix = '14.'
    }
    'Exchange 2013' = @{
        EOLDate = '2023-04-11'
        BuildPrefix = '15.0.'
    }
    'Exchange 2016' = @{
        EOLDate = '2025-10-14'
        BuildPrefix = '15.1.'
    }
    'Exchange 2019' = @{
        EOLDate = '2025-10-14'
        BuildPrefix = '15.2.'
        BuildMax = 2561           # Builds below 2562 are Exchange 2019 (CU15 = 15.2.1748.x)
    }

    # ===== Currently Supported =====
    # Exchange SE follows the Modern Lifecycle Policy: supported as long as it is kept
    # current, with no published end date. $null is therefore the fact, not a gap - and
    # it is what makes Get-ExchangeSeverity answer Standard for it.
    'Exchange SE' = @{
        EOLDate = $null
        BuildPrefix = '15.2.'
        BuildMin = 2562           # Builds 2562+ are Exchange SE (SE RTM = 15.2.2562.17)
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
            # Long-term servicing editions, which have much longer support than SAC.
            # LTSB as well as LTSC: the two oldest releases shipped as LTSB and that is
            # what they write into operatingSystem - "Windows 10 Enterprise 2016 LTSB".
            # Matching 'LTSC' alone sent both of them to the generic Windows 10 row, which
            # ended on 2025-10-14, so every 2016 LTSB machine was reported as out of
            # support while Microsoft supports it until 2026-10-13. Microsoft renamed the
            # channel to LTSC with the 2019 release; the build decides either way.
            if ($OSName -match 'LTS[BC]') {
                # Map build number to the release
                $buildNumber = 0
                if ($OSVersion -match '\((\d+)\)') {
                    $buildNumber = [int]$Matches[1]
                }
                # LTSC 2019: Build 17763 (version 1809) - EOL 2029-01-09
                if ($buildNumber -ge 17763 -and $buildNumber -lt 19044) { return 'Windows 10 LTSC 2019' }
                # LTSC 2021: Build 19044 (version 21H2) - EOL 2027-01-12
                if ($buildNumber -ge 19044) { return 'Windows 10 LTSC 2021' }
                # LTSB 2016: Build 14393 (version 1607) - EOL 2026-10-13
                if ($buildNumber -ge 14393 -and $buildNumber -lt 17763) { return 'Windows 10 LTSB 2016' }
                # LTSB 2015: Build 10240 (version 1507) - EOL 2025-10-14
                if ($buildNumber -ge 10240 -and $buildNumber -lt 14393) { return 'Windows 10 LTSB 2015' }
                # Unknown build - fall through to generic Windows 10
            }
            return 'Windows 10'
        }
        '^Windows 11' {
            # Per release, like the Windows 10 SAC channel was. The build is the only
            # thing that identifies a release, and it used to be read in the LTSC branch
            # only - so every Windows 11 machine normalized to the bare product name and
            # came back "known, not outdated" whatever it was running.
            $buildNumber = 0
            if ($OSVersion -match '\((\d+)\)') { $buildNumber = [int]$Matches[1] }

            # The LTSC edition is not on the annual channel and has a row of its own.
            # Matched on the exact build: a future LTSC release will have another one, and
            # treating any higher build as LTSC 2024 would give it the wrong date.
            if ($OSName -match 'LTSC') {
                if ($buildNumber -eq 26100) { return 'Windows 11 LTSC 2024' }
                return 'Windows 11'
            }

            if ($Script:Windows11Builds.ContainsKey($buildNumber)) {
                return "Windows 11 $($Script:Windows11Builds[$buildNumber].Release)"
            }

            # No build, or a build this table does not know. The bare name, which
            # Test-IsOutdatedOS reports as not assessable rather than as supported.
            return 'Windows 11'
        }

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
        # "Version 15.2 (Build 1544.4)" is what Exchange writes into serialNumber on its
        # own object in the Configuration partition - and that is the only version string
        # the inventory in Get-InfrastructureServers has. None of the patterns below
        # matched it, so Get-ExchangeSeverity answered Standard, the is_exchange_eol
        # trigger stayed false, and the row rendered uncoloured with no card while the
        # dedicated Exchange check assessed the same server correctly from its build.
        if ($ProductName -match 'Version\s+(\d+)\.(\d+)\s*\(Build\s+(\d+)') {
            return (Get-NormalizedExchangeVersion -BuildNumber "$($Matches[1]).$($Matches[2]).$($Matches[3])")
        }
        # A build number handed to the wrong parameter. The trigger does exactly that: it
        # has a version string and does not know which shape it is in.
        if ($ProductName -match '^\d+\.\d+\.\d+') {
            return (Get-NormalizedExchangeVersion -BuildNumber $ProductName)
        }
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

        # The three new fields, and what each is for.
        #
        # SupportState says which of four states the machine is in, because "outdated yes
        # or no" cannot express the one that matters most: past the date everyone stopped
        # getting updates, but inside a paid extension its owner may or may not have
        # bought. A single boolean there either accuses every ESU customer or clears every
        # unpatched server, and the table used to do the second.
        #
        #   Supported      - the date has not passed
        #   ESUOnly        - past ExtendedEnd, within ESUEnd: patched only if ESU was paid for
        #   OutOfSupport   - past everything
        #   NotAssessable  - a recognized product this table cannot place (no build, no
        #                    published date). Not the same as "not outdated".
        SupportState = 'Unknown'
        ESUEnd = $null
        Release = $null
    }

    # Windows 11 on the annual channel: the release decides the date, and which of the two
    # dates applies depends on the edition.
    #
    # The condition repeats the build lookup on purpose, and it is belt and braces rather
    # than load-bearing: Get-NormalizedOSName consults this same table and only produces a
    # release name when the build is in it, so a build the table does not know normalizes
    # to the bare product name and lands in the not-assessable branch below. Measured by
    # mutation - dropping the second half of this condition fails no test, which is the
    # point: one table, one source of truth. It stays because it keeps this function
    # correct on its own terms rather than on the normalizer's.
    $windows11Build = 0
    if ($OSVersion -match '\((\d+)\)') { $windows11Build = [int]$Matches[1] }

    if ($normalizedOS -like 'Windows 11 2*' -and $Script:Windows11Builds.ContainsKey($windows11Build)) {
        $result.HasLifecycleData = $true
        $release = $Script:Windows11Builds[$windows11Build]
        $result.Release = $release.Release

        $isEnterprise = $false
        foreach ($edition in $Script:Windows11EnterpriseEditions) {
            if ($OSName -like "*$edition*") { $isEnterprise = $true; break }
        }

        $endDate = if ($isEnterprise) { $release.EnterpriseEnd } else { $release.ConsumerEnd }
        $eolDate = [DateTime]::ParseExact($endDate, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
        $result.EOLDate = $eolDate
        $result.DaysSinceEOL = ($ReferenceDate - $eolDate).Days

        if ($result.DaysSinceEOL -gt 0) {
            $result.IsOutdated = $true
            $result.SupportState = 'OutOfSupport'
        } else {
            $result.SupportState = 'Supported'
        }
        return $result
    }

    # A recognized product whose support end date is not published, or a Windows 11
    # machine that reported no build at all. Known, no date - and explicitly not
    # assessable, so a caller can tell it apart both from a supported machine and from a
    # platform the tool has never heard of.
    if ($Script:WindowsSupportedNoEOL -contains $normalizedOS) {
        $result.HasLifecycleData = $true
        $result.SupportState = 'NotAssessable'
        return $result
    }

    if ($Script:WindowsLifecycle.ContainsKey($normalizedOS)) {
        $result.HasLifecycleData = $true
        $entry = $Script:WindowsLifecycle[$normalizedOS]

        $eolDate = [DateTime]::ParseExact($entry.ExtendedEnd, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
        $result.EOLDate = $eolDate
        $result.DaysSinceEOL = ($ReferenceDate - $eolDate).Days

        $esuDate = $null
        if ($entry.ContainsKey('ESUEnd')) {
            $esuDate = [DateTime]::ParseExact($entry.ESUEnd, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
            $result.ESUEnd = $esuDate
        }

        if ($result.DaysSinceEOL -le 0) {
            $result.SupportState = 'Supported'
        }
        elseif ($esuDate -and ($ReferenceDate - $esuDate).Days -le 0) {
            # Past the date everyone stopped getting updates, inside the paid extension.
            # Still reported - the machine is unpatched unless somebody bought ESU - but
            # as its own state, with the date it stopped being patched by default.
            $result.IsOutdated = $true
            $result.SupportState = 'ESUOnly'
        }
        else {
            $result.IsOutdated = $true
            $result.SupportState = 'OutOfSupport'
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
        [string]$ProductName,

        [Parameter(Mandatory=$false)]
        [DateTime]$ReferenceDate = (Get-Date)
    )

    $normalizedVersion = Get-NormalizedExchangeVersion -BuildNumber $BuildNumber -ProductName $ProductName
    if (-not $normalizedVersion -or -not $Script:ExchangeLifecycle.ContainsKey($normalizedVersion)) {
        return 'Standard'
    }

    $entry = $Script:ExchangeLifecycle[$normalizedVersion]

    # Derived from the date, not read out of the table.
    #
    # Every version used to carry a hand-written Severity, and it went stale the way a
    # hand-maintained verdict always does: Exchange 2016 and Exchange 2019 both ended on
    # 2025-10-14, 2016 was written down as a Finding and 2019 as a Hint - so a year after
    # support ended for both, one of them was still a yellow hint in every report. The
    # Windows half of this file computes its verdict from the dates for that reason, and
    # this half does now too. The dates are the data that has to be maintained; the
    # verdict follows from them.
    if (-not $entry.EOLDate) { return 'Standard' }

    $eolDate = [DateTime]::MinValue
    if (-not [DateTime]::TryParseExact([string]$entry.EOLDate, 'yyyy-MM-dd', `
            [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$eolDate)) {
        return 'Standard'
    }

    if ($ReferenceDate -ge $eolDate) { return 'Finding' }

    # The last half year before the date. Still supported, and too late to start
    # planning the migration - which is what a hint is for.
    if ($ReferenceDate -ge $eolDate.AddDays(-180)) { return 'Hint' }

    return 'Standard'
}