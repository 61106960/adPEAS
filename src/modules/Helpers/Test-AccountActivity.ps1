function Test-AccountActivity {
    <#
    .SYNOPSIS
    Filters Active Directory accounts based on activity, password age, and status criteria.

    .DESCRIPTION
    Central filter function for AD account analysis. Accepts AD objects via pipeline and outputs only those that match ALL specified criteria.

    Works like Where-Object but with intelligent AD-specific filtering logic.
    Returns the original AD object unchanged if it passes all filters.

    Filter Categories:
    - Activity: Is account actively used (based on lastLogonTimestamp)
    - Password Age: When was password last changed
    - Account Status: Enabled/Disabled, security flags
    
    Important timestamps:
    - lastLogonTimestamp: Replicated, 9-14 day latency (msDS-LogonTimeSyncInterval)
    - lastLogon: NOT replicated, DC-specific, precise

    .PARAMETER ADObject
    The AD object (user or computer) to filter. Passed via pipeline.
    Required properties depend on filters used:
    - Activity filters: lastLogonTimestamp, userAccountControl
    - Password filters: pwdLastSet
    - LastLogon filter: lastLogon

    .PARAMETER IsActive
    Filter for accounts that ARE actively used (logged in within InactiveDays).
    Requires lastLogonTimestamp property.

    .PARAMETER IsInactive
    Filter for accounts that are NOT actively used (no login within InactiveDays).
    Requires lastLogonTimestamp property.

    .PARAMETER InactiveDays
    Threshold for activity determination in days.
    Default: Uses $Script:DefaultInactiveDays (typically 90 days) set by adPEAS.
    Can be overridden per-call if needed (e.g., -InactiveDays 180 for computers).
    When specified without -IsActive or -IsInactive, implicitly enables -IsInactive.

    .PARAMETER IsEnabled
    Filter for accounts that are enabled (not disabled).

    .PARAMETER IsDisabled
    Filter for accounts that are disabled.

    .PARAMETER NeverLoggedIn
    Filter for accounts that have never logged in (no lastLogonTimestamp).

    .PARAMETER HasLoggedIn
    Filter for accounts that have logged in at least once.

    .PARAMETER PasswordAgeDays
    Filter for accounts with password older than N days (exclusive: > not >=).

    .PARAMETER PasswordChangedInYear
    Filter for accounts with password changed in specific year (e.g., 2020).

    .PARAMETER PasswordChangedBeforeYear
    Filter for accounts with password changed BEFORE specific year (exclusive: year < value).

    .PARAMETER PasswordChangedAfterYear
    Filter for accounts with password changed AFTER specific year (exclusive: year > value).

    .PARAMETER PasswordNeverSet
    Filter for accounts where password was never set.

    .PARAMETER PasswordNeverExpires
    Filter for accounts with PASSWORD_NEVER_EXPIRES flag set.

    .PARAMETER PasswordNotRequired
    Filter for accounts with PASSWORD_NOT_REQUIRED flag set.

    .PARAMETER IncludeDetails
    If specified, adds ActivityDetails property to output object with analysis results.
    Useful for debugging or detailed reporting.

    .EXAMPLE
    # Get all users with password from before 2016
    Get-DomainUser -Properties lastLogonTimestamp,pwdLastSet,userAccountControl |
        Test-AccountActivity -PasswordChangedBeforeYear 2016

    .EXAMPLE
    # Get enabled users inactive for 2 years
    Get-DomainUser -Properties lastLogonTimestamp,userAccountControl |
        Test-AccountActivity -IsEnabled -IsInactive -InactiveDays 730

    .EXAMPLE
    # Get active users with password older than 5 years (security risk!)
    Get-DomainUser -Properties lastLogonTimestamp,pwdLastSet,userAccountControl |
        Test-AccountActivity -IsActive -PasswordAgeDays 1825

    .EXAMPLE
    # Get accounts that never logged in
    Get-DomainUser -Properties lastLogonTimestamp,userAccountControl |
        Test-AccountActivity -NeverLoggedIn

    .EXAMPLE
    # Get enabled accounts with PASSWORD_NEVER_EXPIRES
    Get-DomainUser -Properties lastLogonTimestamp,userAccountControl |
        Test-AccountActivity -IsEnabled -PasswordNeverExpires

    .EXAMPLE
    # Get inactive computers (no login in 180 days)
    Get-DomainComputer -Properties lastLogonTimestamp,userAccountControl |
        Test-AccountActivity -IsInactive -InactiveDays 180

    .EXAMPLE
    # Get users with password from exactly 2020
    Get-DomainUser -Properties pwdLastSet,userAccountControl |
        Test-AccountActivity -PasswordChangedInYear 2020

    .EXAMPLE
    # Combine multiple filters: Enabled + Active + Old Password + PasswordNeverExpires
    Get-DomainUser -Properties lastLogonTimestamp,pwdLastSet,userAccountControl |
        Test-AccountActivity -IsEnabled -IsActive -PasswordAgeDays 3650 -PasswordNeverExpires

    .OUTPUTS
    Original AD object if it passes all filters, nothing otherwise.
    With -IncludeDetails: Adds ActivityDetails property with analysis results.

    .NOTES
    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [object]$ADObject,

        # Activity Filters
        [Parameter(Mandatory=$false)]
        [switch]$IsActive,

        [Parameter(Mandatory=$false)]
        [switch]$IsInactive,

        [Parameter(Mandatory=$false)]
        [int]$InactiveDays = 0,  # 0 = use $Script:DefaultInactiveDays

        # Account Status Filters
        [Parameter(Mandatory=$false)]
        [switch]$IsEnabled,

        [Parameter(Mandatory=$false)]
        [switch]$IsDisabled,

        [Parameter(Mandatory=$false)]
        [switch]$NeverLoggedIn,

        [Parameter(Mandatory=$false)]
        [switch]$HasLoggedIn,

        # Password Age Filters
        [Parameter(Mandatory=$false)]
        [int]$PasswordAgeDays = 0,

        [Parameter(Mandatory=$false)]
        [int]$PasswordChangedInYear = 0,

        [Parameter(Mandatory=$false)]
        [int]$PasswordChangedBeforeYear = 0,

        [Parameter(Mandatory=$false)]
        [int]$PasswordChangedAfterYear = 0,

        [Parameter(Mandatory=$false)]
        [switch]$PasswordNeverSet,

        # Security Flag Filters
        [Parameter(Mandatory=$false)]
        [switch]$PasswordNeverExpires,

        [Parameter(Mandatory=$false)]
        [switch]$PasswordNotRequired,

        # Output Options
        [Parameter(Mandatory=$false)]
        [switch]$IncludeDetails
    )

    begin {
        # ===== Validate mutually exclusive parameters =====
        if ($IsActive -and $IsInactive) {
            throw "Parameters -IsActive and -IsInactive are mutually exclusive"
        }
        if ($IsEnabled -and $IsDisabled) {
            throw "Parameters -IsEnabled and -IsDisabled are mutually exclusive"
        }
        if ($NeverLoggedIn -and $HasLoggedIn) {
            throw "Parameters -NeverLoggedIn and -HasLoggedIn are mutually exclusive"
        }
    }

    process {
        # ===== Resolve InactiveDays from global constant if not explicitly set =====
        $effectiveInactiveDays = if ($InactiveDays -gt 0) {
            $InactiveDays
        } elseif ($Script:DefaultInactiveDays) {
            $Script:DefaultInactiveDays
        } else {
            90  # Fallback if no global constant exists
        }

        # ===== Implicit -IsInactive when -InactiveDays is explicitly provided =====
        if ($InactiveDays -gt 0 -and -not $IsActive -and -not $IsInactive) {
            $IsInactive = $true
        }

        # ===== Parse userAccountControl =====
        $uacValue = $ADObject.userAccountControl
        $uac = 0

        if ($uacValue -is [array]) {
            $uacValue = $uacValue[0]
        }

        if ($null -ne $uacValue) {
            if ($uacValue -is [int] -or $uacValue -is [long]) {
                $uac = [int]$uacValue
            }
            elseif ($uacValue -is [string]) {
                $parsed = 0
                if ([int]::TryParse($uacValue, [ref]$parsed)) {
                    $uac = $parsed
                }
            }
        }

        # ===== Determine account state =====
        $accountEnabled = -not (($uac -band 0x0002) -eq 0x0002)
        $hasPasswordNeverExpires = ($uac -band 0x10000) -eq 0x10000
        $hasPasswordNotRequired = ($uac -band 0x0020) -eq 0x0020

        # ===== Check enabled/disabled filter =====
        if ($IsEnabled -and -not $accountEnabled) {
            return  # Filter out: wanted enabled, but account is disabled
        }
        if ($IsDisabled -and $accountEnabled) {
            return  # Filter out: wanted disabled, but account is enabled
        }

        # ===== Check security flag filters =====
        if ($PasswordNeverExpires -and -not $hasPasswordNeverExpires) {
            return  # Filter out: wanted PasswordNeverExpires, but flag not set
        }
        if ($PasswordNotRequired -and -not $hasPasswordNotRequired) {
            return  # Filter out: wanted PasswordNotRequired, but flag not set
        }

        # ===== Parse lastLogonTimestamp =====
        $lastLogonTimestamp = $ADObject.lastLogonTimestamp
        $lastActivityDate = $null
        $hasEverLoggedIn = $false

        if ($lastLogonTimestamp) {
            if ($lastLogonTimestamp -is [array]) {
                $lastLogonTimestamp = $lastLogonTimestamp[0]
            }
            $lastActivityDate = Convert-ADTimestamp -Value $lastLogonTimestamp
            if ($lastActivityDate) {
                $hasEverLoggedIn = $true
            }
        }

        # ===== Check never logged in / has logged in filter =====
        if ($NeverLoggedIn -and $hasEverLoggedIn) {
            return  # Filter out: wanted never logged in, but has logged in
        }
        if ($HasLoggedIn -and -not $hasEverLoggedIn) {
            return  # Filter out: wanted has logged in, but never logged in
        }

        # ===== Check activity filter =====
        if ($IsActive -or $IsInactive) {
            # Accounts that never logged in (no lastLogonTimestamp) are NOT "inactive" -
            # they are "never used". Inactive means "was active once but not recently".
            # Never-logged-in accounts should be excluded from both IsActive and IsInactive.
            if (-not $hasEverLoggedIn) {
                if ($IsActive) {
                    return  # Filter out: never logged in, not active
                }
                if ($IsInactive) {
                    return  # Filter out: never logged in, not inactive either (use -NeverLoggedIn)
                }
            }

            $cutoffDate = (Get-Date).AddDays(-$effectiveInactiveDays)
            $isAccountActive = $lastActivityDate -gt $cutoffDate

            if ($IsActive -and -not $isAccountActive) {
                return  # Filter out: wanted active, but inactive
            }
            if ($IsInactive -and $isAccountActive) {
                return  # Filter out: wanted inactive, but active
            }
        }

        # ===== Parse pwdLastSet =====
        $pwdLastSet = $ADObject.pwdLastSet
        $passwordSetDate = $null
        $passwordYear = $null
        $daysSincePasswordChange = $null
        $passwordWasNeverSet = $true

        if ($pwdLastSet) {
            if ($pwdLastSet -is [array]) {
                $pwdLastSet = $pwdLastSet[0]
            }
            $passwordSetDate = Convert-ADTimestamp -Value $pwdLastSet
            if ($passwordSetDate) {
                $passwordWasNeverSet = $false
                $passwordYear = $passwordSetDate.Year
                $daysSincePasswordChange = [math]::Floor(((Get-Date) - $passwordSetDate).TotalDays)
            }
        }

        # ===== Check password never set filter =====
        if ($PasswordNeverSet -and -not $passwordWasNeverSet) {
            return  # Filter out: wanted password never set, but it was set
        }

        # ===== Check password age filters =====
        if ($PasswordAgeDays -gt 0) {
            # Use < (not <=) so -PasswordAgeDays 90 includes passwords exactly 90 days old
            if ($passwordWasNeverSet -or $daysSincePasswordChange -lt $PasswordAgeDays) {
                return  # Filter out: password not old enough (or never set)
            }
        }

        if ($PasswordChangedInYear -gt 0) {
            if ($passwordWasNeverSet -or $passwordYear -ne $PasswordChangedInYear) {
                return  # Filter out: password not from target year
            }
        }

        if ($PasswordChangedBeforeYear -gt 0) {
            if ($passwordWasNeverSet -or $passwordYear -ge $PasswordChangedBeforeYear) {
                return  # Filter out: password not before target year
            }
        }

        if ($PasswordChangedAfterYear -gt 0) {
            if ($passwordWasNeverSet -or $passwordYear -le $PasswordChangedAfterYear) {
                return  # Filter out: password not after target year
            }
        }

        # ===== All filters passed - output the object =====
        if ($IncludeDetails) {
            # Add analysis details to the object
            $details = [PSCustomObject]@{
                IsEnabled = $accountEnabled
                IsActive = if ($hasEverLoggedIn) { $lastActivityDate -gt (Get-Date).AddDays(-$effectiveInactiveDays) } else { $false }
                LastActivity = $lastActivityDate
                DaysSinceActivity = if ($lastActivityDate) { [math]::Floor(((Get-Date) - $lastActivityDate).TotalDays) } else { $null }
                NeverLoggedIn = -not $hasEverLoggedIn
                PasswordLastSet = $passwordSetDate
                PasswordYear = $passwordYear
                DaysSincePasswordChange = $daysSincePasswordChange
                PasswordNeverSet = $passwordWasNeverSet
                HasPasswordNeverExpires = $hasPasswordNeverExpires
                HasPasswordNotRequired = $hasPasswordNotRequired
            }

            # Add property to object
            # Note: Add-Member modifies the original object in-place, -PassThru returns it for pipeline
            $ADObject | Add-Member -NotePropertyName "ActivityDetails" -NotePropertyValue $details -PassThru
        }
        else {
            # Return original object unchanged
            $ADObject
        }
    }
}

function Convert-ADTimestamp {
    <#
    .SYNOPSIS
    Converts various AD timestamp formats to DateTime.

    .DESCRIPTION
    Helper function to handle different timestamp formats from AD:
    - DateTime objects (pass through)
    - FileTime integers (Windows file time)
    - String representations of FileTime or DateTime

    .PARAMETER Value
    The timestamp value to convert.

    .OUTPUTS
    DateTime object or $null if conversion fails.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Value
    )

    try {
        if ($Value -is [DateTime]) {
            return $Value
        }
        elseif ($Value -is [long] -or $Value -is [int]) {
            # FileTime integer - check for "never" values
            if ($Value -le 0 -or $Value -eq 9223372036854775807) {
                return $null
            }
            return [DateTime]::FromFileTime([long]$Value)
        }
        elseif ($Value -is [string]) {
            # Try parsing as long (FileTime) first
            $parsed = 0L
            if ([long]::TryParse($Value, [ref]$parsed)) {
                if ($parsed -le 0 -or $parsed -eq 9223372036854775807) {
                    return $null
                }
                return [DateTime]::FromFileTime($parsed)
            }

            # Try parsing as DateTime string
            $parsedDate = [DateTime]::MinValue
            if ([DateTime]::TryParse($Value, [ref]$parsedDate)) {
                return $parsedDate
            }
        }
    }
    catch {
        Write-Log "[Convert-ADTimestamp] Error converting timestamp: $_"
    }

    return $null
}
