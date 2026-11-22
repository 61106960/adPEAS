<#
.SYNOPSIS
    Formats a date the same way on every host, whatever calendar the host prefers.

.DESCRIPTION
    A custom format string is rendered through the current culture's calendar. On a host
    whose regional format is Thai, Saudi or Persian, that calendar is not Gregorian, and
    the same instant comes out with a different year:

        en-US / de-DE   2026-03-09
        th-TH           2569-03-09      (Buddhist era)
        ar-SA           1447-09-20      (Hijri)
        fa-IR           1404-12-18      (Persian)

    adPEAS writes dates into reports a consultant hands to a customer, next to data whose
    own timestamps are stored as round-trip ISO strings, so the two have to agree. This
    formats through InvariantCulture, whose calendar is Gregorian.

    A point in time that a person reads - in the console, a report, a card - goes through
    Format-adPEASTime instead, which builds on this and names the zone beside the value.
    Format-adPEASDate itself is for what a machine reads (file names, GPP and XML fields,
    backups) and for calendar dates that are no instant, such as the end-of-support days
    of the lifecycle tables.

    The standard specifiers 'o' and 's' already force the Gregorian calendar and need no
    help; every custom pattern ('yyyy-MM-dd', 'yyyyMMddHHmmss', ...) needs this.

    One place deliberately does not call this and spells the invariant culture out inline
    instead, because what it produces is read by a machine rather than by a person and the
    contract belongs next to the code: the KerberosTime in Kerberos-ASN1.ps1
    (New-ASN1GeneralizedTime).

.PARAMETER Date
    The value to format.

.PARAMETER Format
    A .NET date format string. Defaults to the pattern adPEAS uses most.

.EXAMPLE
    Format-adPEASDate $cert.NotAfter 'yyyy-MM-dd'

.EXAMPLE
    Format-adPEASDate (Get-Date) 'yyyyMMdd_HHmmss'

.OUTPUTS
    [string]

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
function Format-adPEASDate {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [datetime]$Date,

        [Parameter(Mandatory = $false, Position = 1)]
        [string]$Format = 'yyyy-MM-dd HH:mm:ss'
    )

    return $Date.ToString($Format, [System.Globalization.CultureInfo]::InvariantCulture)
}

<#
.SYNOPSIS
    Turns an LDAP Generalized Time value into the local time adPEAS shows every date in.

.DESCRIPTION
    The rule for every point in time adPEAS reads from the directory: it is handed on as a
    DateTime of Kind Local - the local time of the host that runs adPEAS - and shown with
    its zone beside it (Format-adPEASTime). A FILETIME attribute gets there through
    [DateTime]::FromFileTime; a Generalized Time value through this function, which is the
    only place that parses one.

    Before this rule the two classes came out differently: whenCreated, whenChanged and a
    handful of FILETIME values read with FromFileTimeUtc were UTC, pwdLastSet and every other
    FILETIME attribute local, and one card showed the same moment an hour apart, with nothing
    to say which was which. DateTime arithmetic ignores Kind, so subtracting one class from
    the other was off by the UTC offset as well.

    Two times are compared on .ToUniversalTime() of both, which holds across a change of
    daylight saving time. Protocol times - Kerberos, NTLM, PAC, the collector's Unix
    timestamps - are not shown as directory times and stay UTC.

.PARAMETER Value
    The value as LDAP returns it, "yyyyMMddHHmmss.0Z"; digits beyond the seconds are ignored.

.OUTPUTS
    [datetime] of Kind Local, or $null for a value that is not a Generalized Time.

.EXAMPLE
    ConvertFrom-adPEASGeneralizedTime '20261116194017.0Z'
#>
function ConvertFrom-adPEASGeneralizedTime {
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        $Value
    )

    if ($null -eq $Value) { return $null }
    if ($Value -is [byte[]]) { $Value = [System.Text.Encoding]::ASCII.GetString($Value) }
    $text = [string]@($Value)[0]
    if ($text -notmatch '^(\d{14})') { return $null }

    $parsed = [DateTime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [DateTime]::TryParseExact($Matches[1], 'yyyyMMddHHmmss', [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $null
    }
    return $parsed.ToLocalTime()
}

<#
.SYNOPSIS
    Writes a UTC offset the way adPEAS labels a time: "UTC+01:00", "UTC-05:00".
.DESCRIPTION
    The offset of one value, beside that value. It replaced Get-adPEASTimeZoneLabel, which
    named one offset for a whole report in its header - taken at the moment the report was
    written, and so wrong for every value from the other half of the year.
#>
function Format-adPEASUtcOffset {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [TimeSpan]$Offset
    )

    $sign = if ($Offset -lt [TimeSpan]::Zero) { '-' } else { '+' }
    $abs = $Offset.Duration()
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    return ('UTC' + $sign + $abs.Hours.ToString('00', $inv) + ':' + $abs.Minutes.ToString('00', $inv))
}

# ============================================================================
# Times a person reads: every value names its zone
# ============================================================================
#
# A time adPEAS shows carries its zone beside it: "2026-07-15 14:00:00 UTC+02:00" in local
# time, "2026-07-15 12:00:00 UTC" in UTC. A single offset in a report header was wrong for
# every value from the other half of the year - a July value converted with +02:00 under a
# winter header saying +01:00 - and a screenshot of one card lost even that.
#
# The labelled text is also the placeholder. It names one instant, so any text that carries
# one can be rewritten into another zone later: the HTML switch between scan-host time and
# UTC, Convert-adPEASReport -UTC, the JSON export (always UTC) and Compare-adPEASReport
# (which compares the instants, not their spelling) all find the times by
# $Script:adPEASTimeTextRegex. A time without a zone - a calendar date, a GPO task bound
# that is the client's own wall clock - is never written this way and never rewritten.
#
# Run state, raised by Invoke-adPEAS -UTC and Convert-adPEASReport for the length of their
# call and lowered in their finally (Clear-SessionState clears it as well):
#   $Script:adPEASTimeUtc        show times in UTC instead of local time
#   $Script:adPEASTimeZone       the zone "local" means; $null is this host. Convert sets the
#                                zone of the host that ran the scan, read from the export.
#   $Script:adPEASReferenceTime  the "now" an age is measured from; $null is now. The HTML
#                                export and Convert set the time a finding was collected, so
#                                a report rebuilt in June rates a January scan as January saw it.
#   $Script:adPEASScanStart      when the scan began - the date a report names. Invoke-adPEAS
#                                sets it; Convert-adPEASReport sets the original one.
#   $Script:adPEASReportConverted  the report is rebuilt from an export (Convert-adPEASReport);
#                                its header names when, beside the scan date.
$Script:adPEASTimeUtc = $false
$Script:adPEASTimeZone = $null
$Script:adPEASReferenceTime = $null
$Script:adPEASScanStart = $null
$Script:adPEASReportConverted = $false

# A time as Format-adPEASTime writes it, seconds optional: "yyyy-MM-dd HH:mm[:ss] UTC[+hh:mm]".
# The guards on both sides keep it from matching inside a longer number or an ISO string.
$Script:adPEASTimeTextRegex = [regex]::new(
    '(?<![\d:.-])(?<y>\d{4})-(?<mo>\d{2})-(?<d>\d{2}) (?<h>\d{2}):(?<mi>\d{2})(?::(?<s>\d{2}))? UTC(?:(?<sign>[+-])(?<oh>\d{2}):(?<om>\d{2}))?(?![\w:+-])')

<#
.SYNOPSIS
    Writes an instant in the zone of the current display mode, with that zone beside it.
.DESCRIPTION
    The internal half of Format-adPEASTime and the rewriting functions below. Takes the
    instant as UTC and returns "yyyy-MM-dd HH:mm:ss UTC+hh:mm" in local time of
    $Script:adPEASTimeZone (this host when unset) or "yyyy-MM-dd HH:mm:ss UTC".
.PARAMETER UtcTime
    The instant, Kind Utc.
.PARAMETER Minutes
    Leave out the seconds.
.PARAMETER AsUtc
    Write it in UTC.
#>
function Get-adPEASTimeText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [datetime]$UtcTime,

        [Parameter(Mandatory = $false)]
        [bool]$Minutes = $false,

        [Parameter(Mandatory = $false)]
        [bool]$AsUtc = $false
    )

    $pattern = if ($Minutes) { 'yyyy-MM-dd HH:mm' } else { 'yyyy-MM-dd HH:mm:ss' }
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    if ($AsUtc) {
        return ($UtcTime.ToString($pattern, $inv) + ' UTC')
    }
    $zone = if ($Script:adPEASTimeZone) { $Script:adPEASTimeZone } else { [TimeZoneInfo]::Local }
    $wallClock = [TimeZoneInfo]::ConvertTimeFromUtc($UtcTime, $zone)
    return ($wallClock.ToString($pattern, $inv) + ' ' + (Format-adPEASUtcOffset $zone.GetUtcOffset($UtcTime)))
}

<#
.SYNOPSIS
    Formats a point in time for a person to read, with its zone beside it.
.DESCRIPTION
    The way every instant adPEAS shows becomes text: "2026-07-15 14:00:00 UTC+02:00" in local
    time, "2026-07-15 12:00:00 UTC" while a run shows UTC (Invoke-adPEAS -UTC). The offset
    is the one of that instant, so a summer value says +02:00 in a winter report.

    -Precision Minutes is for the places that used to show a bare date - a certificate's
    validity, the day a password was set. Their zone is named too, because the date itself
    can differ between zones (a password set at 00:30 local time was set the day before in
    UTC), and the minutes are what lets the text be rewritten into the other zone later.

    Not for calendar dates that are no instant (an end-of-support day) and not for what a
    machine reads - those stay with Format-adPEASDate.
.PARAMETER Date
    The instant. Kind Local or Utc; an Unspecified value is read as local time, as
    .ToUniversalTime() reads it, so a UTC value has to carry Kind Utc.
.PARAMETER Precision
    Seconds (default) or Minutes.
.EXAMPLE
    Format-adPEASTime $user.pwdLastSet
    Returns "2026-07-15 14:00:00 UTC+02:00" on a host in Central Europe.
.OUTPUTS
    [string]
#>
function Format-adPEASTime {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [datetime]$Date,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet('Seconds', 'Minutes')]
        [string]$Precision = 'Seconds'
    )

    try {
        return (Get-adPEASTimeText -UtcTime $Date.ToUniversalTime() -Minutes ($Precision -eq 'Minutes') -AsUtc ([bool]$Script:adPEASTimeUtc))
    } catch {
        # A value at the edge of the calendar (MinValue/MaxValue) that no zone can hold.
        return (Format-adPEASDate $Date $(if ($Precision -eq 'Minutes') { 'yyyy-MM-dd HH:mm' } else { 'yyyy-MM-dd HH:mm:ss' }))
    }
}

<#
.SYNOPSIS
    Reads the instant out of a labelled time, as Format-adPEASTime writes it.
.PARAMETER Text
    "2026-07-15 14:00:00 UTC+02:00", "2026-07-15 12:00 UTC", or a text containing one; the
    first labelled time in it is read.
.OUTPUTS
    [datetime] of Kind Utc, or $null when the text carries no labelled time.
#>
function ConvertFrom-adPEASTimeText {
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Text
    )

    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $match = $Script:adPEASTimeTextRegex.Match($Text)
    if (-not $match.Success) { return $null }
    return (ConvertFrom-adPEASTimeMatch $match)
}

# The instant of one regex match, or $null for a value no calendar holds (2026-13-45).
function ConvertFrom-adPEASTimeMatch {
    param([System.Text.RegularExpressions.Match]$Match)

    $g = $Match.Groups
    try {
        $offset = [TimeSpan]::Zero
        if ($g['sign'].Success) {
            $offset = New-Object TimeSpan ([int]$g['oh'].Value), ([int]$g['om'].Value), 0
            if ($g['sign'].Value -eq '-') { $offset = $offset.Negate() }
        }
        $seconds = if ($g['s'].Success) { [int]$g['s'].Value } else { 0 }
        $instant = New-Object DateTimeOffset ([int]$g['y'].Value), ([int]$g['mo'].Value), ([int]$g['d'].Value), ([int]$g['h'].Value), ([int]$g['mi'].Value), $seconds, $offset
        return $instant.UtcDateTime
    } catch {
        return $null
    }
}

<#
.SYNOPSIS
    Rewrites every labelled time in a text into one display mode.
.DESCRIPTION
    What lets a text that was written once - a card line, a key-value row, a certificate's
    display text - follow the display mode: the console and text report (in the current
    mode), the JSON export (always UTC), Compare-adPEASReport (UTC, so two scans written in
    different zones compare by instant). A text without a labelled time comes back as it
    went in, after one ordinal search.
.PARAMETER Text
    The text.
.PARAMETER Mode
    Current (the run's mode, default), Utc, or Local (the zone of $Script:adPEASTimeZone).
#>
function ConvertTo-adPEASTimeText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        # Untyped, so $null comes back as $null: a [string] parameter would turn it into ''
        # and the export would write "" where a finding has no text.
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        $Text,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Current', 'Utc', 'Local')]
        [string]$Mode = 'Current'
    )

    if ($null -eq $Text) { return $null }
    $Text = [string]$Text
    if ($Text.Length -eq 0 -or $Text.IndexOf(' UTC', [System.StringComparison]::Ordinal) -lt 0) {
        return $Text
    }
    $toUtc = switch ($Mode) {
        'Utc'   { $true }
        'Local' { $false }
        default { [bool]$Script:adPEASTimeUtc }
    }
    return $Script:adPEASTimeTextRegex.Replace($Text, {
        param($match)
        $instant = ConvertFrom-adPEASTimeMatch $match
        if ($null -eq $instant) { return $match.Value }
        try {
            return (Get-adPEASTimeText -UtcTime $instant -Minutes (-not $match.Groups['s'].Success) -AsUtc $toUtc)
        } catch {
            return $match.Value
        }
    })
}

<#
.SYNOPSIS
    Wraps every labelled time in an HTML text in an element the report's time switch turns.
.DESCRIPTION
    For text that is already HTML-encoded and holds no markup - an attribute value, a card
    line. Each time becomes <span class="adp-time" data-local="..." data-utc="...">, the two
    spellings worked out here, so the switch in the report only swaps text and never does
    arithmetic: "local" is the zone of the host that ran the scan, which a browser does not
    know. The span shows the spelling of the current mode.

    Never applied to a whole document: a time inside a tag's attribute would be broken
    open by the element.
.PARAMETER Html
    Encoded text.
#>
function ConvertTo-HtmlTimeSpans {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Html
    )

    if ([string]::IsNullOrEmpty($Html) -or $Html.IndexOf(' UTC', [System.StringComparison]::Ordinal) -lt 0) {
        return $Html
    }
    return $Script:adPEASTimeTextRegex.Replace($Html, {
        param($match)
        $instant = ConvertFrom-adPEASTimeMatch $match
        if ($null -eq $instant) { return $match.Value }
        try {
            $minutes = -not $match.Groups['s'].Success
            $localText = Get-adPEASTimeText -UtcTime $instant -Minutes $minutes -AsUtc $false
            $utcText = Get-adPEASTimeText -UtcTime $instant -Minutes $minutes -AsUtc $true
            $shown = if ($Script:adPEASTimeUtc) { $utcText } else { $localText }
            return ('<span class="adp-time" data-local="' + $localText + '" data-utc="' + $utcText + '">' + $shown + '</span>')
        } catch {
            return $match.Value
        }
    })
}

<#
.SYNOPSIS
    The moment an age is measured from: now in a scan, the time a finding was collected
    when a report is rebuilt from it.
.DESCRIPTION
    A password age, an inactivity threshold, a scoring age were measured against the moment
    the report was drawn. A report rebuilt in June from a January export moved a password of
    2021-03-01 from 4.8 to 5.25 years and from Hint to Finding, and an account that was
    active at the scan read "INACTIVE". Export-HTMLReport and Convert-adPEASReport set
    $Script:adPEASReferenceTime to the finding's own time while they render it.
.OUTPUTS
    [datetime]
#>
function Get-adPEASReferenceTime {
    [CmdletBinding()]
    [OutputType([datetime])]
    param()

    if ($Script:adPEASReferenceTime -is [datetime]) { return $Script:adPEASReferenceTime }
    return (Get-Date)
}

<#
.SYNOPSIS
    Says in words which zone the times of a report are in, for its header.
.DESCRIPTION
    "UTC", or "Local time of the scan host (W. Europe Standard Time)". The zone is named by
    its identifier, which Windows does not translate; the offset is beside every value.
.PARAMETER Utc
    The report shows UTC.
#>
function Get-adPEASTimeZoneDescription {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$Utc
    )

    if ($Utc) { return 'UTC' }
    $zone = if ($Script:adPEASTimeZone) { $Script:adPEASTimeZone } else { [TimeZoneInfo]::Local }
    return "Local time of the scan host ($($zone.Id))"
}

<#
.SYNOPSIS
    The zone of this host (or of $Script:adPEASTimeZone) as a string the export can carry.
.DESCRIPTION
    The JSON export writes every instant in UTC; to show "local time of the scan host" when a
    report is rebuilt elsewhere, it also records the zone with its daylight saving rules
    (TimeZoneInfo.ToSerializedString), and Convert-adPEASReport rebuilds it from there.
#>
function Get-adPEASSerializedTimeZone {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $zone = if ($Script:adPEASTimeZone) { $Script:adPEASTimeZone } else { [TimeZoneInfo]::Local }
    try { return $zone.ToSerializedString() } catch { return $null }
}

<#
.SYNOPSIS
    Rebuilds a zone the JSON export recorded, or returns $null.
.PARAMETER Serialized
    The TimeZone field of an export.
#>
function ConvertFrom-adPEASSerializedTimeZone {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Serialized
    )

    if ([string]::IsNullOrWhiteSpace($Serialized)) { return $null }
    try { return [TimeZoneInfo]::FromSerializedString($Serialized) } catch { return $null }
}

<#
.SYNOPSIS
    Formats a length of time as hours:minutes:seconds, the hours counted in full.

.DESCRIPTION
    The TimeSpan format 'hh' is the hours component, 0 to 23, not the total: a session of
    26.5 hours read "02:30:00", a ticket valid for ten more years "(in 05:12:00)". And a
    TimeSpan built from seconds with -as [TimeSpan] counts ticks, so a clock seven minutes
    ahead read "Offset: -00:00:00". This counts the hours in full and puts a minus sign in
    front of a negative length.

.PARAMETER Duration
    The length of time.

.EXAMPLE
    Format-adPEASDuration ([TimeSpan]::FromHours(26.5))
    Returns "26:30:00".

.OUTPUTS
    [string] such as "26:30:00" or "-00:07:00".
#>
function Format-adPEASDuration {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [TimeSpan]$Duration
    )

    $sign = if ($Duration -lt [TimeSpan]::Zero) { '-' } else { '' }
    $abs = $Duration.Duration()
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    return ($sign + ([Math]::Floor($abs.TotalHours)).ToString('00', $inv) + ':' +
        $abs.Minutes.ToString('00', $inv) + ':' + $abs.Seconds.ToString('00', $inv))
}
