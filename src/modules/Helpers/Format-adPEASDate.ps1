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
    formats through InvariantCulture, whose calendar is Gregorian, and is the only way a
    date should be turned into a string anywhere in adPEAS.

    The standard specifiers 'o' and 's' already force the Gregorian calendar and need no
    help; every custom pattern ('yyyy-MM-dd', 'yyyyMMddHHmmss', ...) needs this.

    Two places deliberately do not call this and spell the invariant culture out inline
    instead, because what they produce is read by a machine rather than by a person and
    the contract belongs next to the code: the KerberosTime in
    Kerberos-ASN1.ps1 (New-ASN1GeneralizedTime) and the scheduled-task StartBoundary in
    Set-DomainGPO.ps1.

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
    DateTime of Kind Local - the local time of the host that runs adPEAS - and the report
    names that host's offset once instead of beside every value. A FILETIME attribute gets
    there through [DateTime]::FromFileTime; a Generalized Time value through this function,
    which is the only place that parses one.

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
    Names the offset every time adPEAS shows is in, once per report.

.DESCRIPTION
    The other half of the rule in ConvertFrom-adPEASGeneralizedTime: directory times are
    local times of the host that runs adPEAS, so the report states that host's offset in
    its header rather than beside each value. Taken at -At, so a report written in summer
    says +02:00 and one written in winter +01:00 - the offset its times were converted with.

.PARAMETER At
    The moment whose offset is named. Defaults to now.

.OUTPUTS
    [string] such as "UTC+01:00".
#>
function Get-adPEASTimeZoneLabel {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [datetime]$At = (Get-Date)
    )

    $offset = [TimeZoneInfo]::Local.GetUtcOffset($At)
    $sign = if ($offset -lt [TimeSpan]::Zero) { '-' } else { '+' }
    $abs = $offset.Duration()
    return ('UTC' + $sign + $abs.Hours.ToString('00', [System.Globalization.CultureInfo]::InvariantCulture) + ':' + $abs.Minutes.ToString('00', [System.Globalization.CultureInfo]::InvariantCulture))
}
