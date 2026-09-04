<#
.SYNOPSIS
    Turns an Active Directory interval attribute into a TimeSpan.

.DESCRIPTION
    The domain policy intervals - maxPwdAge, minPwdAge, lockoutDuration,
    lockOutObservationWindow, forceLogoff - are stored as NEGATIVE 100-nanosecond deltas,
    not as timestamps. They reach a check as the raw interval string, because
    ConvertFrom-LDAPAttribute's FileTime branch claims those attribute names,
    [DateTime]::FromFileTime throws on a negative delta and the raw value falls through.
    That is deliberate: the collector's BloodHound export needs the raw number, so the
    conversion belongs to whoever displays the value, not to the LDAP layer.

    "Whoever displays the value" was two modules doing the same arithmetic in four places
    each - absolute value, divide by a ticks-per-unit constant, and catch the Int64.MinValue
    sentinel. This is that arithmetic, once.

    Formatting stays with the caller on purpose: Get-DomainPasswordPolicy wants whole days
    and whole minutes, the collector wants "42 days" / "3 hours" / "30 minutes", and a
    third caller may want the number. A TimeSpan serves all three; a preformatted string
    would have to be parsed back, which is exactly what the duplicated code used to do.

    An already formatted "N days" / "N hours" / "N minutes" is accepted as well. Nothing
    produces that today, and the tests pin that nothing does - but if the LDAP layer is
    ever changed to convert these attributes itself, the alternative is worse than the
    extra regex: every domain would suddenly read maxPwdAge as 0 and be reported as
    "password never expires", a Finding, on every single scan. The guard used to sit in
    each caller; it belongs here now that the arithmetic does.

.PARAMETER Value
    The raw attribute value, normally the negative interval as a string. A number, an
    already-typed TimeSpan, a formatted "N days" string, $null and unparseable text are
    all accepted.

.OUTPUTS
    [TimeSpan] - the duration, always positive, or
    [TimeSpan]::Zero when the attribute is 0 ("not set" / "until manually unlocked",
    depending on the attribute), or
    $null when there is no finite duration: the Int64.MinValue "never" sentinel, an empty
    value, or something that is not an interval at all. Callers distinguish those three
    cases, so none of them may collapse into another.

.EXAMPLE
    ConvertFrom-ADInterval -Value '-36288000000000'
    Returns a TimeSpan of 42 days.

.EXAMPLE
    ConvertFrom-ADInterval -Value '-9223372036854775808'
    Returns $null - the "never" sentinel, not a duration of 29227 years.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
function ConvertFrom-ADInterval {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        $Value
    )

    process {
        if ($null -eq $Value) { return $null }
        if ($Value -is [TimeSpan]) { return $Value }

        $text = [string]$Value
        if ([string]::IsNullOrWhiteSpace($text)) { return $null }

        $text = $text.Trim()

        $ticks = 0L
        if (-not [Int64]::TryParse($text, [ref]$ticks)) {
            # Not a raw interval. An already formatted duration still yields one - see the
            # note in the description. "Disabled", "Never" and "Not set" deliberately do
            # not match: they are not durations, and $null is the right answer for them.
            if ($text -match '^(\d+)\s*(day|hour|minute)s?$') {
                $count = [int]$Matches[1]
                switch ($Matches[2]) {
                    'day'    { return [TimeSpan]::FromDays($count) }
                    'hour'   { return [TimeSpan]::FromHours($count) }
                    'minute' { return [TimeSpan]::FromMinutes($count) }
                }
            }

            # A DateTime the FileTime branch did convert, or junk. No duration to report.
            return $null
        }

        if ($ticks -eq 0) { return [TimeSpan]::Zero }

        # Int64.MinValue is the documented "never" sentinel. Its absolute value also
        # overflows, so it has to be caught before [Math]::Abs, not after. Anything within
        # a rounding error of the Int64 range means the same thing in practice.
        if ([Math]::Abs([double]$ticks) -ge 9223372036854775000) { return $null }

        return [TimeSpan]::FromTicks([Math]::Abs($ticks))
    }
}
