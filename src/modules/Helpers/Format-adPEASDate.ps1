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
