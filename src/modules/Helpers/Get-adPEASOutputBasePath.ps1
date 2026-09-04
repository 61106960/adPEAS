<#
.SYNOPSIS
    Turns a user-supplied output path into the base name the report files hang off.

.DESCRIPTION
    -Outputfile and -OutputPath are documented as taking a path "without extension":
    adPEAS appends .html, .txt and .json itself. Typing the extension anyway is a natural
    mistake, so one is removed as a courtesy - otherwise "-Outputfile report.html" would
    produce report.html.html.

    The courtesy applies only to the three extensions adPEAS writes. It used to apply to
    anything that looked like one, which in this tool is the common case rather than the
    exotic one: a report is usually named after the domain it covers, and ".com", ".local"
    and ".de" are indistinguishable from a file extension to Path.HasExtension. Asking for
    "scan_contoso.com" silently produced scan_contoso.html - a different file from the one
    requested, with nothing said about it.

        report.html            -> report
        report.JSON            -> report
        scan_contoso.com       -> scan_contoso.com
        2026-09-04_contoso.de  -> 2026-09-04_contoso.de
        scan_v1.2              -> scan_v1.2
        C:\out.dir\report      -> C:\out.dir\report

    Shared rather than repeated: the same three lines used to sit in adPEAS.ps1,
    Convert-adPEASReport and Compare-adPEASReport, and three copies of one rule are three
    chances for it to drift.

.PARAMETER Path
    The path as the user gave it, already resolved to a provider path.

.EXAMPLE
    Get-adPEASOutputBasePath 'C:\reports\scan_contoso.com'
    C:\reports\scan_contoso.com

.OUTPUTS
    [string] the base path, without a trailing dot.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
function Get-adPEASOutputBasePath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowEmptyString()]
        [string]$Path
    )

    if ([string]::IsNullOrEmpty($Path)) { return $Path }

    # The complete set adPEAS ever appends to a base path. Kept here rather than in a
    # script-level table because this is the only place that needs to know it.
    $ownExtensions = @('.html', '.txt', '.json')

    $extension = [System.IO.Path]::GetExtension($Path)
    if ([string]::IsNullOrEmpty($extension)) { return $Path }
    if ($ownExtensions -notcontains $extension.ToLowerInvariant()) { return $Path }

    $trimmed = $Path.Substring(0, $Path.Length - $extension.Length)

    # A path that is nothing but an extension - ".html", or "C:\out\.json" - would be left
    # with no file name at all. Better to leave it alone than to hand back a directory.
    if ([string]::IsNullOrEmpty([System.IO.Path]::GetFileName($trimmed))) { return $Path }

    return $trimmed
}
