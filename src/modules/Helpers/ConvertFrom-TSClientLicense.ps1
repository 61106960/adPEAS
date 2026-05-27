<#
.SYNOPSIS
    Decodes the legacy Terminal Server Per-User CAL token stored in the
    terminalServer attribute.

.DESCRIPTION
    The terminalServer attribute (1.2.840.113556.1.4.1410) is written by
    Remote Desktop Licensing the first time a user receives a Per-User CAL.
    The layout is not part of any public ADSI specification; the structure
    below was reconstructed empirically against TS 6.x (Server 2008 R2) and
    later RDS deployments:

        UInt32 LE  : Version / marker (0x00060000 for TS 6.x)
        FILETIME   : Token issue timestamp (UTC)
        WCHAR[]    : Null-terminated Windows Product ID of the licensed
                     instance, format XXXXX-XXX-XXXXXXX-XXXXX

    A typical record is 60 bytes (4 + 8 + 23 * 2 + 2 NUL terminator).

    NOTE: This format is unrelated to the TSPropertyArray held by the
    userParameters attribute - use ConvertFrom-TSProperties for that.

.PARAMETER Bytes
    Raw byte[] read from LDAP. May be wrapped in a single-element array.

.OUTPUTS
    [string[]] - one human-readable line per decoded field. Returns $null
    when the blob is too short, the FILETIME is implausible, or the data
    otherwise does not look like a CAL token.
#>
function ConvertFrom-TSClientLicense {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Bytes
    )

    # Unwrap single-element array
    if ($Bytes -is [array] -and $Bytes.Count -eq 1 -and $Bytes[0] -is [byte[]]) {
        $Bytes = $Bytes[0]
    }
    if ($Bytes -isnot [byte[]]) { return $null }

    # Minimum: 4 (version) + 8 (FILETIME) + 2 (WCHAR NUL terminator) = 14
    if ($Bytes.Length -lt 14) { return $null }

    $version  = [BitConverter]::ToUInt32($Bytes, 0)
    $fileTime = [BitConverter]::ToInt64($Bytes, 4)

    # Per-User CAL tracking was introduced with Server 2008; reject FILETIMEs
    # outside [2005, 2099] as a quick sanity check that this is really a CAL token.
    $issued = $null
    try { $issued = [DateTime]::FromFileTimeUtc($fileTime) } catch { return $null }
    if ($issued.Year -lt 2005 -or $issued.Year -gt 2099) { return $null }

    # Trailing UTF-16LE NUL-terminated Product ID string
    $strBytes  = $Bytes[12..($Bytes.Length - 1)]
    $productId = [System.Text.Encoding]::Unicode.GetString($strBytes).TrimEnd([char]0)

    $lines = @()
    $lines += ("Version = 0x{0:X8}" -f $version)
    $lines += ("Issued = {0:yyyy-MM-dd HH:mm:ss} UTC" -f $issued)
    if ($productId) { $lines += "ProductID = '$productId'" }
    return $lines
}
