<#
.SYNOPSIS
    Shortens a SYSVOL path to the part that sits inside the GPO's own folder.

.DESCRIPTION
    Turns

      \\dc01.contoso.com\SYSVOL\contoso.com\Policies\{31B2F340-...}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf

    into

      MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf

    A GPO finding already names the policy by GUID, and the GUID is the folder name, so
    repeating the server, the domain and the Policies segment on every row costs width
    without carrying information. What a reader still needs is which file inside that
    folder produced the setting - MACHINE or USER above all, because the same file name
    occurs under both and the two halves reach different targets. Reporting a bare file
    name instead loses exactly that distinction.

    Anchored on \Policies\{GUID}\ rather than on the SYSVOL base string: the base is not
    in scope at every point a finding is built, and the cache may have walked the path via
    a server name where the caller knows only the domain.

    A path outside a Policies\{GUID} folder - NETLOGON, or a custom -Path scan - is
    returned unchanged. There is no GPO folder to make it relative to, and shortening it
    to its leaf would throw away the only location the reader has.

    This sits in a file of its own rather than beside the SYSVOL cache in
    Invoke-SMBAccess.ps1, where it started. That file's functions reach the network and
    are therefore replaced by stubs in the test seam, so a suite cannot load it to get at
    one pure string helper without losing the stubs it needs. Pure logic has to be
    loadable on its own.

.PARAMETER Path
    Full path to a file below SYSVOL.

.OUTPUTS
    [string] The path relative to the GPO folder, the input unchanged if it is not below
    one, or $null for empty input.

.EXAMPLE
    Get-GPORelativePath -Path "\\contoso.com\SYSVOL\contoso.com\Policies\{AAAA}\Machine\Registry.pol"
    Machine\Registry.pol

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
function Get-GPORelativePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    if ($Path -match '(?i)\\Policies\\\{[^}]*\}\\(.+)$') {
        return $Matches[1]
    }

    return $Path
}

<#
.SYNOPSIS
    Maps each GPO's GUID to the SYSVOL path the directory records for it.

.DESCRIPTION
    Every GPO finding names its policy with the same three rows - GPOName, GPOGUID and
    GPOPath - whether the check reports the GPO object itself or a setting found inside
    one. This builds the lookup the setting-level checks need for the third of those.

    The path is read from the directory, not assembled from the GUID, and that is the
    whole reason this function exists. gPCFileSysPath names the domain:

        \\contoso.com\sysvol\contoso.com\Policies\{AAAA...}

    while the SYSVOL file cache walks one specific controller:

        \\dc01.contoso.com\SYSVOL\contoso.com\Policies\{AAAA...}

    Both are the same folder, and a reader comparing two sections of one report should not
    have to work that out. Deriving the row from the file path a check happened to open
    would print the second spelling next to the first.

    Keys are upper-cased to match the other GPO lookups, which compare a GUID taken out of
    a SYSVOL path against one read from LDAP; the two do not reliably agree on case.

.PARAMETER GPO
    The GPO objects the caller already fetched with Get-DomainGPO.

.OUTPUTS
    [hashtable] GUID, upper case and with braces, mapped to its gPCFileSysPath. Empty when
    nothing was passed. A GPO whose gPCFileSysPath is absent is left out, so a caller can
    tell "no path recorded" from "path is empty".

.EXAMPLE
    $gpoPathMap = Get-GPOPathMap -GPO $gpos
    $gpoPathMap['{31B2F340-016D-11D2-945F-00C04FB984F9}']

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
function Get-GPOPathMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        $GPO
    )

    $map = @{}

    foreach ($entry in @($GPO)) {
        if (-not $entry) { continue }

        # Get-DomainGPO returns the GUID as Name; Get-LAPSGPOConfig reads the same value
        # from cn. Accept either so both kinds of caller can use this.
        $guid = if ($entry.Name) { $entry.Name } elseif ($entry.cn) { $entry.cn } else { $null }
        if (-not $guid) { continue }

        if ([string]::IsNullOrWhiteSpace($entry.gPCFileSysPath)) { continue }

        $map[([string]$guid).ToUpper()] = [string]$entry.gPCFileSysPath
    }

    return $map
}
