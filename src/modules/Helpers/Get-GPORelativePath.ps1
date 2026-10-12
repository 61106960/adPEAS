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
    Which half of a GPO delivers a registry value: Machine or User.

.DESCRIPTION
    The half is a property of the folder the file came out of, not of the hive the value
    writes. For Registry.pol the two always agree, because the hive is derived from the
    folder in the first place. For a Group Policy Preference item they can differ: GPP
    carries the hive per item in the XML, and an item under User\Preferences\Registry may
    write HKEY_LOCAL_MACHINE - that is a choice in the GPP editor.

    The half decides which status flag has to be enabled for the value to arrive. A GPO
    with its user configuration disabled delivers nothing from its User folder, whatever
    hive the items in there write.

    The hive is the fallback, for a source path that says nothing: a custom scan outside a
    Policies\{GUID} folder, or a record without a source.

.PARAMETER SourceFile
    The path inside the GPO folder, as Get-GPORelativePath returns it. May name several
    files separated by commas, which is the form the Point and Print check carries.

.PARAMETER RegistryKey
    The key or hive of the value. Read only when the source says nothing.

.OUTPUTS
    [string] "Machine" or "User".

.EXAMPLE
    Get-GPOHalfFromSource -SourceFile "User\Preferences\Registry\Registry.xml" -RegistryKey "HKLM\Software\..."
    User

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
function Get-GPOHalfFromSource {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$SourceFile,

        [Parameter(Mandatory = $false)]
        [string]$RegistryKey
    )

    $source = [string]$SourceFile
    if (-not [string]::IsNullOrWhiteSpace($source)) {
        # Per named file, because one row can carry several - the Point and Print check
        # joins the sources of a bucket with a comma. StartsWith rather than a regex: the
        # separator is a backslash, and a pattern built around escaped backslashes is the
        # kind of literal that breaks silently when the file is edited.
        $pieces = @($source -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })

        # Machine wins a bucket that names files from both halves: those values reach every
        # computer in scope, and holding them back because a user-side sibling is disabled
        # is the worse of the two errors.
        foreach ($piece in $pieces) {
            if ($piece.StartsWith('Machine' + [char]0x5C, [System.StringComparison]::OrdinalIgnoreCase)) { return 'Machine' }
        }
        foreach ($piece in $pieces) {
            if ($piece.StartsWith('User' + [char]0x5C, [System.StringComparison]::OrdinalIgnoreCase)) { return 'User' }
        }
    }

    if ("$RegistryKey" -like "HKLM*") { return "Machine" }
    return "User"
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
