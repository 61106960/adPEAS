<#
.SYNOPSIS
    Reads the [Registry Values] section of a GPO GptTmpl.inf into registry value records.

.DESCRIPTION
    A GPO can deliver a registry value three ways, and GptTmpl.inf is the third: Security
    Options from the GPMC node "Computer Configuration \ Policies \ Windows Settings \
    Security Settings \ Local Policies \ Security Options" are written to
    Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf in a [Registry Values] section, one
    line per value:

        MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,0

    The number before the comma is the registry type, the rest is the value. For the
    settings that have a Security Option - the LAN Manager authentication level, the two
    anonymous-enumeration restrictions, the UAC switches, the machine password settings -
    this is the normal delivery path, not Registry.pol and not Registry.xml.

    Records use the same shape as Parse-PRegRecords and Parse-RegistryXml (Hive, Key,
    ValueName, Type, ValueInt, ValueString), so all three parsers feed one evaluation.

    The section is cut at a line that begins with '[' rather than at the next '['
    character anywhere in the text. Three callers used '(?s)\[Registry Values\](.*?)(\[|$)'
    and all three were wrong in the same way: the section is sorted by key, so
    MACHINE\Software\... entries come before MACHINE\System\..., and a value that
    contains a bracket - a logon banner reading "Zugang nur fuer [autorisierte] Nutzer" is
    the realistic case - truncated the section at that bracket and silently dropped every
    line after it.

.NOTES
    Author: Alexander Sturz (@_61106960_)
    Part of adPEAS v2 - Active Directory Privilege Escalation Awesome Scripts

    Reference: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj966254(v=ws.11)
               Registry type codes are the ones %WINDIR%\inf\sceregvl.inf declares.
#>

# Type code -> the name Parse-PRegRecords and Parse-RegistryXml use for the same type.
# 2 (REG_EXPAND_SZ) and 7 (REG_MULTI_SZ) carry text, 4 (REG_DWORD) and 11 (REG_QWORD) a
# number; 3 (REG_BINARY) is kept as text because nothing in the project evaluates one.
$Script:GptTmplRegistryTypes = @{
    1  = 'REG_SZ'
    2  = 'REG_EXPAND_SZ'
    3  = 'REG_BINARY'
    4  = 'REG_DWORD'
    7  = 'REG_MULTI_SZ'
    11 = 'REG_QWORD'
}

<#
.SYNOPSIS
    Returns the raw [Registry Values] section of a GptTmpl.inf, or an empty string.
.DESCRIPTION
    Split out because three checks need the section itself rather than parsed records, and
    the anchoring is the part that has to be identical everywhere.
.PARAMETER Content
    The whole file content as one string.
#>
function Get-GptTmplRegistrySection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Content
    )

    if ([string]::IsNullOrEmpty($Content)) { return '' }

    # ^\[ in multiline mode: the section ends at the next SECTION HEADER, which is a '['
    # at the start of a line - not at the next '[' character, which may sit inside a value.
    if ($Content -match '(?sm)^\[Registry Values\][^\r\n]*\r?\n(.*?)(?=^\[|\z)') {
        return [string]$Matches[1]
    }

    return ''
}

<#
.SYNOPSIS
    Parses the [Registry Values] section of a GptTmpl.inf into registry value records.
.PARAMETER Content
    The whole file content as one string. Callers that hold the content already (from the
    SYSVOL content cache) pass it here rather than reading the file a second time.
.PARAMETER InfFilePath
    A GptTmpl.inf to read instead of passing -Content. Read as UTF-8 with the byte-order
    mark honoured, never through Get-Content without -Encoding: a file with no BOM decodes
    as the ANSI code page on Windows PowerShell 5.1 and as UTF-8 on PowerShell 7, and a
    value containing a non-ASCII character then differs between the two hosts.
.OUTPUTS
    An array of PSCustomObject with Hive, Key, ValueName, Type, ValueInt, ValueString.
#>
function Parse-GptTmplRegistryValues {
    [CmdletBinding(DefaultParameterSetName = 'ByContent')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'ByContent')]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Content,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByPath')]
        [string]$InfFilePath
    )

    $records = @()

    try {
        $text = $Content
        if ($PSCmdlet.ParameterSetName -eq 'ByPath') {
            if (-not (Test-Path -LiteralPath $InfFilePath)) { return $records }
            $text = [System.IO.File]::ReadAllText($InfFilePath, [System.Text.Encoding]::UTF8)
        }

        $section = Get-GptTmplRegistrySection -Content $text
        if ([string]::IsNullOrWhiteSpace($section)) { return $records }

        foreach ($rawLine in ($section -split "`r?`n")) {
            $line = $rawLine.Trim()
            if (-not $line) { continue }
            if ($line.StartsWith(';')) { continue }

            # <hive>\<key>\<valuename>=<type>,<value>
            # The value may itself contain commas and equals signs, so only the first of
            # each is a delimiter.
            $eq = $line.IndexOf('=')
            if ($eq -lt 1) { continue }

            $fullPath = $line.Substring(0, $eq).Trim()
            $rhs      = $line.Substring($eq + 1).Trim()

            $comma = $rhs.IndexOf(',')
            if ($comma -lt 1) { continue }

            $typeCode = 0
            if (-not [int]::TryParse($rhs.Substring(0, $comma).Trim(), [ref]$typeCode)) { continue }
            $rawValue = $rhs.Substring($comma + 1)

            # MACHINE\ is the only prefix a Security Option uses, and the Key fields of
            # $Script:DangerousRegistryKeys are written without a hive, so the prefix comes
            # off and the hive becomes HKLM. A USER\ prefix exists in the format and is
            # mapped as well rather than silently treated as machine scope.
            $hive = $null
            $path = $fullPath
            if ($path -imatch '^MACHINE\\(.+)$')   { $hive = 'HKLM'; $path = $Matches[1] }
            elseif ($path -imatch '^USER\\(.+)$')  { $hive = 'HKCU'; $path = $Matches[1] }
            else { continue }

            $lastSep = $path.LastIndexOf('\')
            if ($lastSep -lt 1) { continue }
            $key       = $path.Substring(0, $lastSep)
            $valueName = $path.Substring($lastSep + 1)
            if (-not $valueName) { continue }

            $typeName = if ($Script:GptTmplRegistryTypes.ContainsKey($typeCode)) {
                $Script:GptTmplRegistryTypes[$typeCode]
            } else {
                "REG_TYPE_$typeCode"
            }

            $valueInt = $null
            $valueString = $null
            if ($typeName -match 'DWORD|QWORD') {
                $parsedValue = [int64]0
                if ([int64]::TryParse($rawValue.Trim(), [ref]$parsedValue)) {
                    $valueInt = $parsedValue
                }
            } else {
                # A REG_MULTI_SZ is written as one line with its elements separated by
                # commas; kept verbatim, because no evaluation in the project splits one.
                $valueString = $rawValue.Trim().Trim('"')
            }

            $records += [PSCustomObject]@{
                Hive        = $hive
                Key         = $key
                ValueName   = $valueName
                Type        = $typeName
                ValueInt    = $valueInt
                ValueString = $valueString
            }
        }
    } catch {
        $where = if ($PSCmdlet.ParameterSetName -eq 'ByPath') { $InfFilePath } else { 'the supplied content' }
        Write-Log "[Parse-GptTmplRegistryValues] Error parsing $where : $_"
    }

    return $records
}
