<#
.SYNOPSIS
    Parses a GPO Registry.pol file (PReg binary format) into individual registry value records.

.DESCRIPTION
    Registry.pol is the binary format used by Group Policy Administrative Templates to store
    registry values (as opposed to Group Policy Preferences, which use Registry.xml). This is
    a byte-offset binary parser - not a text/regex search - so it correctly handles binary
    Type/Size fields regardless of what byte values they happen to contain.

    Format: "PReg" + version(4) + records of [key;value;type;size;data]
    Strings are null-terminated UTF-16LE; separators ';' '[' ']' are UTF-16LE literals.
    Ref: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/registry-policy-file-format

.PARAMETER PolFilePath
    Full path to the Registry.pol file.

.PARAMETER Hive
    Hive label to stamp on each returned record (e.g. 'Machine' or 'User') - purely
    informational, based on which SYSVOL subfolder the file was read from.

.OUTPUTS
    Array of PSCustomObject: Hive, Key, ValueName, Type, ValueInt, ValueString

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
function Parse-PRegRecords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$PolFilePath,

        [Parameter(Mandatory=$true)]
        [string]$Hive
    )

    $records = @()

    try {
        $bytes = [System.IO.File]::ReadAllBytes($PolFilePath)
        if ($bytes.Length -lt 8) { return $records }
        if ([System.Text.Encoding]::ASCII.GetString($bytes, 0, 4) -ne 'PReg') {
            Write-Log "[Parse-PRegRecords] Invalid PReg header: $PolFilePath"
            return $records
        }

        $pos = 8  # skip signature(4) + version(4)
        $len = $bytes.Length

        # Local reader for null-terminated UTF-16LE strings; advances $pos past terminator
        $readString = {
            param([ref]$p)
            $start = $p.Value
            while (($p.Value + 1) -lt $len) {
                if ($bytes[$p.Value] -eq 0 -and $bytes[$p.Value + 1] -eq 0) { break }
                $p.Value += 2
            }
            $strLen = $p.Value - $start
            $s = ''
            if ($strLen -gt 0) { $s = [System.Text.Encoding]::Unicode.GetString($bytes, $start, $strLen) }
            $p.Value += 2  # consume null terminator
            return $s
        }

        $openBracket = 0x5B   # [
        $semicolon   = 0x3B   # ;

        while ($pos -lt $len) {
            # Find next '[' (0x5B 0x00)
            if (-not ($bytes[$pos] -eq $openBracket -and ($pos + 1) -lt $len -and $bytes[$pos + 1] -eq 0)) {
                $pos += 2
                continue
            }
            $pos += 2

            $ref = [ref]$pos
            $key = (& $readString $ref)
            # expect ';'
            if (-not ($pos -lt $len -and $bytes[$pos] -eq $semicolon)) { break }
            $pos += 2

            $valueName = (& $readString $ref)
            if (-not ($pos -lt $len -and $bytes[$pos] -eq $semicolon)) { break }
            $pos += 2

            if (($pos + 4) -gt $len) { break }
            $type = [System.BitConverter]::ToUInt32($bytes, $pos)
            $pos += 4
            if (-not ($pos -lt $len -and $bytes[$pos] -eq $semicolon)) { break }
            $pos += 2

            if (($pos + 4) -gt $len) { break }
            $size = [System.BitConverter]::ToUInt32($bytes, $pos)
            $pos += 4
            if (-not ($pos -lt $len -and $bytes[$pos] -eq $semicolon)) { break }
            $pos += 2

            if (($pos + $size) -gt $len) { break }
            $data = New-Object byte[] $size
            if ($size -gt 0) { [System.Array]::Copy($bytes, $pos, $data, 0, $size) }
            $pos += $size

            # Decode value depending on registry type
            $valueInt = $null
            $valueString = $null
            switch ($type) {
                4  { if ($data.Length -ge 4) { $valueInt = [System.BitConverter]::ToUInt32($data, 0) } }      # REG_DWORD
                5  { if ($data.Length -ge 4) { $valueInt = [System.BitConverter]::ToUInt32($data, 0) } }      # REG_DWORD_BIG_ENDIAN (rare)
                11 { if ($data.Length -ge 8) { $valueInt = [System.BitConverter]::ToUInt64($data, 0) } }      # REG_QWORD
                1  { $valueString = [System.Text.Encoding]::Unicode.GetString($data).TrimEnd([char]0) }       # REG_SZ
                2  { $valueString = [System.Text.Encoding]::Unicode.GetString($data).TrimEnd([char]0) }       # REG_EXPAND_SZ
                7  { $valueString = ([System.Text.Encoding]::Unicode.GetString($data).TrimEnd([char]0)) }     # REG_MULTI_SZ
            }

            $records += [PSCustomObject]@{
                Hive        = $Hive
                Key         = $key
                ValueName   = $valueName
                Type        = $type
                ValueInt    = $valueInt
                ValueString = $valueString
            }

            # expect ']' - if not present, the loop's resync will find the next '['
        }
    } catch {
        Write-Log "[Parse-PRegRecords] Error parsing $PolFilePath : $_"
    }

    return $records
}
