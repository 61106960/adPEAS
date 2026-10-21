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
    Array of PSCustomObject: Hive, Key, ValueName, Type, ValueInt, ValueString, ValueBytes
    (the data of a REG_BINARY value, $null for every other type)

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
        # An empty file holds no policy. One shorter than the eight-byte header, or with
        # another signature, is not a Registry.pol that could be read - and whatever it
        # was meant to deploy is unknown, which is not the same as nothing.
        if ($bytes.Length -eq 0) { return $records }
        if ($bytes.Length -lt 8 -or [System.Text.Encoding]::ASCII.GetString($bytes, 0, 4) -ne 'PReg') {
            Write-Log "[Parse-PRegRecords] Invalid PReg header: $PolFilePath"
            Register-SYSVOLFileGap -Path $PolFilePath -Reason 'could not be parsed'
            return $records
        }

        $pos = 8  # skip signature(4) + version(4)
        $len = $bytes.Length
        $malformed = $false

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
            if (-not ($pos -lt $len -and $bytes[$pos] -eq $semicolon)) { $malformed = $true; break }
            $pos += 2

            $valueName = (& $readString $ref)
            if (-not ($pos -lt $len -and $bytes[$pos] -eq $semicolon)) { $malformed = $true; break }
            $pos += 2

            if (($pos + 4) -gt $len) { $malformed = $true; break }
            $type = [System.BitConverter]::ToUInt32($bytes, $pos)
            $pos += 4
            if (-not ($pos -lt $len -and $bytes[$pos] -eq $semicolon)) { $malformed = $true; break }
            $pos += 2

            if (($pos + 4) -gt $len) { $malformed = $true; break }
            $size = [System.BitConverter]::ToUInt32($bytes, $pos)
            $pos += 4
            if (-not ($pos -lt $len -and $bytes[$pos] -eq $semicolon)) { $malformed = $true; break }
            $pos += 2

            if (($pos + $size) -gt $len) { $malformed = $true; break }
            $data = New-Object byte[] $size
            if ($size -gt 0) { [System.Array]::Copy($bytes, $pos, $data, 0, $size) }
            $pos += $size

            # Decode value depending on registry type
            $valueInt = $null
            $valueString = $null
            $valueBytes = $null
            switch ($type) {
                # REG_BINARY. Handed on as it is: TightVNC and TigerVNC keep their password
                # this way, and Get-CredentialExposure decrypts it.
                3  { $valueBytes = $data }
                4  { if ($data.Length -ge 4) { $valueInt = [System.BitConverter]::ToUInt32($data, 0) } }      # REG_DWORD
                5  {
                    # REG_DWORD_BIG_ENDIAN. BitConverter reads in the machine's byte
                    # order, so this used to come back byte-swapped: a stored 1 was
                    # reported as 16777216, and a check comparing against 1 saw nothing.
                    if ($data.Length -ge 4) {
                        $beBytes = New-Object byte[] 4
                        [System.Array]::Copy($data, 0, $beBytes, 0, 4)
                        [System.Array]::Reverse($beBytes)
                        $valueInt = [System.BitConverter]::ToUInt32($beBytes, 0)
                    }
                }
                11 { if ($data.Length -ge 8) { $valueInt = [System.BitConverter]::ToUInt64($data, 0) } }      # REG_QWORD
                1  { $valueString = [System.Text.Encoding]::Unicode.GetString($data).TrimEnd([char]0) }       # REG_SZ
                2  { $valueString = [System.Text.Encoding]::Unicode.GetString($data).TrimEnd([char]0) }       # REG_EXPAND_SZ
                7  {
                    # REG_MULTI_SZ is a run of null-terminated strings closed by an extra
                    # null. Trimming only the trailing nulls left the separators embedded
                    # in the middle of the string, so "eins<NUL>zwei<NUL>drei" reached the
                    # console and the report as one value with two null characters in it.
                    # Joined with ", " instead, which reads and greps.
                    $rawMulti = [System.Text.Encoding]::Unicode.GetString($data).TrimEnd([char]0)
                    $valueString = (($rawMulti -split "`0") | Where-Object { $_.Length -gt 0 }) -join ', '
                }
            }

            $records += [PSCustomObject]@{
                Hive        = $Hive
                Key         = $key
                ValueName   = $valueName
                Type        = $type
                ValueInt    = $valueInt
                ValueString = $valueString
                ValueBytes  = $valueBytes
            }

            # expect ']' - if not present, the loop's resync will find the next '['
        }

        # A record that broke off: the records before it are kept, and whatever followed
        # it was never read.
        if ($malformed) {
            Write-Log "[Parse-PRegRecords] Truncated or malformed record: $PolFilePath"
            Register-SYSVOLFileGap -Path $PolFilePath -Reason 'could not be parsed'
        }
    } catch {
        Write-Log "[Parse-PRegRecords] Error parsing $PolFilePath : $_"
        Register-SYSVOLFileGap -Path $PolFilePath -ErrorRecord $_
    }

    return $records
}
