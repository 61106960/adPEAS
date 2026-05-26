<#
.SYNOPSIS
    Decodes the Terminal Services property blob stored in userParameters / terminalServer.

.DESCRIPTION
    The userParameters attribute (and the related terminalServer attribute) carry a
    TSPropertyArray structure documented in [MS-TSTS] section 2.2.1.1. The blob holds
    legacy Terminal Services / Remote Desktop per-user settings such as the TS home
    directory, TS profile path, allow-logon flag, shadowing mode, and idle-timeout.

    Layout (little-endian):
        Reserved1 : 96 bytes  (48 WCHAR, usually all 0x20 0x00 = U+0020 spaces)
        Signature : 2 bytes   (WCHAR 'P' = 0x50 0x00)
        PropCount : 2 bytes   (USHORT, number of TSProperty entries)
        Properties: PropCount * TSPropertyStruct

    TSPropertyStruct:
        NameLength  : 2 bytes  (length of PropertyName in bytes)
        ValueLength : 2 bytes  (length of PropertyValue in bytes)
        Type        : 2 bytes  (1 = String, 2 = ULong)
        PropertyName: NameLength bytes (Unicode string)
        PropertyValue: ValueLength bytes (each output byte is encoded as 2 ASCII
                       characters where char = nibble + 0x30; 0..9 -> '0'..'9',
                       A..F -> ':'..'?')

.PARAMETER Bytes
    Raw byte[] read from LDAP. May be wrapped in a single-element array.

.OUTPUTS
    [string[]] - one human-readable line per recognised property. Returns $null when
    the blob does not look like a TSPropertyArray (signature mismatch).
#>
function ConvertFrom-TSProperties {
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

    # Need at least preamble + signature + count
    if ($Bytes.Length -lt 100) { return $null }

    # Validate signature: WCHAR 'P' at offset 96 (0x50 0x00 little-endian)
    if ($Bytes[96] -ne 0x50 -or $Bytes[97] -ne 0x00) { return $null }

    $propCount = [BitConverter]::ToUInt16($Bytes, 98)
    if ($propCount -lt 1 -or $propCount -gt 100) { return $null }  # sanity

    $offset = 100
    $lines = @()

    # Friendly labels for the well-known Ctx* property names
    $labelMap = @{
        'CtxCfgPresent'             = 'TSConfigPresent'
        'CtxCfgFlags1'              = 'TSConfigFlags'
        'CtxCallback'               = 'TSCallback'
        'CtxCallbackNumber'         = 'TSCallbackNumber'
        'CtxKeyboardLayout'         = 'TSKeyboardLayout'
        'CtxMinEncryptionLevel'     = 'TSMinEncryptionLevel'
        'CtxNWLogonServer'          = 'TSNetWareLogonServer'
        'CtxWFHomeDir'              = 'TSHomeDirectory'
        'CtxWFHomeDirDrive'         = 'TSHomeDrive'
        'CtxWFProfilePath'          = 'TSProfilePath'
        'CtxInitialProgram'         = 'TSInitialProgram'
        'CtxMaxConnectionTime'      = 'TSMaxConnectionTime'
        'CtxMaxDisconnectionTime'   = 'TSMaxDisconnectionTime'
        'CtxMaxIdleTime'            = 'TSMaxIdleTime'
        'CtxShadow'                 = 'TSShadowingSetting'
        'CtxWorkDirectory'          = 'TSWorkDirectory'
    }

    # Flag bits for CtxCfgFlags1 (only the ones useful for security review).
    # Use a plain hashtable, not [ordered]@{} - the OrderedDictionary indexer treats
    # integer arguments as positional indices, so $cfgFlags[0x20] returns the 32nd
    # entry (or fails) instead of the value under key 0x00000020. With @{} the
    # integer key lookup works as expected.
    $cfgFlags = @{
        0x00000008 = 'INHERIT_INITIAL_PROGRAM'
        0x00000010 = 'INHERIT_CALLBACK'
        0x00000020 = 'INHERIT_CALLBACK_NUMBER'
        0x00000040 = 'INHERIT_SHADOW'
        0x00000080 = 'INHERIT_MAX_DISCONNECTION_TIME'
        0x00000100 = 'INHERIT_MAX_CONNECTION_TIME'
        0x00000200 = 'INHERIT_MAX_IDLE_TIME'
        0x00000400 = 'INHERIT_AUTO_CLIENT'
        0x00010000 = 'AUTO_CLIENT_DRIVES'
        0x00020000 = 'AUTO_CLIENT_PRINTERS'
        0x00040000 = 'FORCE_CLIENT_PRINTER_DEFAULT'
        0x00080000 = 'DISABLE_ENCRYPTION'
        0x00100000 = 'HOMEDIR_MAP_ROOT'
        0x00200000 = 'USE_DEFAULT_GINA'
        0x00400000 = 'DISABLE_CPM'
        0x00800000 = 'DISABLE_CDM'
        0x01000000 = 'DISABLE_CCM'
        0x02000000 = 'DISABLE_LPT'
        0x04000000 = 'DISABLE_CLIP'
        0x08000000 = 'DISABLE_EXE'
        0x10000000 = 'WALLPAPER_DISABLED'
        0x40000000 = 'LOGON_DISABLED'
        0x80000000 = 'RECONNECT_SAME'
    }
    # Sorted ascending key list so flag enumeration is deterministic
    $cfgFlagKeys = ($cfgFlags.Keys | Sort-Object)

    try {
        for ($i = 0; $i -lt $propCount; $i++) {
            if ($offset + 6 -gt $Bytes.Length) { break }

            $nameLen  = [BitConverter]::ToUInt16($Bytes, $offset);     $offset += 2
            $valueLen = [BitConverter]::ToUInt16($Bytes, $offset);     $offset += 2
            $type     = [BitConverter]::ToUInt16($Bytes, $offset);     $offset += 2

            # Sanity: header lengths must point inside the buffer and the encoded
            # value must be an even number of bytes (two ASCII chars per output byte).
            if ($offset + $nameLen + $valueLen -gt $Bytes.Length) { break }
            if ($valueLen % 2 -ne 0) { break }

            $name = [System.Text.Encoding]::Unicode.GetString($Bytes, $offset, $nameLen)
            $offset += $nameLen

            # Decode value: each output byte = (nibbleHi - 0x30) << 4 | (nibbleLo - 0x30)
            # The valueLen is the length of the ENCODED ASCII representation, so the
            # decoded byte count is valueLen / 2.
            $decodedLen = [int]($valueLen / 2)
            $decoded = New-Object byte[] $decodedLen
            for ($k = 0; $k -lt $decodedLen; $k++) {
                $hi = $Bytes[$offset + ($k * 2)]     - 0x30
                $lo = $Bytes[$offset + ($k * 2) + 1] - 0x30
                $decoded[$k] = (($hi -shl 4) -bor $lo) -band 0xFF
            }
            $offset += $valueLen

            $label = if ($labelMap.ContainsKey($name)) { $labelMap[$name] } else { $name }

            switch ($type) {
                1 {
                    # String - decoded bytes are UTF-16LE Unicode (with trailing NULs)
                    $str = [System.Text.Encoding]::Unicode.GetString($decoded).TrimEnd([char]0)
                    if ($str) { $lines += "$label = '$str'" }
                }
                2 {
                    # ULong - decoded bytes are a 4-byte little-endian integer
                    if ($decoded.Length -ge 4) {
                        $val = [BitConverter]::ToUInt32($decoded, 0)
                        if ($name -eq 'CtxCfgFlags1') {
                            $setFlags = foreach ($mask in $cfgFlagKeys) {
                                if ($val -band $mask) { $cfgFlags[$mask] }
                            }
                            if ($setFlags) {
                                $lines += ("{0} = 0x{1:X8} ({2})" -f $label, $val, ($setFlags -join ', '))
                            } else {
                                $lines += ("{0} = 0x{1:X8}" -f $label, $val)
                            }
                        } elseif ($name -eq 'CtxCfgPresent') {
                            # 0xB00FA6C3 marker = configured at least once
                            $lines += ("{0} = 0x{1:X8}" -f $label, $val)
                        } else {
                            $lines += "$label = $val"
                        }
                    }
                }
                default {
                    $lines += "$label (type $type, $($decoded.Length) bytes)"
                }
            }
        }
    } catch {
        Write-Log "[ConvertFrom-TSProperties] Parse error: $_"
        return $null
    }

    if ($lines.Count -eq 0) { return $null }
    return $lines
}
