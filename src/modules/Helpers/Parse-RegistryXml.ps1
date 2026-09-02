<#
.SYNOPSIS
    Parses a GPO Registry.xml file (Group Policy Preferences format) into registry value records.

.DESCRIPTION
    Registry.xml is the XML format used by Group Policy Preferences to deploy registry values,
    as opposed to Administrative Templates which use the binary Registry.pol (PReg) format.
    Both mechanisms can deliver the same value, so a check that only parses one of them misses
    half of the deployed configuration.

    Output records use the same shape as Parse-PRegRecords (Hive, Key, ValueName, Type,
    ValueInt, ValueString) so both parsers can feed the same evaluation logic.

    Unlike Registry.pol, Registry.xml carries the hive explicitly per item, so the hive is read
    from the XML rather than derived from the file location.

.NOTES
    Author: Alexander Sturz (@_61106960_)
    Part of adPEAS v2 - Active Directory Privilege Escalation Awesome Scripts

    Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/
#>
function Parse-RegistryXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$XmlFilePath
    )

    $records = @()

    try {
        [xml]$xml = Get-Content -Path $XmlFilePath -ErrorAction Stop

        $regNodes = $xml.SelectNodes("//Registry")
        if (-not $regNodes) { return $records }

        foreach ($node in $regNodes) {
            $props = $node.Properties
            if (-not $props) { continue }

            # Normalize hive
            $hiveRaw = [string]$props.hive
            $hive = $null
            switch -Wildcard ($hiveRaw.ToUpper()) {
                'HKEY_LOCAL_MACHINE*' { $hive = 'HKLM' }
                'HKLM*'               { $hive = 'HKLM' }
                'HKEY_CURRENT_USER*'  { $hive = 'HKCU' }
                'HKCU*'               { $hive = 'HKCU' }
                default               { $hive = $hiveRaw }
            }

            $type = [string]$props.type
            $rawValue = [string]$props.value

            $valueInt = $null
            $valueString = $null
            if ($type -match 'DWORD|QWORD') {
                # GPP stores DWORD/QWORD values as hexadecimal in the XML value attribute
                $parsed = $null
                if ($rawValue -match '^[0-9A-Fa-f]+$') {
                    try { $parsed = [System.Convert]::ToInt64($rawValue, 16) } catch { $parsed = $null }
                }
                if ($null -eq $parsed -and $rawValue -match '^\d+$') {
                    try { $parsed = [System.Convert]::ToInt64($rawValue, 10) } catch { $parsed = $null }
                }
                $valueInt = $parsed
            } else {
                $valueString = $rawValue
            }

            $records += [PSCustomObject]@{
                Hive        = $hive
                Key         = [string]$props.key
                ValueName   = [string]$props.name
                Type        = $type
                ValueInt    = $valueInt
                ValueString = $valueString
            }
        }
    } catch {
        Write-Log "[Parse-RegistryXml] Error parsing $XmlFilePath : $_"
    }

    return $records
}
