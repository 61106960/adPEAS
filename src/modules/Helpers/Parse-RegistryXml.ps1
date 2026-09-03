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
        # Loaded through XmlDocument rather than "[xml](Get-Content ...)".
        #
        # Get-Content without -Encoding reads a file with no BOM as the ANSI code page on
        # Windows PowerShell 5.1 and as UTF-8 on PowerShell 7. Registry.xml declares its
        # own encoding in the prolog, and XmlDocument.Load honours that declaration on
        # both hosts. Measured on 5.1: a BOM-less UTF-8 file containing the path
        # "C:\Program Files\Geraete\setup.exe" (with an a-umlaut) came back with the
        # umlaut split into two characters, so the deployed value was reported wrong.
        #
        # XmlResolver is cleared as well, as a statement of intent rather than a fix: this
        # file comes off SYSVOL, which is the share these checks look at precisely because
        # it may be writable by someone it should not be. Measured on both hosts, .NET
        # already refuses an external entity in an attribute value and does not fetch an
        # external DTD, so nothing was exploitable here - but that behaviour is a default
        # that has changed across framework versions, and this makes it not depend on it.
        $resolvedPath = (Resolve-Path -LiteralPath $XmlFilePath -ErrorAction Stop).ProviderPath

        $xml = New-Object System.Xml.XmlDocument
        $xml.XmlResolver = $null
        $xml.Load($resolvedPath)

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
