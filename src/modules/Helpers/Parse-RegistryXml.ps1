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

        # An empty file deploys nothing. Loaded, it fails as XML without a root element, and
        # would be recorded as a file that could not be parsed - a gap with nothing in it.
        if ((Get-Item -LiteralPath $resolvedPath -ErrorAction Stop).Length -eq 0) { return $records }

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
                # GPMC writes a GPP DWORD as eight hexadecimal digits, zero padded, and that
                # is what the hex branch is for. A plain decimal number matches the same
                # character class, though, and was read as hex: a hand-written or
                # third-party Registry.xml saying value="10" came out as 16, and value="31"
                # as 49 - which drops the 0x4 bit the Schannel UPN mapping check looks for.
                #
                # So the shape decides: eight digits or more, or a hex letter anywhere, is
                # the GPMC form; a short all-digit value is decimal.
                $parsed = $null
                $looksHex = ($rawValue -match '^[0-9A-Fa-f]{8,}$') -or ($rawValue -match '^[0-9A-Fa-f]*[A-Fa-f][0-9A-Fa-f]*$')
                if ($looksHex) {
                    try { $parsed = [System.Convert]::ToInt64($rawValue, 16) } catch { $parsed = $null }
                }
                if ($null -eq $parsed -and $rawValue -match '^\d+$') {
                    try { $parsed = [System.Convert]::ToInt64($rawValue, 10) } catch { $parsed = $null }
                }
                $valueInt = $parsed
            } else {
                $valueString = $rawValue
            }

            # The GPP semantics, which used to be dropped here. action is C(reate),
            # R(eplace), U(pdate) or D(elete) and defaults to U when absent; disabled="1"
            # on the item means Group Policy never applies it at all. Without these two a
            # GPO that REMOVES EnableLUA - the cleanup an administrator performs after an
            # audit - was reported as "User Account Control disabled", and a preference
            # item switched off in the editor read as an active misconfiguration. The
            # Registry.pol side of the same question is already handled: a value name
            # starting with "**del." is skipped there.
            $action = [string]$props.action
            if ([string]::IsNullOrWhiteSpace($action)) { $action = 'U' }

            $records += [PSCustomObject]@{
                Hive        = $hive
                Key         = [string]$props.key
                ValueName   = [string]$props.name
                Type        = $type
                ValueInt    = $valueInt
                ValueString = $valueString
                Action      = $action.ToUpper()
                Disabled    = ([string]$node.disabled -eq '1')
            }
        }
    } catch {
        Write-Log "[Parse-RegistryXml] Error parsing $XmlFilePath : $_"
        Register-SYSVOLFileGap -Path $XmlFilePath -ErrorRecord $_
    }

    return $records
}
