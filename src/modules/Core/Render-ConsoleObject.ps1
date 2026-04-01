<#
.SYNOPSIS
    Console renderer for adPEAS RenderModel objects.

.DESCRIPTION
    Iterates over a RenderModel and outputs each row to the console using Write-adPEASAttribute from Write-adPEASOutput.ps1.
    Multi-value rendering is handled inline with per-value severity coloring.

    This is a "dumb" renderer - all business logic (severity, attribute selection, transformations) has already been resolved by Get-RenderModel.

.NOTES
    Author: Alexander Sturz (@_61106960_)
    Requires: Write-adPEASOutput.ps1 (Write-adPEASAttribute, Show-EmptyLine)
#>

<#
.SYNOPSIS
    Renders a RenderModel to the console.
.DESCRIPTION
    Iterates over Primary and PostObject rows and renders each one.
    Extended rows are NOT shown in console (they are HTML-only collapsible).
.PARAMETER Model
    The RenderModel object produced by Get-RenderModel.
.PARAMETER AlignAt
    Column width for attribute alignment (default: 45).
#>
function Render-ConsoleObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Model,

        [Parameter(Mandatory=$false)]
        [int]$AlignAt = 45
    )

    $outputSomething = $false

    # Render Primary rows (always visible)
    foreach ($row in $Model.Primary) {
        Render-ConsoleRow -Row $row -AlignAt $AlignAt
        $outputSomething = $true
    }

    # Render PostObject rows (roasting hashes - special format)
    foreach ($row in $Model.PostObject) {
        Render-ConsolePostObjectRow -Row $row
        $outputSomething = $true
    }

    # Trailing empty line after object
    if ($outputSomething) {
        Show-EmptyLine
    }
}

<#
.SYNOPSIS
    Renders a single RenderRow to the console.
.DESCRIPTION
    Dispatches to the appropriate output function based on RowType:
    - SingleValue: Write-adPEASAttribute
    - MultiValue: Inline per-value coloring
    - Image: Write-adPEASAttribute (with DisplayText)
    - Hash: handled by PostObject
#>
function Render-ConsoleRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Row,

        [Parameter(Mandatory=$false)]
        [int]$AlignAt = 45
    )

    switch ($Row.RowType) {
        'SingleValue' {
            $val = $Row.Values[0]
            $colorValue = ($Row.OverallSeverity -ne 'Standard')
            Write-adPEASAttribute -Name $Row.Name -Value $val.Display -Class $Row.OverallSeverity -AlignAt $AlignAt -ColorValue:$colorValue
        }

        'MultiValue' {
            # Build classified values for inline multi-value rendering
            $classifiedValues = @()
            foreach ($val in $Row.Values) {
                $classifiedValues += [PSCustomObject]@{ Value = $val.Display; Class = $val.Severity }
            }

            if ($classifiedValues.Count -eq 0) { return }

            # Determine if attribute name should be colored
            $attrClass = if ($Row.ForceAttributeClass -or $Row.OverallSeverity -ne 'Standard') {
                $Row.OverallSeverity
            } else { 'Standard' }

            $attrPrefix = Get-ClassPrefix -Class $attrClass
            $hasAttrPrefix = ($attrPrefix.Length -gt 0)

            $ANSI = $Script:ANSI

            # Build attribute name with padding
            $attrPadding = if ($hasAttrPrefix) { $AlignAt - 4 } else { $AlignAt }
            $paddedAttrName = "$($Row.Name):".PadRight($attrPadding, ' ')

            # First value - output with attribute name
            $firstVal = $classifiedValues[0]
            $firstLinePlain = $attrPrefix + $paddedAttrName + $firstVal.Value

            if ($Script:adPEAS_OutputColor -ne $false) {
                $attrColor = Get-ClassColor -Class $attrClass
                $valColor = Get-ClassColor -Class $firstVal.Class

                # Special handling for Secure class (has background color)
                if ($attrClass -eq "Secure") {
                    $nameOnlyWithColon = "$($Row.Name):"
                    $paddingSpaces = ' ' * ($attrPadding - $nameOnlyWithColon.Length)
                    $coloredOutput = $attrColor + $attrPrefix + $nameOnlyWithColon + $ANSI["Reset"] + $paddingSpaces + $valColor + $firstVal.Value + $ANSI["Reset"]
                    Write-Host $coloredOutput
                } else {
                    $attrPart = $attrColor + $attrPrefix + $paddedAttrName + $ANSI["Reset"]
                    Write-Host ($attrPart + $valColor + $firstVal.Value + $ANSI["Reset"])
                }
            } else {
                Write-Host $firstLinePlain
            }

            if ($Script:adPEAS_Outputfile) {
                if ($Script:adPEAS_OutputColor -ne $false) {
                    $attrColor = Get-ClassColor -Class $attrClass
                    $valColor = Get-ClassColor -Class $firstVal.Class
                    if ($attrClass -eq "Secure") {
                        $nameOnlyWithColon = "$($Row.Name):"
                        $paddingSpaces = ' ' * ($attrPadding - $nameOnlyWithColon.Length)
                        $fileText = $attrColor + $attrPrefix + $nameOnlyWithColon + $ANSI["Reset"] + $paddingSpaces + $valColor + $firstVal.Value + $ANSI["Reset"]
                    } else {
                        $fileText = $attrColor + $attrPrefix + $paddedAttrName + $ANSI["Reset"] + $valColor + $firstVal.Value + $ANSI["Reset"]
                    }
                } else {
                    $fileText = $firstLinePlain
                }
                [System.IO.File]::AppendAllText($Script:adPEAS_Outputfile, $fileText + "`n", [System.Text.Encoding]::UTF8)
            }

            # Continuation values - indented
            $indent = " " * $AlignAt
            for ($i = 1; $i -lt $classifiedValues.Count; $i++) {
                $cv = $classifiedValues[$i]
                $linePlain = $indent + $cv.Value

                if ($Script:adPEAS_OutputColor -ne $false) {
                    $lineColor = Get-ClassColor -Class $cv.Class
                    Write-Host ($indent + $lineColor + $cv.Value + $ANSI["Reset"])
                } else {
                    Write-Host $linePlain
                }

                if ($Script:adPEAS_Outputfile) {
                    if ($Script:adPEAS_OutputColor -ne $false) {
                        $lineColor = Get-ClassColor -Class $cv.Class
                        $fileText = $indent + $lineColor + $cv.Value + $ANSI["Reset"]
                    } else {
                        $fileText = $linePlain
                    }
                    [System.IO.File]::AppendAllText($Script:adPEAS_Outputfile, $fileText + "`n", [System.Text.Encoding]::UTF8)
                }
            }
        }

        'Image' {
            # Image data - show DisplayText
            $val = $Row.Values[0]
            Write-adPEASAttribute -Name $Row.Name -Value $val.Display -AlignAt $AlignAt
        }
    }
}

<#
.SYNOPSIS
    Renders a PostObject row (roasting hashes) to the console.
.DESCRIPTION
    PostObject rows (KerberoastingHash, ASREPRoastingHash) are rendered after
    the object card with a Show-Line label followed by the hash value.
#>
function Render-ConsolePostObjectRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Row
    )

    $val = $Row.Values[0]

    # Determine hash type label from RawName
    $hashLabel = switch ($Row.RawName) {
        'KerberoastingHash' {
            if ($val.RawValue -is [PSCustomObject] -and $val.RawValue.PSObject.Properties['KerberoastingHashType']) {
                $val.RawValue.KerberoastingHashType
            } else { 'Kerberoast Hash' }
        }
        'ASREPRoastingHash' {
            if ($val.RawValue -is [PSCustomObject] -and $val.RawValue.PSObject.Properties['ASREPRoastingHashType']) {
                $val.RawValue.ASREPRoastingHashType
            } else { 'AS-REP Roast Hash' }
        }
        default { $Row.Name }
    }

    Show-Line "${hashLabel}:" -Class "Finding" -NoCollect
    Write-adPEASOutput -Text $val.Display -Class "Finding" -NoPrefix
}
