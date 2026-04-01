<#
.SYNOPSIS
    Pure output layer for adPEAS - handles console and file output.

.DESCRIPTION
    Layer 3 of the three-layer architecture. This module is responsible ONLY for:
    - ANSI color-coded console output (Write-Host)
    - Plain text file output (without ANSI codes)
    - Prefix handling ([?], [!], [+], [*], [#])

    NO business logic, NO data transformation, NO LDAP queries.
    All formatting decisions are made by Get-RenderModel and the renderers.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

<#
.SYNOPSIS
    Writes a single formatted line to console and/or file.
.DESCRIPTION
    Pure output function - takes pre-formatted content and writes it to:
    - Console with ANSI colors (if $Script:adPEAS_OutputColor is not $false)
    - File without ANSI codes (if $Script:adPEAS_Outputfile is set)
.PARAMETER Text
    The text to output.
.PARAMETER Class
    The severity class for coloring: Info, SubInfo, Finding, Hint, Note, Secure, Standard.
.PARAMETER NoPrefix
    Skip the class prefix ([!], [+], etc.).
.PARAMETER NoNewline
    Don't add a newline after output.
.PARAMETER NoColor
    Force plain output even if color is enabled.
.PARAMETER LeadingNewline
    Add a newline before the output (for visual separation).
.EXAMPLE
    Write-adPEASOutput -Text "Vulnerability found!" -Class "Finding"
.EXAMPLE
    Write-adPEASOutput -Text "contoso.com" -Class "Standard" -NoPrefix
#>
function Write-adPEASOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [AllowEmptyString()]
        [string]$Text,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Info", "SubInfo", "Finding", "Hint", "Note", "Secure", "Standard")]
        [string]$Class = "Standard",

        [Parameter(Mandatory=$false)]
        [switch]$NoPrefix,

        [Parameter(Mandatory=$false)]
        [switch]$NoNewline,

        [Parameter(Mandatory=$false)]
        [switch]$NoColor,

        [Parameter(Mandatory=$false)]
        [switch]$LeadingNewline
    )

    begin {
        $ANSI = $Script:ANSI
        $ANSI_esc = $Script:ANSI_esc
    }

    process {
        # Build prefix
        $prefix = if (-not $NoPrefix) { Get-ClassPrefix -Class $Class } else { "" }

        # Build plain text (for file output and non-color console)
        $plainText = $prefix + $Text
        if ($LeadingNewline) {
            $plainText = "`n" + $plainText
        }

        # Console output
        if ($Script:adPEAS_OutputColor -ne $false -and -not $NoColor) {
            # Colored output
            $color = Get-ClassColor -Class $Class
            $coloredText = $color + $plainText + $ANSI["Reset"]
            Write-Host $coloredText -NoNewline:$NoNewline
        } else {
            # Plain output
            Write-Host $plainText -NoNewline:$NoNewline
        }

        # File output (with or without ANSI codes based on $Script:adPEAS_OutputColor)
        if ($Script:adPEAS_Outputfile) {
            if ($Script:adPEAS_OutputColor -ne $false -and -not $NoColor) {
                # Colored file output (default) - include ANSI codes
                $color = Get-ClassColor -Class $Class
                $fileText = $color + $plainText + $ANSI["Reset"]
            } else {
                # Plain file output (-NoColor) - strip ANSI codes
                $fileText = $plainText -replace "$ANSI_esc\[\d+(;\d+)*m", ""
            }
            # Add newline to text itself to avoid Out-File adding extra blank lines
            if (-not $NoNewline) {
                $fileText = $fileText + "`n"
            }
            [System.IO.File]::AppendAllText($Script:adPEAS_Outputfile, $fileText, [System.Text.Encoding]::UTF8)
        }
    }
}

<#
.SYNOPSIS
    Writes a formatted attribute line (key-value pair) to output.
.DESCRIPTION
    Outputs a key-value pair with proper alignment and optional per-value coloring.
    Used for AD object attributes where the key (attribute name) may have a different class than the value.
.PARAMETER Name
    The attribute name (key).
.PARAMETER Value
    The attribute value.
.PARAMETER Class
    The severity class for the attribute name.
.PARAMETER ValueClass
    Optional separate class for the value. If not specified, value uses Standard (grey).
.PARAMETER AlignAt
    Column width for alignment (default: 45).
.PARAMETER ColorValue
    When set, color the entire line (name + value) with the Class color.
.EXAMPLE
    Write-adPEASAttribute -Name "sAMAccountName" -Value "admin"
.EXAMPLE
    Write-adPEASAttribute -Name "pwdLastSet" -Value "01/01/2020" -Class "Finding" -ColorValue
#>
function Write-adPEASAttribute {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [string]$Value,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Info", "SubInfo", "Finding", "Hint", "Note", "Secure", "Standard")]
        [string]$Class = "Standard",

        [Parameter(Mandatory=$false)]
        [ValidateSet("Info", "SubInfo", "Finding", "Hint", "Note", "Secure", "Standard")]
        [string]$ValueClass,

        [Parameter(Mandatory=$false)]
        [int]$AlignAt = 45,

        [Parameter(Mandatory=$false)]
        [switch]$ColorValue
    )

    $ANSI = $Script:ANSI
    $ANSI_esc = $Script:ANSI_esc

    # Determine if this is a continuation line (no name)
    $IsContinuationLine = [string]::IsNullOrEmpty($Name)

    # Build prefix (only for non-continuation lines)
    $prefix = if (-not $IsContinuationLine) { Get-ClassPrefix -Class $Class } else { "" }
    $hasPrefix = ($prefix.Length -gt 0)

    # Calculate padding (reduce by 4 when prefix present)
    $paddingWidth = if ($hasPrefix) { $AlignAt - 4 } else { $AlignAt }
    $nameWithColon = if ($Name) { "${Name}:" } else { "" }
    $paddedName = $nameWithColon.PadRight($paddingWidth, ' ')

    # Build plain text
    $plainText = $prefix + $paddedName + $Value

    # Console output
    if ($Script:adPEAS_OutputColor -ne $false) {
        $classColor = Get-ClassColor -Class $Class

        # For Secure class: NEVER color entire line (background color looks ugly), instead, color name and value separately WITH padding uncolored
        if ($ColorValue -and $Class -notin @("Standard", "Secure")) {
            # Color entire line (name + value) with class color
            $coloredText = $classColor + $plainText + $ANSI["Reset"]
            Write-Host $coloredText
        } elseif ($Class -eq "Secure") {
            # Special handling for Secure class (has background color), color ONLY the prefix+name and value, NOT the padding spaces
            $nameOnlyWithColon = if ($Name) { "${Name}:" } else { "" }
            $paddingSpaces = ' ' * ($paddingWidth - $nameOnlyWithColon.Length)

            # Build: [colored prefix+name] [reset] [padding] [colored value] [reset]
            $coloredOutput = $classColor + $prefix + $nameOnlyWithColon + $ANSI["Reset"] +
                            $paddingSpaces +
                            $classColor + $Value + $ANSI["Reset"]
            Write-Host $coloredOutput
        } else {
            # Default: color attribute name (with padding), value uses ValueClass or grey
            $attrPart = $prefix + $paddedName
            $effectiveValueClass = if ($ValueClass) { $ValueClass } else { "Standard" }
            $valueColor = Get-ClassColor -Class $effectiveValueClass
            Write-Host ($classColor + $attrPart + $ANSI["Reset"] + $valueColor + $Value + $ANSI["Reset"])
        }
    } else {
        Write-Host $plainText
    }

    # File output (with or without ANSI codes based on $Script:adPEAS_OutputColor)
    if ($Script:adPEAS_Outputfile) {
        if ($Script:adPEAS_OutputColor -ne $false) {
            # Colored file output (default) - recreate the colored version
            $classColor = Get-ClassColor -Class $Class
            if ($ColorValue -and $Class -notin @("Standard", "Secure")) {
                $fileText = $classColor + $plainText + $ANSI["Reset"]
            } elseif ($Class -eq "Secure") {
                $nameOnlyWithColon = if ($Name) { "${Name}:" } else { "" }
                $paddingSpaces = ' ' * ($paddingWidth - $nameOnlyWithColon.Length)
                $fileText = $classColor + $prefix + $nameOnlyWithColon + $ANSI["Reset"] +
                            $paddingSpaces +
                            $classColor + $Value + $ANSI["Reset"]
            } else {
                $attrPart = $prefix + $paddedName
                $effectiveValueClass = if ($ValueClass) { $ValueClass } else { "Standard" }
                $valueColor = Get-ClassColor -Class $effectiveValueClass
                $fileText = $classColor + $attrPart + $ANSI["Reset"] + $valueColor + $Value + $ANSI["Reset"]
            }
        } else {
            # Plain file output (-NoColor) - strip any ANSI codes
            $fileText = $plainText -replace "$ANSI_esc\[\d+(;\d+)*m", ""
        }
        # Add newline to match console output exactly
        [System.IO.File]::AppendAllText($Script:adPEAS_Outputfile, $fileText + "`n", [System.Text.Encoding]::UTF8)
    }
}

<#
.SYNOPSIS
    Writes an empty line to output.
.DESCRIPTION
    Utility function to add vertical spacing in output.
    Follows the Show-* naming convention for consistency with other output functions.
#>
function Show-EmptyLine {
    [CmdletBinding()]
    param()

    Write-Host ""
    if ($Script:adPEAS_Outputfile) {
        # Write single newline to match console output exactly
        [System.IO.File]::AppendAllText($Script:adPEAS_Outputfile, "`n", [System.Text.Encoding]::UTF8)
    }
}

<#
.SYNOPSIS
    Writes the adPEAS logo to output.
.DESCRIPTION
    Displays the adPEAS logo with version number and legend.
    This is a special case that bypasses the normal formatting pipeline.
.PARAMETER Version
    The version string to display.
#>
function Write-adPEASLogo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Version = "2.0"
    )

    $ANSI = $Script:ANSI

    # Build legend entries
    $Legend = @{
        "Info"    = "[?] Searching for juicy information"
        "Finding" = "[!] Found a vulnerability which may be exploitable"
        "Hint"    = "[+] Found some interesting information for further investigation"
        "Note"    = "[*] Some kind of note"
        "Secure"  = "[#] Some kind of secure configuration"
    }

    # Color legend if enabled
    if ($Script:adPEAS_OutputColor -ne $false) {
        foreach ($cls in @("Info", "Finding", "Hint", "Note", "Secure")) {
            $color = Get-ClassColor -Class $cls
            $Legend[$cls] = $color + $Legend[$cls] + $ANSI["Reset"]
        }
    }

    # Build logo
    $LogoStart = if ($Script:adPEAS_OutputColor -ne $false) { Get-ClassColor -Class "Info" } else { "" }
    $LogoStop = if ($Script:adPEAS_OutputColor -ne $false) { $ANSI["Reset"] } else { "" }

    $LogoText = @"
$LogoStart
               _ _____  ______           _____
              | |  __ \|  ____|   /\    / ____|
      ____  __| | |__) | |__     /  \  | (___
     / _  |/ _  |  ___/|  __|   / /\ \  \___ \
    | (_| | (_| | |    | |____ / ____ \ ____) |
     \__,_|\__,_|_|    |______/_/    \_\_____/
                                            Version $Version
$LogoStop
    Active Directory Enumeration
    by @61106960
$("")
    Legend
        $($Legend["Info"])
        $($Legend["Finding"])
        $($Legend["Hint"])
        $($Legend["Note"])
        $($Legend["Secure"])
"@

    Write-Host $LogoText
    # Explicit empty line after logo (survives minification and scope changes)
    Write-Host ""

    # File output (with or without ANSI codes based on $Script:adPEAS_OutputColor)
    if ($Script:adPEAS_Outputfile) {
        if ($Script:adPEAS_OutputColor -ne $false) {
            # Colored file output (default) - include ANSI codes
            # Extra newline at end for empty line after logo
            [System.IO.File]::AppendAllText($Script:adPEAS_Outputfile, $LogoText + "`n`n", [System.Text.Encoding]::UTF8)
        } else {
            # Plain file output (-NoColor) - strip ANSI codes
            # Extra newline at end for empty line after logo
            $ANSI_esc = $Script:ANSI_esc
            $FileLogoText = $LogoText -replace "$ANSI_esc\[\d+(;\d+)*m", ""
            [System.IO.File]::AppendAllText($Script:adPEAS_Outputfile, $FileLogoText + "`n`n", [System.Text.Encoding]::UTF8)
        }
    }
}

<#
.SYNOPSIS
    Writes a section header with decorative lines.
.DESCRIPTION
    Outputs a visually distinct section header with separator lines.
    Used for main sections like "Domain Information", "User Enumeration", etc.
.PARAMETER Value
    The header text.
#>
function Write-adPEASHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Value
    )

    $ANSI = $Script:ANSI
    $ANSI_esc = $Script:ANSI_esc

    $SeparatorLine = "=" * 70
    $HeaderLine = "+++++ $Value +++++"

    if ($Script:adPEAS_OutputColor -ne $false) {
        $color = Get-ClassColor -Class "Info"
        $output = "`n`n" + $color + $SeparatorLine + "`n" + $HeaderLine + "`n" + $SeparatorLine + $ANSI["Reset"]
        Write-Host $output
    } else {
        Write-Host ("`n`n" + $SeparatorLine)
        Write-Host $HeaderLine
        Write-Host $SeparatorLine
    }

    # File output (with or without ANSI codes based on $Script:adPEAS_OutputColor)
    if ($Script:adPEAS_Outputfile) {
        if ($Script:adPEAS_OutputColor -ne $false) {
            # Colored file output (default) - include ANSI codes
            $color = Get-ClassColor -Class "Info"
            $fileOutput = "`n`n" + $color + $SeparatorLine + "`n" + $HeaderLine + "`n" + $SeparatorLine + $ANSI["Reset"] + "`n"
            [System.IO.File]::AppendAllText($Script:adPEAS_Outputfile, $fileOutput, [System.Text.Encoding]::UTF8)
        } else {
            # Plain file output (-NoColor)
            $fileOutput = "`n`n" + $SeparatorLine + "`n" + $HeaderLine + "`n" + $SeparatorLine + "`n"
            [System.IO.File]::AppendAllText($Script:adPEAS_Outputfile, $fileOutput, [System.Text.Encoding]::UTF8)
        }
    }
}
