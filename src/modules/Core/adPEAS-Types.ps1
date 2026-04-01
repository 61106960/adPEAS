<#
.SYNOPSIS
    adPEAS Type definitions, constants, and helper functions.

.DESCRIPTION
    Central module containing:
    - Finding object schema (New-adPEASFinding)
    - ANSI escape sequences
    - Class prefixes and colors
    - Privileged principal patterns and SID mappings
    - Classification helper functions

.NOTES
    Author: Alexander Sturz (@_61106960_)
    This module must be loaded BEFORE Write-adPEASOutput and Get-RenderModel.
#>

# =============================================================================
# SEVERITY CLASSES - Central Definition
# =============================================================================
# These are the canonical severity class names used throughout adPEAS.
# All modules should reference these constants for consistency.
#
# Priority order (highest to lowest): Finding > Secure > Hint > Note > Standard
#
# Usage:
#   - Finding  : Critical security issues requiring immediate attention (red)
#   - Secure   : Explicitly secure configurations worth highlighting (red on yellow)
#   - Hint     : Interesting findings that may be security-relevant (yellow)
#   - Note     : Informational items, generally positive (green)
#   - Standard : Normal output, no special classification (grey)
#   - Info     : Section headers and informational labels (blue)
#   - SubInfo  : Sub-section headers (blue)

$Script:SeverityClasses = @{
    Finding  = 'Finding'
    Secure   = 'Secure'
    Hint     = 'Hint'
    Note     = 'Note'
    Standard = 'Standard'
    Info     = 'Info'
    SubInfo  = 'SubInfo'
}

# Ordered list for priority comparisons (highest first)
$Script:SeverityPriority = @('Finding', 'Secure', 'Hint', 'Note', 'Standard')

# ANSI ESCAPE SEQUENCES
$Script:ANSI_esc = [char]27
$Script:ANSI = @{
    "RedYellow" = "$Script:ANSI_esc[1;31;103m"  # Bold Red on Yellow BG
    "Black"     = "$Script:ANSI_esc[1;30m"
    "Red"       = "$Script:ANSI_esc[1;31m"
    "Green"     = "$Script:ANSI_esc[1;32m"
    "Yellow"    = "$Script:ANSI_esc[1;33m"
    "Blue"      = "$Script:ANSI_esc[1;34m"
    "Magenta"   = "$Script:ANSI_esc[1;35m"
    "Cyan"      = "$Script:ANSI_esc[1;36m"
    "LightGrey" = "$Script:ANSI_esc[1;37m"
    "DarkGrey"  = "$Script:ANSI_esc[1;90m"
    "Reset"     = "$Script:ANSI_esc[0m"
}

# Class to Prefix mapping (uses SeverityClasses keys)
$Script:ClassPrefixes = @{
    $Script:SeverityClasses.Info     = "[?] "
    $Script:SeverityClasses.SubInfo  = "[?] "
    $Script:SeverityClasses.Finding  = "[!] "
    $Script:SeverityClasses.Hint     = "[+] "
    $Script:SeverityClasses.Note     = "[*] "
    $Script:SeverityClasses.Secure   = "[#] "
    $Script:SeverityClasses.Standard = ""
}

# Class to Color mapping (uses SeverityClasses keys)
$Script:ClassColors = @{
    $Script:SeverityClasses.Info     = "Blue"
    $Script:SeverityClasses.SubInfo  = "Blue"
    $Script:SeverityClasses.Finding  = "Red"
    $Script:SeverityClasses.Hint     = "Yellow"
    $Script:SeverityClasses.Note     = "Green"
    $Script:SeverityClasses.Secure   = "RedYellow"
    $Script:SeverityClasses.Standard = "LightGrey"
}

# ===== HELPER FUNCTIONS =====
<#
.SYNOPSIS
    Gets the prefix string for a severity class.
.DESCRIPTION
    Returns the appropriate prefix ([!], [+], [*], [#], [?]) for a given class.
#>
function Get-ClassPrefix {
    param([string]$Class)
    if ($Script:ClassPrefixes.ContainsKey($Class)) {
        return $Script:ClassPrefixes[$Class]
    }
    return ""
}

<#
.SYNOPSIS
    Gets the ANSI color code for a severity class.
.DESCRIPTION
    Returns the ANSI escape sequence for coloring output based on class.
#>
function Get-ClassColor {
    param([string]$Class)
    $colorName = if ($Script:ClassColors.ContainsKey($Class)) {
        $Script:ClassColors[$Class]
    } else {
        "LightGrey"
    }
    return $Script:ANSI[$colorName]
}

<#
.SYNOPSIS
    Classifies a principal based on privilege level using SID-based lookup.
.DESCRIPTION
    Returns a severity class based on whether the principal is a broad group, privileged, or standard. Uses Test-IsPrivileged for language-independent SID-based classification.

    Accepts either:
    - Principal name (e.g., "DOMAIN\User") - will be resolved to SID
    - SID string (e.g., "S-1-5-21-...-512") - used directly
    - Name for Exchange group detection (optional, with SID)

    Categories returned by Test-IsPrivileged:
    - "BroadGroup" → maps to BroadGroupClass (default: "Hint")
    - "Privileged" → maps to PrivilegedClass (default: "Finding")
    - "Standard"   → maps to DefaultClass (default: "Standard")
    - "Unknown"    → maps to DefaultClass (default: "Standard")

.PARAMETER Principal
    The principal name to classify (e.g., "DOMAIN\User"). Will be resolved to SID.
.PARAMETER SID
    Direct SID string to classify (e.g., "S-1-5-21-...-512"). Faster than name resolution.
.PARAMETER Name
    Optional group name for Exchange group detection (Exchange groups have dynamic SIDs but fixed names like "Organization Management").
.PARAMETER BroadGroupClass
    The class to return for broad groups (default: "Hint").
    Applies to: Domain Users, Domain Computers, Authenticated Users, Everyone, etc.
.PARAMETER PrivilegedClass
    The class to return for privileged principals (default: "Finding").
    Applies to: Domain Admins, Enterprise Admins, SYSTEM, etc.
.PARAMETER DefaultClass
    The class to return for other principals (default: "Standard").
    Applies to: Regular users/groups not in privileged or broad categories.
.PARAMETER IncludeOperators
    Include Operator groups (Account Operators, Server Operators, etc.) as privileged.
.RETURNS
    Severity class string: "Finding", "Hint", "Standard", etc.
#>
function Get-PrincipalClass {
    param(
        [string]$Principal,
        [string]$SID,
        [string]$Name,
        [string]$BroadGroupClass = "Hint",
        [string]$PrivilegedClass = "Finding",
        [string]$DefaultClass = "Standard",
        [switch]$IncludeOperators
    )

    # Determine identity for Test-IsPrivileged
    $identity = $null

    if (-not [string]::IsNullOrEmpty($SID)) {
        # SID provided directly - use it (optionally with Name for Exchange groups)
        if (-not [string]::IsNullOrEmpty($Name)) {
            $identity = [PSCustomObject]@{
                objectSid = $SID
                sAMAccountName = $Name
            }
        } else {
            $identity = $SID
        }
    } elseif (-not [string]::IsNullOrEmpty($Principal)) {
        # Principal name provided - resolve to SID
        $resolvedSID = ConvertTo-SID -Identity $Principal
        if (-not $resolvedSID) {
            Write-Log "[Get-PrincipalClass] Could not resolve principal to SID: $Principal"
            return $DefaultClass
        }
        $identity = $resolvedSID
    } else {
        # No input provided
        return $DefaultClass
    }

    # Use Test-IsPrivileged for centralized SID-based classification
    $category = (Test-IsPrivileged -Identity $identity -IncludeOperators:$IncludeOperators).Category

    switch ($category) {
        'BroadGroup' { return $BroadGroupClass }
        'Privileged' { return $PrivilegedClass }
        default      { return $DefaultClass }
    }
}

# FINDING OBJECT SCHEMA

<#
.SYNOPSIS
    Creates a new adPEAS Finding object.
.DESCRIPTION
    Factory function for creating standardized Finding objects used in the output architecture. Findings flow from Check-Modules through Get-RenderModel to Render-ConsoleObject/Render-HtmlObject.
.PARAMETER Type
    The type of finding: Text, KeyValue, Object, Header, or Separator.
.PARAMETER Class
    The severity class: Info, SubInfo, Finding, Hint, Note, Secure, or Standard.
.PARAMETER Value
    The text value (for Text, KeyValue, Header types).
.PARAMETER Key
    The key name (for KeyValue type).
.PARAMETER Object
    The AD object or PSCustomObject (for Object type).
.PARAMETER Metadata
    Additional metadata hashtable for custom data.
.EXAMPLE
    New-adPEASFinding -Type "Text" -Class "Finding" -Value "Vulnerability found!"
.EXAMPLE
    New-adPEASFinding -Type "Object" -Object $adUser
.EXAMPLE
    New-adPEASFinding -Type "KeyValue" -Key "Domain Name" -Value "contoso.com"
#>
function New-adPEASFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Text", "KeyValue", "Object", "Header", "Separator")]
        [string]$Type,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Info", "SubInfo", "Finding", "Hint", "Note", "Secure", "Standard")]
        [string]$Class = "Standard",

        [Parameter(Mandatory=$false)]
        [string]$Value,

        [Parameter(Mandatory=$false)]
        [string]$Key,

        [Parameter(Mandatory=$false)]
        [object]$Object,

        [Parameter(Mandatory=$false)]
        [hashtable]$Metadata = @{}
    )

    [PSCustomObject]@{
        PSTypeName = 'adPEAS.Finding'
        Type       = $Type
        Class      = $Class
        Value      = $Value
        Key        = $Key
        Object     = $Object
        Metadata   = $Metadata
        Timestamp  = Get-Date
    }
}
