<#
.SYNOPSIS
    Output functions and message templates for adPEAS v2.

.DESCRIPTION
    This module provides the central output functions and message templates for adPEAS v2.

    OUTPUT FUNCTIONS (delegate to RenderModel pipeline):
    - Show-Output    - Low-level output with full control
    - Show-Line      - Single line output with optional styling
    - Show-KeyValue  - Key-value pairs with alignment
    - Show-Object    - AD object output with all properties
    - Show-Header    - Main section headers (+++++ text +++++)
    - Show-SubHeader - Sub-section headers

    Output Architecture:
    - adPEAS-Types.ps1         - Constants, helpers, Finding schema
    - Write-adPEASOutput.ps1   - Pure output (console, file)
    - Get-RenderModel.ps1      - RenderModel builder (enrichment, classification)
    - Render-ConsoleObject.ps1 - Console renderer
    - Render-HtmlObject.ps1    - HTML renderer

    Output Classes (compatible with adPEAS v1):
    - [?] Info (Blue)       - Section headers (with ++++)
    - [?] SubInfo (Blue)    - Sub-task headers (without ++++)
    - [!] Finding (Red)     - Vulnerabilities
    - [+] Hint (Yellow)     - Interesting findings
    - [*] Note (Green)      - General information
    - [#] Secure (RedYellow)- Secure configuration

    MESSAGE TEMPLATES:
    - Show-Message: Central function for Error/Warning/Success/Info messages
    - Show-NoSessionError: No active session errors
    - Show-Error: Unified error function
    - Show-DisconnectError: Disconnect failure messages
    - Show-NoParametersError: Missing parameters errors
    - Get-adPEASHelp: Help overview with -Section parameter (QuickStart, Checks, Commands)

    FINDINGS COLLECTION (for HTML/JSON export):
    - Initialize-FindingsCollection: Start collecting findings
    - Add-Finding: Add a finding to the collection (called automatically)
    - Get-FindingsCollection: Retrieve all collected findings
    - Clear-FindingsCollection: Clear the collection

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

# ============================================================================
# Findings Collection System
# ============================================================================
# This system collects findings in parallel to console/file output.
# It enables HTML and JSON report generation without modifying Check-Modules.
#
# Design: "Tap into the Output Layer"
# - Check-Modules call Show-Object, Show-Line as before (unchanged)
# - Show-Output intercepts and collects findings when enabled
# - After all checks, Export-HTMLReport uses the collection

# Module-level variables for findings collection (Script scope - shared across all functions in the standalone .ps1)
$Script:adPEAS_FindingsCollection = $null
$Script:adPEAS_FindingsCollectionEnabled = $false
$Script:adPEAS_CurrentCheckContext = $null

<#
.SYNOPSIS
    Initializes the findings collection system.
.DESCRIPTION
    Call this before running checks to enable findings collection.
    The collection stores all findings for later export to HTML/JSON.
.EXAMPLE
    Initialize-FindingsCollection
    Invoke-adPEAS -Domain "contoso.com"
    $findings = Get-FindingsCollection
#>
function Initialize-FindingsCollection {
    [CmdletBinding()]
    param()

    $Script:adPEAS_FindingsCollection = [System.Collections.ArrayList]::new()
    $Script:adPEAS_FindingsCollectionEnabled = $true
    $Script:adPEAS_CurrentCheckContext = $null
    Write-Log "[FindingsCollection] Initialized"
}

<#
.SYNOPSIS
    Sets the current check context for findings collection.
.DESCRIPTION
    Called by Invoke-adPEAS before each check to provide context (category, check name, title) for collected findings.
.PARAMETER Category
    The module category (e.g., "Accounts", "Delegation", "ADCS")
.PARAMETER CheckName
    The function name (e.g., "Get-KerberoastableAccounts")
.PARAMETER Title
    Human-readable title for the check
#>
function Set-CheckContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Category,

        [Parameter(Mandatory=$true)]
        [string]$CheckName,

        [Parameter(Mandatory=$false)]
        [string]$Title = ""
    )

    $Script:adPEAS_CurrentCheckContext = @{
        Category  = $Category
        CheckName = $CheckName
        Title     = if ($Title) { $Title } else { $CheckName }
        Timestamp = Get-Date
    }
}

<#
.SYNOPSIS
    Clears the current check context.
.DESCRIPTION
    Called by Invoke-adPEAS after each check completes.
#>
function Clear-CheckContext {
    [CmdletBinding()]
    param()

    $Script:adPEAS_CurrentCheckContext = $null
}

<#
.SYNOPSIS
    Adds a finding to the collection.
.DESCRIPTION
    Internal function called by Show-Output when collection is enabled.
    Captures the object, severity class, and current check context.
.PARAMETER Object
    The AD object or finding data.
.PARAMETER Class
    The severity class (Finding, Hint, Note, etc.)
.PARAMETER Text
    Text message (for Show-Line calls)
.PARAMETER Key
    Key name (for Show-KeyValue calls)
.PARAMETER Value
    Value (for Show-KeyValue calls)
#>
function Add-Finding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        $Object,

        [Parameter(Mandatory=$false)]
        [string]$Class = "Standard",

        [Parameter(Mandatory=$false)]
        [string]$Text,

        [Parameter(Mandatory=$false)]
        [string]$Key,

        [Parameter(Mandatory=$false)]
        [string]$Value,

        [Parameter(Mandatory=$false)]
        [string]$FindingId,

        [Parameter(Mandatory=$false)]
        [string]$ObjectType,

        [Parameter(Mandatory=$false)]
        $RenderModel
    )

    if (-not $Script:adPEAS_FindingsCollectionEnabled) { return }
    if ($null -eq $Script:adPEAS_FindingsCollection) { return }

    # Skip Standard class without Object AND without Key (neutral text like "Executing Modules: Domain")
    # But keep KeyValue pairs with Standard class (they contain useful data)
    if (-not $Object -and -not $Key -and $Class -eq "Standard") { return }

    # Determine type and severity
    $entryType = switch ($Class) {
        "Info"    { "Header" }      # Main section header
        "SubInfo" { "SubHeader" }   # Sub-section header
        default   { if ($Object) { "Object" } elseif ($Key) { "KeyValue" } else { "Line" } }
    }

    # Use original adPEAS class names as severity (Finding, Hint, Note, Secure)
    $severity = switch ($Class) {
        "Finding" { "Finding" }     # [!] Red - Vulnerabilities
        "Hint"    { "Hint" }        # [+] Yellow - Interesting findings
        "Note"    { "Note" }        # [*] Green - General information
        "Secure"  { "Secure" }      # [#] RedYellow - Secure configuration
        "Info"    { "Header" }      # Special marker for headers
        "SubInfo" { "SubHeader" }   # Special marker for sub-headers
        "Standard" { "Standard" }
        default   { "Note" }
    }

    # Derive attribute severities from RenderModel if available, otherwise use legacy function
    $attributeSeverities = $null
    if ($RenderModel) {
        # Derive from RenderModel - Single Source of Truth
        $attributeSeverities = @{}
        foreach ($row in @($RenderModel.Primary) + @($RenderModel.Extended) + @($RenderModel.PostObject)) {
            if ($row.OverallSeverity -ne 'Standard') {
                $attributeSeverities[$row.RawName] = $row.OverallSeverity
            }
        }
    } elseif ($Object) {
        # Legacy fallback - inline severity calculation (Get-ObjectAttributeSeverities was removed)
        $attributeSeverities = @{}
        foreach ($prop in $Object.PSObject.Properties) {
            if ($null -eq $prop.Value) { continue }
            $sev = Get-AttributeSeverity -Name $prop.Name -Value $prop.Value -SourceObject $Object
            if ($sev -ne "Standard") { $attributeSeverities[$prop.Name] = $sev }
        }
    }

    # Build the finding entry
    $finding = [PSCustomObject]@{
        Timestamp           = Get-Date
        Category            = if ($Script:adPEAS_CurrentCheckContext) { $Script:adPEAS_CurrentCheckContext.Category } else { "Unknown" }
        CheckName           = if ($Script:adPEAS_CurrentCheckContext) { $Script:adPEAS_CurrentCheckContext.CheckName } else { "Unknown" }
        CheckTitle          = if ($Script:adPEAS_CurrentCheckContext) { $Script:adPEAS_CurrentCheckContext.Title } else { "Unknown" }
        Severity            = $severity
        Class               = $Class
        Type                = $entryType
        Object              = $Object
        Text                = $Text
        Key                 = $Key
        Value               = $Value
        AttributeSeverities = $attributeSeverities  # Pre-calculated attribute classifications
        FindingId           = $FindingId            # Reference to FindingDefinitions for detailed tooltips
        ObjectType          = $ObjectType           # Direct ObjectType for SubHeader tooltip lookup (preferred over title mapping)
        RenderModel         = $RenderModel          # Cached RenderModel for HTML rendering (avoids re-computation)
    }

    [void]$Script:adPEAS_FindingsCollection.Add($finding)
    Write-Verbose "[FindingsCollection] Added: $($finding.Type) - $($finding.Class) - $Text$Key$(if($ObjectType){" ObjectType=$ObjectType"})"
}

<#
.SYNOPSIS
    Retrieves the collected findings.
.DESCRIPTION
    Returns all findings collected since Initialize-FindingsCollection was called.
.EXAMPLE
    $findings = Get-FindingsCollection
    $findings | Where-Object Severity -eq "Critical"
#>
function Get-FindingsCollection {
    [CmdletBinding()]
    param()

    if ($null -eq $Script:adPEAS_FindingsCollection) {
        return @()
    }

    return $Script:adPEAS_FindingsCollection.ToArray()
}

<#
.SYNOPSIS
    Clears the findings collection.
.DESCRIPTION
    Resets the collection and disables collection mode.
#>
function Clear-FindingsCollection {
    [CmdletBinding()]
    param()

    $Script:adPEAS_FindingsCollection = $null
    $Script:adPEAS_FindingsCollectionEnabled = $false
    $Script:adPEAS_CurrentCheckContext = $null
    Write-Log "[FindingsCollection] Cleared"
}

# ============================================================================
# Findings Cache Functions (for -OutputAppend)
# ============================================================================
# These functions enable persisting findings between Invoke-adPEAS runs.
# A JSON cache file stores serialized findings alongside the HTML report.
# On subsequent runs with -OutputAppend, previous findings are loaded,
# merged with current findings (replacing by module/category), and re-exported.

<#
.SYNOPSIS
    Replaces the current in-memory findings collection.
.DESCRIPTION
    Overwrites the findings collection with a new set of findings.
    Used by the -OutputAppend feature to inject merged findings.
#>
function Set-FindingsCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$Findings
    )

    $Script:adPEAS_FindingsCollection = [System.Collections.ArrayList]@($Findings)
    Write-Log "[FindingsCollection] Set to $($Findings.Count) findings"
}

<#
.SYNOPSIS
    Exports the current findings collection to a JSON cache file.
.DESCRIPTION
    Serializes all collected findings to a JSON file for persistence between runs.
    AD objects are serialized as property hashtables, RenderModel is excluded
    (it will be re-computed by Export-HTMLReport via Get-RenderModel).
.PARAMETER Path
    Path for the JSON cache file.
#>
function Export-FindingsCache {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    $findings = Get-FindingsCollection
    $serializable = foreach ($f in $findings) {
        $objectProps = $null
        if ($f.Object) {
            $objectProps = @{}
            foreach ($p in $f.Object.PSObject.Properties) {
                # Serialize primitive types directly, convert complex types to string
                if ($p.Value -is [System.Collections.IDictionary] -or
                    $p.Value -is [array] -or
                    $p.Value -is [string] -or
                    $p.Value -is [int] -or $p.Value -is [long] -or
                    $p.Value -is [bool] -or $p.Value -is [datetime] -or
                    $null -eq $p.Value) {
                    $objectProps[$p.Name] = $p.Value
                } else {
                    $objectProps[$p.Name] = $p.Value.ToString()
                }
            }
        }

        @{
            Timestamp           = $f.Timestamp.ToString('o')
            Category            = $f.Category
            CheckName           = $f.CheckName
            CheckTitle          = $f.CheckTitle
            Severity            = $f.Severity
            Class               = $f.Class
            Type                = $f.Type
            Text                = $f.Text
            Key                 = $f.Key
            Value               = $f.Value
            FindingId           = $f.FindingId
            ObjectType          = $f.ObjectType
            AttributeSeverities = $f.AttributeSeverities
            ObjectProperties    = $objectProps
        }
    }

    $cache = @{
        CacheVersion  = 1
        ExportDate    = (Get-Date).ToString('o')
        Domain        = if ($Script:LDAPContext) { $Script:LDAPContext.Domain } else { 'Unknown' }
        Server        = if ($Script:LDAPContext) { $Script:LDAPContext.Server } else { 'Unknown' }
        adPEASVersion = if ($Script:adPEASVersion) { $Script:adPEASVersion } else { 'Unknown' }
        FindingCount  = $serializable.Count
        Findings      = @($serializable)
    }

    $json = $cache | ConvertTo-Json -Depth 5 -Compress
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    [System.IO.File]::WriteAllText($resolvedPath, $json, $utf8NoBom)
    Write-Log "[FindingsCache] Exported $($serializable.Count) findings to '$Path'"
}

<#
.SYNOPSIS
    Imports findings from a JSON cache file.
.DESCRIPTION
    Reads a JSON cache file and delegates to Import-FindingsFromCache for deserialization.
    Includes version check and domain mismatch warning.
.PARAMETER Path
    Path to the JSON cache file.
#>
function Import-FindingsCache {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    $raw = Get-Content -Path $Path -Raw -Encoding UTF8
    $cache = $raw | ConvertFrom-Json

    # Version check
    if ($cache.CacheVersion -ne 1) {
        Write-Warning "[FindingsCache] Unsupported cache version $($cache.CacheVersion) - expected 1"
        return @()
    }

    # Domain mismatch warning
    $currentDomain = if ($Script:LDAPContext) { $Script:LDAPContext.Domain } else { $null }
    if ($currentDomain -and $cache.Domain -and $cache.Domain -ne $currentDomain -and $cache.Domain -ne 'Unknown') {
        Write-Warning "[FindingsCache] Cache domain '$($cache.Domain)' differs from current domain '$currentDomain'"
        Write-Warning "[FindingsCache] Continuing with merge - findings may be from different domains"
    }

    $result = Import-FindingsFromCache -Cache $cache
    Write-Log "[FindingsCache] Loaded $(@($result).Count) findings from '$Path'"
    return @($result)
}

<#
.SYNOPSIS
    Imports findings from an already-parsed JSON cache object.
.DESCRIPTION
    Reconstructs finding objects from a deserialized cache.
    Used by Import-FindingsCache (file-based) and Convert-adPEASReport (pre-parsed).
    AD objects are reconstructed using hashtable construction (24x faster than Add-Member).
    RenderModel is set to $null and will be re-computed during HTML export.
.PARAMETER Cache
    The deserialized cache object (from ConvertFrom-Json).
#>
function Import-FindingsFromCache {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Cache
    )

    $result = foreach ($f in $Cache.Findings) {
        # Reconstruct AD-Object from serialized properties using hashtable construction
        $adObject = $null
        if ($f.ObjectProperties) {
            $props = @{}
            foreach ($p in $f.ObjectProperties.PSObject.Properties) {
                $props[$p.Name] = $p.Value
            }
            $adObject = [PSCustomObject]$props
        }

        # Reconstruct AttributeSeverities as hashtable (ConvertFrom-Json returns PSCustomObject)
        $attrSev = $null
        if ($f.AttributeSeverities) {
            $attrSev = @{}
            foreach ($p in $f.AttributeSeverities.PSObject.Properties) {
                $attrSev[$p.Name] = $p.Value
            }
        }

        [PSCustomObject]@{
            Timestamp           = [datetime]::Parse($f.Timestamp)
            Category            = $f.Category
            CheckName           = $f.CheckName
            CheckTitle          = $f.CheckTitle
            Severity            = $f.Severity
            Class               = $f.Class
            Type                = $f.Type
            Object              = $adObject
            Text                = $f.Text
            Key                 = $f.Key
            Value               = $f.Value
            FindingId           = $f.FindingId
            ObjectType          = $f.ObjectType
            AttributeSeverities = $attrSev
            RenderModel         = $null  # Re-computed by Export-HTMLReport via Get-RenderModel
        }
    }

    return @($result)
}

<#
.SYNOPSIS
    Merges previous and current findings, replacing by category.
.DESCRIPTION
    Combines findings from a previous cache with current scan findings.
    Findings from categories that were re-scanned (in ReplacedCategories)
    are removed from the previous set and replaced with current findings.
.PARAMETER PreviousFindings
    Findings loaded from cache.
.PARAMETER CurrentFindings
    Findings from the current scan.
.PARAMETER ReplacedCategories
    Category names whose findings should be replaced (= modules that ran).
#>
function Merge-FindingsCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$PreviousFindings,

        [Parameter(Mandatory=$true)]
        [array]$CurrentFindings,

        [Parameter(Mandatory=$true)]
        [string[]]$ReplacedCategories
    )

    # Keep old findings EXCEPT those whose Category is being replaced
    # Use HashSet for O(1) lookups instead of Where-Object pipeline
    $replacedSet = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]$ReplacedCategories, [System.StringComparer]::OrdinalIgnoreCase
    )
    $kept = [System.Collections.ArrayList]::new($PreviousFindings.Count)
    foreach ($f in $PreviousFindings) {
        if (-not $replacedSet.Contains($f.Category)) {
            [void]$kept.Add($f)
        }
    }

    # Sort by canonical module order to ensure consistent report layout
    $categoryOrder = @('Domain','Creds','Rights','Delegation','ADCS','Accounts','GPO','Computer','Application','Bloodhound')
    $categoryIndex = @{}
    for ($i = 0; $i -lt $categoryOrder.Count; $i++) {
        $categoryIndex[$categoryOrder[$i]] = $i
    }

    # Build merged list: kept previous + current, then sort by category order
    $merged = [System.Collections.ArrayList]::new($kept.Count + $CurrentFindings.Count)
    [void]$merged.AddRange(@($kept))
    [void]$merged.AddRange(@($CurrentFindings))
    $sorted = @($merged | Sort-Object { if ($categoryIndex.ContainsKey($_.Category)) { $categoryIndex[$_.Category] } else { 999 } })

    Write-Log "[FindingsCache] Merge: kept $($kept.Count) previous, added $($CurrentFindings.Count) new, total $($sorted.Count)"
    return $sorted
}

# ============================================================================
# Core Output Functions
# ============================================================================
# These functions provide the primary output interface for adPEAS.
# They delegate to the three-layer output architecture.

<#
.SYNOPSIS
    Low-level output function with full control over output formatting.

.DESCRIPTION
    Core output function that dispatches to the RenderModel pipeline.
    Use the semantic wrapper functions (Show-Line, Show-Header, etc.) for most cases.

.PARAMETER Object
    AD object to output (uses Get-RenderModel + Render-ConsoleObject).

.PARAMETER Class
    Output class: Info, SubInfo, Finding, Hint, Note, Secure, Standard

.PARAMETER Value
    The message to output.

.PARAMETER Key
    Key name for key-value pairs with automatic alignment (used with -Value).

.PARAMETER AlignAt
    Column width for key alignment (default: 45 characters).

.PARAMETER Raw
    No prefixes ([?], [!], etc.)

.PARAMETER Logo
    Outputs the adPEAS logo.

.PARAMETER ObjectType
    The _adPEASObjectType for SubHeader checks. Used for tooltip lookup in HTML reports.

.EXAMPLE
    Show-Output -Class Info -Value "Checking Domain Information"
    Output: [?] +++++ Checking Domain Information +++++

.EXAMPLE
    Show-Output -Class Finding -Value "Vulnerability Found"
    Output: [!] Vulnerability Found

.EXAMPLE
    Show-Output -Key "Domain Name (DNS)" -Value "contoso.com"
    Output: Domain Name (DNS):                      contoso.com
#>
function Show-Output {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        $Object,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Info", "SubInfo", "Finding", "Hint", "Note", "Secure", "Standard")]
        [string]$Class = "Standard",

        [Parameter(Mandatory=$false)]
        [string]$Value,

        [Parameter(Mandatory=$false)]
        [string]$Key,

        [Parameter(Mandatory=$false)]
        [int]$AlignAt = 45,

        [Parameter(Mandatory=$false)]
        [switch]$Raw,

        [Parameter(Mandatory=$false)]
        [switch]$Logo,

        [Parameter(Mandatory=$false)]
        [string]$FindingId,

        [Parameter(Mandatory=$false)]
        [string]$ObjectType,

        [Parameter(Mandatory=$false)]
        [switch]$NoCollect
    )

    # =========================================================================
    # FINDINGS COLLECTION: Collect findings in parallel to normal output
    # This enables HTML/JSON export without modifying Check-Modules
    # Skip collection if -NoCollect is specified (used for console-only output)
    # =========================================================================
    # Build RenderModel for objects (used by both console rendering and findings collection)
    $renderModel = $null
    if ($Object) {
        $renderModel = Get-RenderModel -Object $Object
    }

    if ($Script:adPEAS_FindingsCollectionEnabled -and -not $NoCollect) {
        Write-Verbose "[FindingsCollection] Show-Output called: Object=$($null -ne $Object), Key=$Key, Class=$Class, FindingId=$FindingId, ObjectType=$ObjectType"
        if ($Object) {
            # Collect object findings with pre-built RenderModel
            Add-Finding -Object $Object -Class $Class -FindingId $FindingId -RenderModel $renderModel
        }
        elseif ($Key) {
            # Collect key-value findings
            Add-Finding -Class $Class -Key $Key -Value $Value -FindingId $FindingId
        }
        elseif ($Value) {
            # Collect ALL line findings including headers (Info/SubInfo)
            # These are used for structuring the HTML report
            # For SubHeaders, include ObjectType for direct tooltip lookup
            Add-Finding -Class $Class -Text $Value -FindingId $FindingId -ObjectType $ObjectType
        }
    }
    # =========================================================================

    if ($Logo) {
        Write-adPEASLogo -Version $Value
        return
    }

    if ($Object) {
        # Use RenderModel pipeline: Get-RenderModel -> Render-ConsoleObject
        Render-ConsoleObject -Model $renderModel -AlignAt $AlignAt
        return
    }

    if ($Key) {
        if ($Class -eq "Secure") {
            # Use Write-adPEASAttribute with ColorValue for proper key:value coloring
            # Remove trailing colon from Key if present (Write-adPEASAttribute adds it)
            $keyName = if ($Key.EndsWith(':')) { $Key.TrimEnd(':') } else { $Key }
            Write-adPEASAttribute -Name $keyName -Value $Value -Class $Class -ValueClass $Class -AlignAt $AlignAt
            return
        }

        # For other classes: color the entire line
        $hasPrefix = $Class -in @("Info", "SubInfo", "Finding", "Hint", "Note", "Secure")
        $paddingWidth = if ($hasPrefix) { $AlignAt - 4 } else { $AlignAt }
        $paddedKey = $Key.PadRight($paddingWidth)
        $formattedValue = "$paddedKey$Value"

        # Output with class coloring (entire line colored)
        Write-adPEASOutput -Text $formattedValue -Class $Class -LeadingNewline:($Class -eq "SubInfo")
        return
    }

    switch ($Class) {
        "Info" {
            # Main section header with decorative lines
            Write-adPEASHeader -Value $Value
        }

        "SubInfo" {
            # Sub-section header with leading newline
            if ($Raw) {
                Write-adPEASOutput -Text $Value -Class "Standard" -NoPrefix -LeadingNewline
            } else {
                Write-adPEASOutput -Text $Value -Class "SubInfo" -LeadingNewline
            }
        }

        default {
            # Standard text output
            if ($Raw) {
                Write-adPEASOutput -Text $Value -Class "Standard" -NoPrefix
            } else {
                Write-adPEASOutput -Text $Value -Class $Class
            }
        }
    }
}

# ============================================================================
# Semantic Wrapper Functions
# ============================================================================
# These functions provide clearer semantics for common output patterns.
# They all delegate to Show-Output internally.

<#
.SYNOPSIS
    Outputs a single line of text with optional class styling.

.DESCRIPTION
    Simple wrapper for outputting a single line of text.
    Use this for status messages, simple text output, and informational lines.

.PARAMETER Text
    The text to output.

.PARAMETER Class
    Output class: Finding, Hint, Note, Secure, Standard (default: Standard)

.PARAMETER Raw
    Output without prefix ([?], [!], etc.)

.EXAMPLE
    Show-Line "Processing users..."
    Output: Processing users...

.EXAMPLE
    Show-Line "Vulnerability found!" -Class Finding
    Output: [!] Vulnerability found!
#>
function Show-Line {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Text,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Info", "SubInfo", "Finding", "Hint", "Note", "Secure", "Standard")]
        [string]$Class = "Standard",

        [Parameter(Mandatory=$false)]
        [switch]$Raw,

        [Parameter(Mandatory=$false)]
        [string]$FindingId,

        [Parameter(Mandatory=$false)]
        [switch]$NoCollect
    )

    Show-Output -Value $Text -Class $Class -Raw:$Raw -FindingId $FindingId -NoCollect:$NoCollect
}

<#
.SYNOPSIS
    Outputs a key-value pair with automatic alignment.

.DESCRIPTION
    Formats and outputs a key-value pair with consistent column alignment.
    The key is padded to AlignAt characters, then the value follows.

.PARAMETER Key
    The attribute/property name (left side).

.PARAMETER Value
    The attribute/property value (right side).

.PARAMETER Class
    Output class for styling: Finding, Hint, Note, Secure, Standard (default: Standard)

.PARAMETER AlignAt
    Column width for key alignment (default: 45 characters).

.EXAMPLE
    Show-KeyValue -Key "Domain Name" -Value "contoso.com"
    Output: Domain Name:                                contoso.com

.EXAMPLE
    Show-KeyValue -Key "Status" -Value "VULNERABLE" -Class Finding
    Output: [!] Status:                                 VULNERABLE
#>
function Show-KeyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Key,

        [Parameter(Mandatory=$true, Position=1)]
        [string]$Value,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Finding", "Hint", "Note", "Secure", "Standard")]
        [string]$Class = "Standard",

        [Parameter(Mandatory=$false)]
        [int]$AlignAt = 45,

        [Parameter(Mandatory=$false)]
        [string]$FindingId,

        [Parameter(Mandatory=$false)]
        [switch]$NoCollect
    )

    Show-Output -Key $Key -Value $Value -Class $Class -AlignAt $AlignAt -FindingId $FindingId -NoCollect:$NoCollect
}

<#
.SYNOPSIS
    Outputs an AD object with all relevant properties formatted.

.DESCRIPTION
    Takes an AD object (user, computer, group, GPO, etc.) and outputs
    all its relevant properties in a formatted, aligned manner.
    Uses Get-RenderModel + Render-ConsoleObject internally.

.PARAMETER Object
    The AD object to output.

.PARAMETER AlignAt
    Column width for property name alignment (default: 45 characters).

.EXAMPLE
    Show-Object $user
    Outputs all relevant properties of the AD user object.

.EXAMPLE
    Get-DomainUser -Identity "admin" | Show-Object
    Pipes a user object directly to Show-Object.
#>
function Show-Object {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        $Object,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Finding", "Hint", "Note", "Secure", "Standard")]
        [string]$Class = "Standard",

        [Parameter(Mandatory=$false)]
        [int]$AlignAt = 45,

        [Parameter(Mandatory=$false)]
        [switch]$NoCollect
    )

    process {
        Show-Output -Object $Object -Class $Class -AlignAt $AlignAt -NoCollect:$NoCollect
    }
}

<#
.SYNOPSIS
    Outputs a section header with decorative formatting.

.DESCRIPTION
    Outputs a main section header with decorative lines (+++++ text +++++).
    Use this for major section divisions in the output.

.PARAMETER Title
    The header title text.

.EXAMPLE
    Show-Header "Checking Domain Information"
    Output: [?] +++++ Checking Domain Information +++++
#>
function Show-Header {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Title
    )

    Show-Output -Class Info -Value $Title
}

<#
.SYNOPSIS
    Outputs a sub-section header.

.DESCRIPTION
    Outputs a sub-section header with a leading newline.
    Use this for sub-divisions within a main section.

.PARAMETER Title
    The sub-header title text.

.PARAMETER ObjectType
    The _adPEASObjectType for this check. Used for tooltip lookup in HTML reports.
    This should match a key in $Script:ObjectTypeDefinitions.

.PARAMETER Raw
    Output without prefix (just the text with leading newline).

.EXAMPLE
    Show-SubHeader "Searching for vulnerable accounts..." -ObjectType "Kerberoastable"
    Output: [?] Searching for vulnerable accounts...

.EXAMPLE
    Show-SubHeader "Checking AdminSDHolder ACLs..." -ObjectType "AdminSDHolderACL"
#>
function Show-SubHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Title,

        [Parameter(Mandatory=$false)]
        [string]$ObjectType,

        [Parameter(Mandatory=$false)]
        [switch]$Raw,

        [Parameter(Mandatory=$false)]
        [switch]$NoCollect
    )

    Show-Output -Class SubInfo -Value $Title -ObjectType $ObjectType -Raw:$Raw -NoCollect:$NoCollect
}

<#
.SYNOPSIS
    Outputs the adPEAS logo.

.DESCRIPTION
    Wrapper for displaying the adPEAS logo with version information.

.PARAMETER Version
    The version string to display (e.g., "2.0.0").

.EXAMPLE
    Show-Logo -Version "2.0.0"
#>
function Show-Logo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Version
    )

    Show-Output -Logo -Value $Version
}

# ============================================================================
# Core Unified Message Functions
# ============================================================================

<#
.SYNOPSIS
    Unified function for displaying structured messages.

.DESCRIPTION
    Central function for all structured output messages in adPEAS.
    Provides consistent formatting for Error, Warning, Success, and Info messages.

    Output Format:
    - Title line with appropriate class (Finding/Hint/Note/Info)
    - Optional details as indented lines
    - Optional hints with Hint class prefix

.PARAMETER Type
    The message type: Error, Warning, Success, or Info.
    - Error:   Red output (Finding class) - for failures and errors
    - Warning: Yellow output (Hint class) - for warnings and important notices
    - Success: Green output (Note class) - for successful operations
    - Info:    Blue output (Info class) - for informational headers

.PARAMETER Title
    The main message title/headline.

.PARAMETER Details
    Optional array of detail lines to display below the title.

.PARAMETER Hints
    Optional array of hint messages displayed with Hint class prefix.

.PARAMETER NoLeadingLine
    Suppresses the leading empty line before the message.

.PARAMETER NoTrailingLine
    Suppresses the trailing empty line after the message.

.EXAMPLE
    Show-Message -Type Error -Title "CONNECTION FAILED" -Details @("Server not responding", "Check firewall settings")
    # Output:
    # [!] CONNECTION FAILED
    #
    # Server not responding
    # Check firewall settings

.EXAMPLE
    Show-Message -Type Success -Title "Template modified successfully" -Details @("WebServer", "2 attributes changed")
    # Output:
    # [*] Template modified successfully
    #
    # WebServer
    # 2 attributes changed

.EXAMPLE
    Show-Message -Type Warning -Title "DISCONNECT FAILED" -Details @("Error: Object disposed") -Hints @("Use -Force to force disconnect", "Check if already disconnected")
    # Output:
    # [+] DISCONNECT FAILED
    #
    # Error: Object disposed
    #
    # [+] Use -Force to force disconnect
    # [+] Check if already disconnected
#>
function Show-Message {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('Error', 'Warning', 'Success', 'Info')]
        [string]$Type,

        [Parameter(Mandatory=$true)]
        [string]$Title,

        [Parameter(Mandatory=$false)]
        [string[]]$Details,

        [Parameter(Mandatory=$false)]
        [string[]]$Hints,

        [Parameter(Mandatory=$false)]
        [switch]$NoLeadingLine,

        [Parameter(Mandatory=$false)]
        [switch]$NoTrailingLine
    )

    # Leading empty line (unless suppressed)
    if (-not $NoLeadingLine) {
        Show-EmptyLine
    }

    # Determine output class based on type
    $titleClass = switch ($Type) {
        'Error'   { 'Finding' }
        'Warning' { 'Hint' }
        'Success' { 'Note' }
        'Info'    { 'Info' }
    }

    # Output title (with class prefix, e.g., [!] for Error)
    Show-Line $Title -Class $titleClass

    # Output details (no prefix - visually subordinate to title)
    if ($Details -and $Details.Count -gt 0) {
        Show-EmptyLine
        foreach ($detail in $Details) {
            Show-Line $detail
        }
    }

    # Output hints (with [+] prefix - visually distinct action items)
    if ($Hints -and $Hints.Count -gt 0) {
        Show-EmptyLine
        foreach ($hint in $Hints) {
            Show-Line $hint -Class Hint
        }
    }

    # Trailing empty line (unless suppressed)
    if (-not $NoTrailingLine) {
        Show-EmptyLine
    }
}

# ============================================================================
# Session Error Messages (Wrapper)
# ============================================================================

<#
.SYNOPSIS
    Displays a consistent "No Active Session" error message.

.DESCRIPTION
    Central function for displaying "No Active Session" errors with consistent formatting.
    Used by all modules when they require a session but none exists.

.PARAMETER Context
    Optional context information (e.g., module name that requires the session).

.EXAMPLE
    Show-NoSessionError
    Shows standard error message.

.EXAMPLE
    Show-NoSessionError -Context "Get-DomainPasswordPolicy"
    Shows error with module context.
#>
function Show-NoSessionError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Context
    )

    # SubHeader with context (NoCollect: session errors are not security findings)
    if ($Context) {
        Show-SubHeader "No active session for $Context..." -NoCollect
    } else {
        Show-SubHeader "No active session..." -NoCollect
    }

    # Error details (NoCollect: session errors are not security findings)
    Show-KeyValue "Session:" "Not connected" -Class Finding -NoCollect

    # Help section
    Show-EmptyLine
    Show-Line "Help:" -Class Hint -NoCollect
    Show-Line "Connect-adPEAS -Domain 'contoso.com' -Credential (Get-Credential)" -NoCollect
    Show-Line "Get-Help Connect-adPEAS -Examples" -NoCollect
    Show-EmptyLine
}

# ============================================================================
# Unified Error Messages
# ============================================================================

<#
.SYNOPSIS
    Displays a consistent error message based on error type.

.DESCRIPTION
    Unified function for displaying all types of errors with consistent formatting.

    Error Types:
    - Permission:   "ERROR: Insufficient permissions to {Operation} '{Target}'"
    - NotFound:     "ERROR: {Message} '{Target}' not found"
    - Operation:    "ERROR: {Message} '{Target}'"
    - Connection:   "CONNECTION FAILED - {Message}"
    - HealthCheck:  "CONNECTION HEALTH CHECK FAILED - {Message}" + Hints

.PARAMETER Type
    The type of error: Permission, NotFound, Operation, Connection, or HealthCheck.

.PARAMETER Message
    The error message or operation description.
    - For Permission: The operation that failed (e.g., "modify template")
    - For NotFound: The object type (e.g., "User", "Certificate template")
    - For Operation: The error description (e.g., "Failed to connect")
    - For Connection: Optional additional context (default: "see error messages above")
    - For HealthCheck: The failure reason (e.g., "Domain Controller is not responding")

.PARAMETER Target
    The target object (e.g., template name, user identity, server name).

.PARAMETER Reason
    Optional detailed reason or original error message.

.PARAMETER Hints
    Optional array of hint messages to display after the error (as Hint class).

.EXAMPLE
    Show-Error -Type Permission -Message "modify template" -Target "WebServer" -Reason "Access denied"
    # Output:
    # [!] ERROR: Insufficient permissions to modify template 'WebServer'
    # [!]   Reason: Access denied

.EXAMPLE
    Show-Error -Type NotFound -Message "User" -Target "john.doe"
    # Output:
    # [!] ERROR: User 'john.doe' not found

.EXAMPLE
    Show-Error -Type Operation -Message "Failed to connect" -Target "DC01" -Reason "Connection timeout"
    # Output:
    # [!] ERROR: Failed to connect 'DC01'
    # [!]   Reason: Connection timeout

.EXAMPLE
    Show-Error -Type Connection
    # Output:
    # [!] CONNECTION FAILED - see error messages above

.EXAMPLE
    Show-Error -Type HealthCheck -Message "DC not responding" -Hints @("Connection established but queries failing", "Check firewall")
    # Output:
    # [!] CONNECTION HEALTH CHECK FAILED - DC not responding
    # [+] Connection established but queries failing
    # [+] Check firewall
#>
function Show-Error {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('Permission', 'NotFound', 'Operation', 'Connection', 'HealthCheck')]
        [string]$Type,

        [Parameter(Mandatory=$false)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [string]$Target,

        [Parameter(Mandatory=$false)]
        [string]$Reason,

        [Parameter(Mandatory=$false)]
        [string[]]$Hints
    )

    # Build error title based on type
    $errorTitle = switch ($Type) {
        'Permission' {
            if ($Target) {
                "ERROR: Insufficient permissions to $Message '$Target'"
            } else {
                "ERROR: Insufficient permissions to $Message"
            }
        }
        'NotFound' {
            "ERROR: $Message '$Target' not found"
        }
        'Operation' {
            if ($Target) {
                "ERROR: $Message '$Target'"
            } else {
                "ERROR: $Message"
            }
        }
        'Connection' {
            if ($Message) {
                "CONNECTION FAILED - $Message"
            } else {
                "CONNECTION FAILED - see error messages above"
            }
        }
        'HealthCheck' {
            if ($Message) {
                "CONNECTION HEALTH CHECK FAILED - $Message"
            } else {
                "CONNECTION HEALTH CHECK FAILED"
            }
        }
    }

    # Build details array
    $details = @()
    if ($Reason) {
        $details += "Reason: $Reason"
    }

    # Connection and HealthCheck have different formatting
    $noLeading = $Type -in @('Connection', 'HealthCheck')

    Show-Message -Type Error -Title $errorTitle -Details $details -Hints $Hints -NoLeadingLine:$noLeading
}

# ============================================================================
# Disconnect Error Messages
# ============================================================================

<#
.SYNOPSIS
    Displays a consistent disconnect failure error with troubleshooting hints.

.DESCRIPTION
    Central function for displaying disconnect failures with helpful troubleshooting steps.

.PARAMETER ErrorMessage
    The original error message.

.EXAMPLE
    Show-DisconnectError -ErrorMessage "Object already disposed"
#>
function Show-DisconnectError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ErrorMessage
    )

    $details = @("Error: $ErrorMessage")
    $hints = @(
        "Use -Force to force disconnect despite errors",
        "Check if session is already disconnected (Get-adPEASSession)"
    )

    Show-Message -Type Error -Title "DISCONNECT FAILED" -Details $details -Hints $hints -NoLeadingLine -NoTrailingLine
}

# ============================================================================
# No Parameters Error Messages
# ============================================================================

<#
.SYNOPSIS
    Displays a consistent "No parameters specified" error message.

.DESCRIPTION
    Central function for displaying errors when required parameters are missing.
    Shows the function name and a hint to view examples.

.PARAMETER FunctionName
    The name of the function that was called without parameters.

.EXAMPLE
    Show-NoParametersError -FunctionName "Set-CertificateTemplate"
#>
function Show-NoParametersError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FunctionName
    )

    $hints = @("For more information, run: Get-Help $FunctionName -Examples")

    Show-Message -Type Error -Title "${FunctionName}: No modification parameters specified" -Hints $hints
}

# ============================================================================
# Module Import / Quick Start Messages
# ============================================================================

function Get-adPEASHelp {
<#
.SYNOPSIS
    Displays adPEAS help including check modules, commands, and usage examples.

.DESCRIPTION
    Shows a comprehensive overview of adPEAS: quick start examples,
    the 10 security check modules, all available commands grouped by category,
    and how to access detailed help for individual commands.

    Use the -Section parameter to display only specific sections.

.PARAMETER Section
    Which section(s) to display. Valid values: QuickStart, Checks, Commands.
    Default: all sections are shown.

.EXAMPLE
    Get-adPEASHelp

    Displays the full adPEAS help overview.

.EXAMPLE
    Get-adPEASHelp -Section Checks

    Displays only the security check modules section.

.EXAMPLE
    Get-adPEASHelp -Section QuickStart,Commands

    Displays quick start examples and available commands.
#>
    [CmdletBinding()]
    param(
        [ValidateSet('QuickStart','Checks','Commands')]
        [string[]]$Section
    )

    # If no section specified, show all
    $showAll = -not $Section
    $showQuickStart = $showAll -or ($Section -contains 'QuickStart')
    $showChecks = $showAll -or ($Section -contains 'Checks')
    $showCommands = $showAll -or ($Section -contains 'Commands')

    # --- Quick Start ---
    if ($showQuickStart) {
        Show-SubHeader "Quick Start"

        Show-Line "Simple scan (Windows Auth):" -Class Hint
        Show-Line "Invoke-adPEAS -Domain 'contoso.com'"
        Show-EmptyLine

        Show-Line "Session-based with credentials:" -Class Hint
        Show-Line "Connect-adPEAS -Domain 'contoso.com' -Credential (Get-Credential)"
        Show-Line "Invoke-adPEAS"
        Show-EmptyLine

        # PTT Note (for domain-joined machines with alternate credentials)
        Show-Line "On domain-joined machines, Kerberos authentication with -Password/-NTHash/-AES*Key/-Certificate replace Kerberos tickets." -Class Note
        Show-Line "Use Connect-adPEAS with -ForceNTLM or -ForceSimpleBind to avoid this."
        Show-EmptyLine

        Show-Line "More help:" -Class Hint
        Show-Line "Get-adPEASHelp"
        Show-Line "Get-Help Connect-adPEAS -Examples"
        Show-Line "Get-Help <Command> -Detailed"
        Show-EmptyLine

    }

    # --- Check Modules (dynamic from ObjectTypeDefinitions) ---
    if ($showChecks) {
        Show-SubHeader "Security Check Modules"

        Show-Line "Run all modules:" -Class Hint
        Show-Line "Invoke-adPEAS (without -Module)"
        Show-EmptyLine
        Show-Line "Run specific modules only:" -Class Hint
        Show-Line "Invoke-adPEAS -Module 'Domain','Creds','ADCS'"
        Show-EmptyLine

        # Module display order and descriptions
        $moduleOrder = [ordered]@{
            'Domain'      = "Domain Configuration"
            'Creds'       = "Credential Exposure"
            'Rights'      = "Access Permissions"
            'Delegation'  = "Delegation Settings"
            'ADCS'        = "AD Certificate Services"
            'Accounts'    = "Privileged Accounts"
            'GPO'         = "Group Policy Objects"
            'Computer'    = "Computer Security"
            'Application' = "Application Infrastructure"
            'Bloodhound'  = "BloodHound Data"
        }

        # Group ObjectTypes by Module, collect unique SectionTitles with Summary
        $checksByModule = @{}
        if ($Script:ObjectTypeDefinitions) {
            foreach ($entry in $Script:ObjectTypeDefinitions.GetEnumerator()) {
                $mod = $entry.Value.Module
                if ($mod -and $moduleOrder.Contains($mod)) {
                    if (-not $checksByModule[$mod]) { $checksByModule[$mod] = @() }
                    $title = $entry.Value.SectionTitle
                    $summary = $entry.Value.Summary
                    if ($title -and ($checksByModule[$mod].Title -notcontains $title)) {
                        $checksByModule[$mod] += @{ Title = $title; Summary = $summary }
                    }
                }
            }
        }

        foreach ($mod in $moduleOrder.Keys) {
            $desc = $moduleOrder[$mod]
            Show-Line "$($desc): -Module $mod" -Class Hint
            $checks = $checksByModule[$mod]
            if ($checks) {
                foreach ($check in $checks) {
                    Show-KeyValue $check.Title $check.Summary
                }
            }
            Show-EmptyLine
        }
    }

    # --- Commands ---
    if ($showCommands) {
        Show-SubHeader "Additional Core and Helper Modules"

        # --- Connection ---
        Show-Line "Connection:" -Class Hint
        Show-KeyValue "Connect-adPEAS" "Establish LDAP session"
        Show-KeyValue "Disconnect-adPEAS" "Close LDAP session"
        Show-KeyValue "Get-adPEASSession" "Show session status"
        Show-EmptyLine

        # --- AD Queries ---
        Show-Line "AD Queries:" -Class Hint
        Show-KeyValue "Get-DomainUser" "Query AD users"
        Show-KeyValue "Get-DomainComputer" "Query AD computers"
        Show-KeyValue "Get-DomainGroup" "Query AD groups"
        Show-KeyValue "Get-DomainGPO" "Query Group Policy Objects"
        Show-KeyValue "Get-DomainObject" "Query any AD object"
        Show-KeyValue "Get-ObjectACL" "Query object ACLs"
        Show-KeyValue "Get-CertificateTemplate" "Query certificate templates"
        Show-KeyValue "Get-CertificateAuthority" "Query certificate authorities"
        Show-EmptyLine

        # --- AD Modifications ---
        Show-Line "AD Modifications:" -Class Hint
        Show-KeyValue "Set-DomainUser" "Modify user attributes"
        Show-KeyValue "Set-DomainComputer" "Modify computer attributes"
        Show-KeyValue "Set-DomainGroup" "Modify group attributes"
        Show-KeyValue "Set-DomainObject" "Modify any AD object"
        Show-KeyValue "Set-DomainGPO" "Modify Group Policy Objects"
        Show-KeyValue "Set-CertificateTemplate" "Modify certificate templates"
        Show-KeyValue "New-DomainUser" "Create AD user"
        Show-KeyValue "New-DomainComputer" "Create AD computer"
        Show-KeyValue "New-DomainGroup" "Create AD group"
        Show-KeyValue "New-DomainGPO" "Create Group Policy Object"
        Show-EmptyLine

        # --- Kerberos Authentication ---
        Show-Line "Kerberos Authentication:" -Class Hint
        Show-KeyValue "Invoke-KerberosAuth" "Request TGT (Password/Hash/Key/Cert)"
        Show-KeyValue "Request-ServiceTicket" "Request TGS for a service"
        Show-KeyValue "Import-KerberosTicket" "Pass-the-Ticket (inject into session)"
        Show-EmptyLine

        # --- Credential Attacks ---
        Show-Line "Credential Attacks:" -Class Hint
        Show-KeyValue "Invoke-Kerberoast" "Kerberoasting (request service tickets)"
        Show-KeyValue "Invoke-ASREPRoast" "AS-REP Roasting (no preauth)"
        Show-KeyValue "Invoke-DCSync" "DCSync (directory replication)"
        Show-KeyValue "Invoke-PasswordSpray" "Password spraying"
        Show-EmptyLine

        # --- Offensive Actions ---
        Show-Line "Offensive Actions:" -Class Hint
        Show-KeyValue "Invoke-TicketForge" "Golden/Silver/Diamond Tickets"
        Show-KeyValue "Invoke-S4U" "S4U delegation attacks"
        Show-KeyValue "Invoke-RBCDOperation" "Resource-Based Constrained Delegation"
        Show-KeyValue "Invoke-ShadowCredentialOperation" "Shadow Credentials"
        Show-KeyValue "Request-ADCSCertificate" "Request ADCS certificate"
        Show-EmptyLine
    }
}

