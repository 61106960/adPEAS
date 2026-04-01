<#
.SYNOPSIS
    Central RenderModel builder for adPEAS output.

.DESCRIPTION
    Produces a unified RenderModel that both Console and HTML renderers consume.
    This is the SINGLE SOURCE OF TRUTH for:
    - Which attributes are shown (via Get-OrderedAttributes / PrimaryAttributes)
    - What severity each attribute has (via Get-TriggerMatch)
    - What tooltip each value gets (via Get-TriggerMatch FindingId)
    - How values are transformed (via AttributeTransformers)

    The RenderModel architecture provides a single pipeline where attribute selection,
    severity, and formatting are determined once, then consumed by both
    Render-ConsoleObject.ps1 (console) and Render-HtmlObject.ps1 (HTML).

.NOTES
    Author: Alexander Sturz (@_61106960_)
    Requires: adPEAS-AttributeOrder.ps1, adPEAS-FindingDefinitions.ps1, AttributeTransformers.ps1
#>

# ============================================================================
# Transformer Registry
# Maps attribute names to transformer functions.
# Attributes not in this registry use the default transformer.
# Populated by AttributeTransformers.ps1 after it loads.
# ============================================================================
$Script:AttributeTransformers = @{}

# ============================================================================
# Factory Functions
# ============================================================================

<#
.SYNOPSIS
    Creates a new RenderValue object.
.PARAMETER Display
    The display text for this value (resolved name, formatted string, etc.)
.PARAMETER Severity
    Per-value severity: Finding, Hint, Secure, Note, or Standard.
.PARAMETER FindingId
    Optional FindingDefinition ID for HTML tooltip.
.PARAMETER RawValue
    The original unprocessed value.
.PARAMETER Metadata
    Optional hashtable with extra info (SID, DN, etc.)
#>
function New-RenderValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Display,

        [Parameter(Mandatory=$false)]
        [string]$Severity = 'Standard',

        [Parameter(Mandatory=$false)]
        [string]$FindingId = $null,

        [Parameter(Mandatory=$false)]
        $RawValue = $null,

        [Parameter(Mandatory=$false)]
        [hashtable]$Metadata = @{}
    )

    [PSCustomObject]@{
        PSTypeName = 'adPEAS.RenderValue'
        Display    = $Display
        Severity   = $Severity
        FindingId  = $FindingId
        RawValue   = $RawValue
        Metadata   = $Metadata
    }
}

<#
.SYNOPSIS
    Creates a new RenderRow object.
.PARAMETER Name
    Display name for the attribute.
.PARAMETER RawName
    Original attribute name.
.PARAMETER RowType
    SingleValue, MultiValue, Image, or Hash.
.PARAMETER OverallSeverity
    Aggregate severity for the attribute label.
.PARAMETER FindingId
    Optional row-level FindingId.
.PARAMETER Values
    Array of RenderValue objects.
.PARAMETER ForceAttributeClass
    Whether to force attribute name coloring even if all values are Standard.
#>
function New-RenderRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [Parameter(Mandatory=$false)]
        [string]$RawName = $Name,

        [Parameter(Mandatory=$false)]
        [string]$RowType = 'SingleValue',

        [Parameter(Mandatory=$false)]
        [string]$OverallSeverity = 'Standard',

        [Parameter(Mandatory=$false)]
        [string]$FindingId = $null,

        [Parameter(Mandatory=$false)]
        [array]$Values = @(),

        [Parameter(Mandatory=$false)]
        [bool]$ForceAttributeClass = $false
    )

    [PSCustomObject]@{
        PSTypeName         = 'adPEAS.RenderRow'
        Name               = $Name
        RawName            = $RawName
        RowType            = $RowType
        OverallSeverity    = $OverallSeverity
        FindingId          = $FindingId
        Values             = $Values
        ForceAttributeClass = $ForceAttributeClass
    }
}

# ============================================================================
# Default Transformer
# ============================================================================

<#
.SYNOPSIS
    Default transformer for attributes without a registered custom transformer.
.DESCRIPTION
    Determines severity and FindingId via Get-TriggerMatch,
    and handles common value types (scalar, array, multi-line string, ImageData).
#>
function Convert-DefaultToRenderValues {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        $Value,

        [Parameter(Mandatory=$true)]
        $Context
    )

    # Handle ImageData objects (thumbnailPhoto, jpegPhoto)
    if ($Value -is [PSCustomObject] -and ($Value.psobject.TypeNames -contains 'adPEAS.ImageData')) {
        return @{
            RowType         = 'Image'
            OverallSeverity = 'Standard'
            ForceAttributeClass = $false
            Values          = @(
                New-RenderValue -Display $Value.DisplayText -Severity 'Standard' -RawValue $Value
            )
        }
    }

    # Handle multi-line strings (e.g., siteIPSubnets, domainControllers)
    if ($Value -is [string] -and $Value -match "`n") {
        $lines = $Value -split "`n"
        $renderValues = @()
        foreach ($line in $lines) {
            $lineMatch = Get-TriggerMatch -Name $Name -Value $line -IsComputer $Context.IsComputer -SourceObject $Context.SourceObject
            $renderValues += New-RenderValue -Display $line -Severity $lineMatch.Severity -FindingId $lineMatch.FindingId -RawValue $line
        }
        $maxSev = Get-MaxSeverityFromValues -Values $renderValues
        return @{
            RowType         = 'MultiValue'
            OverallSeverity = $maxSev
            ForceAttributeClass = ($maxSev -ne 'Standard')
            Values          = $renderValues
        }
    }

    # Handle arrays
    if ($Value -is [array]) {
        # Check if array contains objects with DisplayText (e.g., privilegedGroups structured format)
        $firstItem = $Value | Select-Object -First 1
        if ($firstItem -is [PSCustomObject] -and $firstItem.PSObject.Properties['DisplayText']) {
            # Array of objects with DisplayText - use DisplayText for display
            $renderValues = @()
            foreach ($item in $Value) {
                $itemDisplay = [string]$item.DisplayText
                $itemMatch = Get-TriggerMatch -Name $Name -Value $item -IsComputer $Context.IsComputer -SourceObject $Context.SourceObject
                $renderValues += New-RenderValue -Display $itemDisplay -Severity $itemMatch.Severity -FindingId $itemMatch.FindingId -RawValue $item
            }
            $maxSev = Get-MaxSeverityFromValues -Values $renderValues
            return @{
                RowType         = 'MultiValue'
                OverallSeverity = $maxSev
                ForceAttributeClass = ($maxSev -ne 'Standard')
                Values          = $renderValues
            }
        }

        # Check if array contains LinkedOUs objects (from Get-GPOLinkage)
        if ($firstItem -is [PSCustomObject] -and $firstItem.PSObject.Properties['DistinguishedName'] -and $firstItem.PSObject.Properties['Scope']) {
            # Display full DistinguishedName with LinkStatus for clarity
            $renderValues = @()
            foreach ($item in $Value) {
                $ouDisplay = $item.DistinguishedName
                if ([string]::IsNullOrWhiteSpace($ouDisplay)) { continue }

                # Append LinkStatus if not standard Enabled (show Disabled/Enforced explicitly)
                if ($item.LinkStatus -and $item.LinkStatus -ne 'Enabled') {
                    $ouDisplay = "$ouDisplay ($($item.LinkStatus))"
                }

                # Check each OU individually for trigger matches (e.g., domain-level GPO links)
                $itemMatch = Get-TriggerMatch -Name $Name -Value $item.DistinguishedName -IsComputer $Context.IsComputer -SourceObject $Context.SourceObject
                $renderValues += New-RenderValue -Display $ouDisplay -Severity $itemMatch.Severity -FindingId $itemMatch.FindingId -RawValue $item
            }
            if ($renderValues.Count -eq 0) { return $null }
            $maxSev = Get-MaxSeverityFromValues -Values $renderValues
            return @{
                RowType         = 'MultiValue'
                OverallSeverity = $maxSev
                ForceAttributeClass = ($maxSev -ne 'Standard')
                Values          = $renderValues
            }
        }

        # Simple array of strings - render as MultiValue (one line per item)
        # Skip empty arrays (e.g., LinkedOUs = @() on GPO tasks)
        if ($Value.Count -eq 0) { return $null }
        $renderValues = @()
        foreach ($item in $Value) {
            $itemStr = [string]$item
            if ([string]::IsNullOrEmpty($itemStr)) { continue }
            $itemMatch = Get-TriggerMatch -Name $Name -Value $itemStr -IsComputer $Context.IsComputer -SourceObject $Context.SourceObject
            $renderValues += New-RenderValue -Display $itemStr -Severity $itemMatch.Severity -FindingId $itemMatch.FindingId -RawValue $item
        }
        if ($renderValues.Count -eq 0) { return $null }
        $maxSev = Get-MaxSeverityFromValues -Values $renderValues
        return @{
            RowType         = 'MultiValue'
            OverallSeverity = $maxSev
            ForceAttributeClass = ($maxSev -ne 'Standard')
            Values          = $renderValues
        }
    }

    # Simple scalar value
    $displayValue = [string]$Value
    # Skip empty scalar values that slipped through the filter
    if ([string]::IsNullOrEmpty($displayValue)) { return $null }
    # Pass original $Value (not $displayValue) so typed objects (DateTime, Int64) are preserved
    # for Custom triggers like pwdAge_gt_1825 that need Get-DateFromValue to work correctly
    $scalarMatch = Get-TriggerMatch -Name $Name -Value $Value -IsComputer $Context.IsComputer -SourceObject $Context.SourceObject
    return @{
        RowType         = 'SingleValue'
        OverallSeverity = $scalarMatch.Severity
        ForceAttributeClass = $false
        Values          = @(
            New-RenderValue -Display $displayValue -Severity $scalarMatch.Severity -FindingId $scalarMatch.FindingId -RawValue $Value
        )
    }
}

# ============================================================================
# Helper Functions
# ============================================================================

<#
.SYNOPSIS
    Gets the maximum severity from an array of RenderValue objects.
#>
function Get-MaxSeverityFromValues {
    [CmdletBinding()]
    param([array]$Values)

    $priority = @{ 'Finding' = 4; 'Secure' = 3; 'Hint' = 2; 'Note' = 1; 'Standard' = 0 }
    $maxPriority = 0
    $maxSeverity = 'Standard'

    foreach ($v in $Values) {
        $p = $priority[$v.Severity]
        if ($null -ne $p -and $p -gt $maxPriority) {
            $maxPriority = $p
            $maxSeverity = $v.Severity
            if ($maxSeverity -eq 'Finding') { return 'Finding' }
        }
    }
    return $maxSeverity
}

<#
.SYNOPSIS
    Builds a RenderRow from a transformer result hashtable.
#>
function Build-RenderRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [hashtable]$TransformResult
    )

    # Use custom display name if provided, otherwise use raw name
    $displayName = if ($TransformResult.DisplayName) { $TransformResult.DisplayName } else { $Name }

    # Row-level FindingId: if single value with FindingId, promote to row level
    $rowFindingId = $TransformResult.FindingId
    if (-not $rowFindingId -and $TransformResult.Values.Count -eq 1 -and $TransformResult.Values[0].FindingId) {
        $rowFindingId = $TransformResult.Values[0].FindingId
    }

    New-RenderRow -Name $displayName `
                  -RawName $Name `
                  -RowType ($TransformResult.RowType) `
                  -OverallSeverity ($TransformResult.OverallSeverity) `
                  -FindingId $rowFindingId `
                  -Values ($TransformResult.Values) `
                  -ForceAttributeClass ([bool]$TransformResult.ForceAttributeClass)
}

# ============================================================================
# Object Type Detection and Activity Status (used by Get-RenderModel)
# ============================================================================

<#
.SYNOPSIS
    Detects if an object is a Computer account.
.PARAMETER Object
    The object to check.
.RETURNS
    $true if the object is a Computer, $false otherwise.
#>
function Test-IsComputerObject {
    param($Object)

    return (($Object.objectClass -contains "computer") -or ($Object.sAMAccountName -like '*$'))
}

<#
.SYNOPSIS
    Adds activity status to an object based on lastLogonTimestamp.
.DESCRIPTION
    Checks if an account is inactive (no login within InactiveDays) and adds
    an activityStatus property if so. Uses $Script:DefaultInactiveDays by default.
.PARAMETER Object
    The object to check and potentially modify.
.PARAMETER InactiveDays
    Number of days without login to consider inactive.
    Default: Uses $Script:DefaultInactiveDays (typically 90 days) set by Invoke-adPEAS.
#>
function Add-ActivityStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Object,

        [Parameter(Mandatory=$false)]
        [int]$InactiveDays = 0  # 0 = use $Script:DefaultInactiveDays
    )

    # Skip if already has status or no lastLogonTimestamp
    if ($Object.activityStatus -or -not $Object.lastLogonTimestamp) {
        return
    }

    # Resolve InactiveDays from global constant if not explicitly set
    $effectiveInactiveDays = if ($InactiveDays -gt 0) {
        $InactiveDays
    } elseif ($Script:DefaultInactiveDays) {
        $Script:DefaultInactiveDays
    } else {
        90  # Fallback if global not set
    }

    $lastLogon = $Object.lastLogonTimestamp
    $lastLogonDate = $null

    # Parse lastLogonTimestamp (could be DateTime, FileTime, or string)
    if ($lastLogon -is [DateTime]) {
        $lastLogonDate = $lastLogon
    } elseif ($lastLogon -is [long] -or $lastLogon -is [int]) {
        if ($lastLogon -gt 0 -and $lastLogon -ne 9223372036854775807) {
            try { $lastLogonDate = [DateTime]::FromFileTime([long]$lastLogon) } catch {}
        }
    } elseif ($lastLogon -is [string]) {
        $parsed = 0L
        if ([long]::TryParse($lastLogon, [ref]$parsed) -and $parsed -gt 0) {
            try { $lastLogonDate = [DateTime]::FromFileTime($parsed) } catch {}
        } else {
            $parsedDate = [DateTime]::MinValue
            if ([DateTime]::TryParse($lastLogon, [ref]$parsedDate)) {
                $lastLogonDate = $parsedDate
            }
        }
    }

    # Check if inactive
    if ($lastLogonDate -and $lastLogonDate -lt (Get-Date).AddDays(-$effectiveInactiveDays)) {
        $Object | Add-Member -NotePropertyName 'activityStatus' -NotePropertyValue "INACTIVE (no login for >$effectiveInactiveDays days)" -Force
    }
}

# ============================================================================
# Main Function: Get-RenderModel
# ============================================================================

<#
.SYNOPSIS
    Builds a unified RenderModel from an AD object.
.DESCRIPTION
    Central function that produces a RenderModel consumed by both Console and HTML
    renderers. Determines attribute selection (via Get-OrderedAttributes), severity
    (via Get-TriggerMatch), and transformations (via AttributeTransformers).

    This function is the SINGLE SOURCE OF TRUTH for all output decisions.
.PARAMETER Object
    The AD object or PSCustomObject to render.
.RETURNS
    A PSCustomObject with ObjectType, IsComputer, Primary, Extended, and PostObject arrays.
#>
function Get-RenderModel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Object
    )

    # 1. Detect object type and computer status
    $objectType = Get-ObjectTypeForOrdering -Object $Object
    $isComputer = Test-IsComputerObject -Object $Object

    # 2. Enrich object with activity status if inactive (mutates input object)
    Add-ActivityStatus -Object $Object

    # 3. Build context for transformers
    $context = [PSCustomObject]@{
        IsComputer              = $isComputer
        IsExchangeGroup         = [bool]$Object._isExchangeGroup
        DangerousRightsSeverity = $Object.dangerousRightsSeverity
        CredentialType          = $Object.credentialType
        OwnerSID                = $Object.OwnerSID
        ObjectType              = $objectType
        SourceObject            = $Object
    }

    # 4. Get ordered attribute lists (Primary/Extended)
    $orderedAttrs = Get-OrderedAttributes -Object $Object -PromoteNonStandard -IsComputer $isComputer

    # 5. Transform each attribute into RenderRows
    $primaryRows = [System.Collections.ArrayList]@()
    $extendedRows = [System.Collections.ArrayList]@()
    $postObjectRows = [System.Collections.ArrayList]@()

    # Track attributes for PostObject (rendered after the card in console)
    $postObjectAttributes = @('KerberoastingHash', 'ASREPRoastingHash')

    foreach ($section in @(
        @{ Source = $orderedAttrs.Primary; Target = 'Primary' },
        @{ Source = $orderedAttrs.Extended; Target = 'Extended' }
    )) {
        foreach ($attrInfo in $section.Source) {
            $name = $attrInfo.Name
            $value = $attrInfo.Value

            # Route PostObject attributes (roasting hashes)
            $isPostObject = $name -in $postObjectAttributes

            # Look up transformer or use default
            $transformer = $Script:AttributeTransformers[$name]
            if ($transformer) {
                $result = & $transformer -Name $name -Value $value -Context $context
            } else {
                $result = Convert-DefaultToRenderValues -Name $name -Value $value -Context $context
            }

            # Skip if transformer returns $null (e.g., Owner that IS default)
            if ($null -eq $result) { continue }

            $row = Build-RenderRow -Name $name -TransformResult $result

            if ($isPostObject) {
                [void]$postObjectRows.Add($row)
            } elseif ($section.Target -eq 'Primary') {
                [void]$primaryRows.Add($row)
            } else {
                [void]$extendedRows.Add($row)
            }
        }
    }

    # 6. Return the model
    [PSCustomObject]@{
        PSTypeName  = 'adPEAS.RenderModel'
        ObjectType  = $objectType
        IsComputer  = $isComputer
        Primary     = $primaryRows.ToArray()
        Extended    = $extendedRows.ToArray()
        PostObject  = $postObjectRows.ToArray()
    }
}
