<#
.SYNOPSIS
    HTML renderer for adPEAS RenderModel objects.

.DESCRIPTION
    Iterates over a RenderModel and produces HTML for each row.
    Replaces the previous Build-AttributeRowHtml function in Export-HTMLReport.ps1.

    This is a "dumb" renderer - all business logic (severity, attribute selection,
    transformations) has already been resolved by Get-RenderModel.

.NOTES
    Author: Alexander Sturz (@_61106960_)
    Requires: Get-RenderModel.ps1, Export-HTMLReport.ps1 (ConvertTo-HtmlEncode)
#>

<#
.SYNOPSIS
    Renders a full RenderModel as HTML for an object detail card.
.DESCRIPTION
    Produces the HTML content for Primary, Extended, and PostObject sections.
    Primary attributes are always visible, Extended are in a collapsible section.
.PARAMETER Model
    The RenderModel object produced by Get-RenderModel.
.PARAMETER ObjectId
    Unique ID for this object's HTML elements (for toggle functionality).
.PARAMETER Severity
    Overall card severity (unused by renderer itself, passed through for compatibility).
.RETURNS
    HTML string for the object's attribute rows.
#>
function Render-HtmlObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Model,

        [Parameter(Mandatory=$true)]
        [string]$ObjectId,

        [Parameter(Mandatory=$false)]
        [string]$Severity = 'Standard'
    )

    $primaryHtml = [System.Text.StringBuilder]::new()
    $extendedHtml = [System.Text.StringBuilder]::new()

    # Render Primary rows
    foreach ($row in $Model.Primary) {
        [void]$primaryHtml.AppendLine((Render-HtmlRow -Row $row))
    }

    # Render Extended rows
    foreach ($row in $Model.Extended) {
        [void]$extendedHtml.AppendLine((Render-HtmlRow -Row $row))
    }

    # Render PostObject rows (roasting hashes etc.) - inside the primary section
    foreach ($row in $Model.PostObject) {
        [void]$primaryHtml.AppendLine((Render-HtmlRow -Row $row))
    }

    # Build output
    $html = [System.Text.StringBuilder]::new()
    [void]$html.Append($primaryHtml.ToString())

    # Extended section (collapsible)
    $extendedContent = $extendedHtml.ToString().Trim()
    if ($extendedContent) {
        $extendedCount = $Model.Extended.Count
        [void]$html.AppendLine("                        <div class=`"extended-attrs-toggle`" onclick=`"toggleExtendedAttrs('$ObjectId')`">")
        [void]$html.AppendLine("                            <span class=`"toggle-icon`" id=`"icon-$ObjectId`">&#9654;</span>")
        [void]$html.AppendLine("                            <span>Show $extendedCount more attribute(s)</span>")
        [void]$html.AppendLine("                        </div>")
        [void]$html.AppendLine("                        <div class=`"extended-attrs`" id=`"ext-$ObjectId`" style=`"display: none;`">")
        [void]$html.Append($extendedContent)
        [void]$html.AppendLine("                        </div>")
    }

    return $html.ToString()
}

<#
.SYNOPSIS
    Renders a single RenderRow as HTML.
.DESCRIPTION
    Creates an attr-row div with the attribute name and formatted values.
    Values with non-Standard severity get CSS class spans with optional
    data-finding-id attributes for tooltips.
.PARAMETER Row
    A RenderRow object from the RenderModel.
.RETURNS
    HTML string for the attribute row.
#>
function Render-HtmlRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Row
    )

    $nameHtml = ConvertTo-HtmlEncode $Row.Name

    switch ($Row.RowType) {
        'SingleValue' {
            $val = $Row.Values[0]
            $displayHtml = ConvertTo-HtmlEncode $val.Display
            $valueHtml = Format-HtmlValueSpan -DisplayHtml $displayHtml -Severity $val.Severity -FindingId $val.FindingId
            $classAttr = Get-HtmlValueClassAttr -Severity $Row.OverallSeverity
            $attrNameEncoded = ConvertTo-HtmlEncode $Row.Name
            return "                        <div class=`"attr-row`" draggable=`"true`" data-attr-name=`"$attrNameEncoded`"><div class=`"attr-name`">$nameHtml</div><div$classAttr>$valueHtml</div></div>"
        }

        'MultiValue' {
            $valuesHtml = @()
            foreach ($val in $Row.Values) {
                $displayHtml = ConvertTo-HtmlEncode $val.Display
                $valuesHtml += Format-HtmlValueSpan -DisplayHtml $displayHtml -Severity $val.Severity -FindingId $val.FindingId
            }
            $displayValue = $valuesHtml -join '<br>'
            # Individual values carry their own severity spans, so the container
            # div uses plain "attr-value" to avoid coloring non-severity items
            $attrNameEncoded = ConvertTo-HtmlEncode $Row.Name
            return "                        <div class=`"attr-row`" draggable=`"true`" data-attr-name=`"$attrNameEncoded`"><div class=`"attr-name`">$nameHtml</div><div class=`"attr-value`">$displayValue</div></div>"
        }

        'Image' {
            $val = $Row.Values[0]
            $rawValue = $val.RawValue

            # Check if this is an ImageData object
            $isImageData = $false
            if ($rawValue -is [PSCustomObject]) {
                if ($rawValue.psobject.TypeNames -contains 'adPEAS.ImageData') {
                    $isImageData = $true
                }
                elseif ($rawValue.PSObject.Properties['Base64'] -and $rawValue.PSObject.Properties['MimeType']) {
                    $isImageData = $true
                }
            }

            if ($isImageData) {
                # XSS Protection: Validate MimeType
                $allowedMimeTypes = @('image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/webp')
                $mimeType = if ($rawValue.MimeType -in $allowedMimeTypes) { $rawValue.MimeType } else { 'image/png' }

                $imgSrc = "data:$mimeType;base64,$($rawValue.Base64)"
                $imgTypeEncoded = ConvertTo-HtmlEncode $rawValue.ImageType
                $imgSizeEncoded = ConvertTo-HtmlEncode $rawValue.SizeKB
                $imgTitle = "$imgTypeEncoded image, $imgSizeEncoded KB"
                $altText = ConvertTo-HtmlEncode $Row.Name
                $displayValue = "<img src=`"$imgSrc`" alt=`"$altText`" title=`"$imgTitle`" style=`"max-width: 96px; max-height: 96px; border: 1px solid #555; border-radius: 4px;`" /><br><span style=`"font-size: 0.85em; color: #888;`">$imgTitle</span>"
                $attrNameEncoded = ConvertTo-HtmlEncode $Row.Name
                return "                        <div class=`"attr-row`" draggable=`"true`" data-attr-name=`"$attrNameEncoded`"><div class=`"attr-name`">$nameHtml</div><div class=`"attr-value`">$displayValue</div></div>"
            }

            # Fallback: display as text
            $displayHtml = ConvertTo-HtmlEncode $val.Display
            $attrNameEncoded = ConvertTo-HtmlEncode $Row.Name
            return "                        <div class=`"attr-row`" draggable=`"true`" data-attr-name=`"$attrNameEncoded`"><div class=`"attr-name`">$nameHtml</div><div class=`"attr-value`">$displayHtml</div></div>"
        }

        'Hash' {
            # Roasting hashes - always red/finding
            $val = $Row.Values[0]
            $displayHtml = ConvertTo-HtmlEncode $val.Display
            $dataAttr = if ($val.FindingId) { " data-finding-id=`"$(ConvertTo-HtmlEncode $val.FindingId)`"" } else { "" }
            $valueHtml = "<span class=`"finding`"$dataAttr>$displayHtml</span>"
            $attrNameEncoded = ConvertTo-HtmlEncode $Row.Name
            return "                        <div class=`"attr-row`" draggable=`"true`" data-attr-name=`"$attrNameEncoded`"><div class=`"attr-name`">$nameHtml</div><div class=`"attr-value`">$valueHtml</div></div>"
        }

        default {
            # Fallback
            $val = if ($Row.Values.Count -gt 0) { $Row.Values[0] } else { $null }
            $displayHtml = if ($val) { ConvertTo-HtmlEncode $val.Display } else { '' }
            $attrNameEncoded = ConvertTo-HtmlEncode $Row.Name
            return "                        <div class=`"attr-row`" draggable=`"true`" data-attr-name=`"$attrNameEncoded`"><div class=`"attr-name`">$nameHtml</div><div class=`"attr-value`">$displayHtml</div></div>"
        }
    }
}

# ============================================================================
# HTML Helper Functions
# ============================================================================

<#
.SYNOPSIS
    Wraps a display value in a severity-colored span with optional FindingId.
.DESCRIPTION
    If severity is Standard, returns the raw HTML. Otherwise wraps in a span
    with CSS class and optional data-finding-id for tooltip.
#>
function Format-HtmlValueSpan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DisplayHtml,

        [Parameter(Mandatory=$false)]
        [string]$Severity = 'Standard',

        [Parameter(Mandatory=$false)]
        [string]$FindingId = $null
    )

    if ($Severity -eq 'Standard' -or -not $Severity) {
        return $DisplayHtml
    }

    $cssClass = ConvertTo-HtmlEncode $Severity.ToLower()
    $dataAttr = if ($FindingId) { " data-finding-id=`"$(ConvertTo-HtmlEncode $FindingId)`"" } else { "" }
    return "<span class=`"$cssClass`"$dataAttr>$DisplayHtml</span>"
}

<#
.SYNOPSIS
    Returns the class attribute string for an attr-value div based on severity.
.DESCRIPTION
    For Standard severity, returns just class="attr-value".
    For other severities, adds the severity as CSS class.
#>
function Get-HtmlValueClassAttr {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Severity = 'Standard'
    )

    if ($Severity -eq 'Standard' -or -not $Severity) {
        return " class=`"attr-value`""
    }

    $cssClass = ConvertTo-HtmlEncode $Severity.ToLower()
    return " class=`"attr-value $cssClass`""
}
