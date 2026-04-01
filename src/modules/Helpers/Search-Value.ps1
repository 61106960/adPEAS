<#
.SYNOPSIS
    Searches all attribute values of pipeline objects for a given pattern.

.DESCRIPTION
    Search-Value accepts AD objects from the pipeline (e.g., from Get-DomainUser,
    Get-DomainGroup, Get-DomainComputer) and searches all property values for a
    matching string. Matching objects are displayed with their identity and the
    properties that contain the match.

    By default, performs a case-insensitive wildcard search (*pattern*).
    Use -Exact for exact string matching or -Regex for regular expression matching.
    Use -Property to restrict the search to specific attributes.

.PARAMETER Pattern
    The search pattern. By default used as wildcard (*Pattern*).
    With -Exact: exact string comparison.
    With -Regex: regular expression.

.PARAMETER InputObject
    The object to search (from pipeline).

.PARAMETER Property
    Optional array of property names to search. If not specified, all properties are searched.

.PARAMETER Exact
    Perform exact string matching instead of wildcard.

.PARAMETER Regex
    Interpret Pattern as a regular expression.

.EXAMPLE
    Get-DomainUser | Search-Value "admin"
    Searches all user attributes for the string "admin".

.EXAMPLE
    Get-DomainUser | Search-Value "admin" -Property description,name
    Searches only the description and name attributes.

.EXAMPLE
    Get-DomainGroup | Search-Value "^Domain" -Regex
    Searches group attributes using a regular expression.

.EXAMPLE
    Get-DomainComputer | Search-Value "Windows Server 2019" -Exact
    Searches for an exact match of the string.

.OUTPUTS
    Console output with matching objects and their matching properties.

.NOTES
    Author: Alexander Sturz (@yourway_sec)
#>
function Search-Value {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Pattern,

        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [PSObject]$InputObject,

        [Parameter(Mandatory=$false)]
        [string[]]$Property,

        [Parameter(Mandatory=$false)]
        [switch]$Exact,

        [Parameter(Mandatory=$false)]
        [switch]$Regex
    )

    process {
        # Get properties to search
        $propsToSearch = if ($Property) {
            $InputObject.PSObject.Properties | Where-Object { $_.Name -in $Property }
        } else {
            $InputObject.PSObject.Properties
        }

        $matchResults = @()
        foreach ($prop in $propsToSearch) {
            # Skip binary/byte[] and null values
            if ($null -eq $prop.Value) { continue }
            if ($prop.Value -is [byte[]]) { continue }

            # Convert value to searchable string(s)
            $searchValues = if ($prop.Value -is [array]) {
                $prop.Value | ForEach-Object { "$_" }
            } else {
                @("$($prop.Value)")
            }

            foreach ($val in $searchValues) {
                $isMatch = if ($Exact) {
                    $val -eq $Pattern
                } elseif ($Regex) {
                    $val -match $Pattern
                } else {
                    $val -like "*$Pattern*"
                }

                if ($isMatch) {
                    $matchResults += [PSCustomObject]@{
                        Property = $prop.Name
                        Value    = $val
                    }
                }
            }
        }

        if ($matchResults.Count -gt 0) {
            # Determine object identity
            $identity = if ($InputObject.sAMAccountName) { $InputObject.sAMAccountName }
                       elseif ($InputObject.name) { $InputObject.name }
                       elseif ($InputObject.distinguishedName) { $InputObject.distinguishedName }
                       else { "(object)" }

            Write-Host "  $identity" -ForegroundColor Yellow
            foreach ($m in $matchResults) {
                Write-Host "    $($m.Property): " -ForegroundColor Cyan -NoNewline
                Write-Host "$($m.Value)" -ForegroundColor White
            }
        }
    }
}
