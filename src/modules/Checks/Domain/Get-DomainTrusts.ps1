function Get-DomainTrusts {
    <#
    .SYNOPSIS
    Enumerates and analyzes domain trust relationships.

    .DESCRIPTION
    Collects comprehensive information about all domain trust relationships including:
    - Trust direction (Bidirectional, Inbound, Outbound)
    - Trust type (ParentChild, TreeRoot, External, Forest)
    - Trust attributes (Transitive, SID Filtering, Quarantined)

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-DomainTrusts

    .EXAMPLE
    Get-DomainTrusts -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Domain
    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    begin {
        Write-Log "[Get-DomainTrusts] Starting check"
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            Show-SubHeader "Searching for domain trusts..." -ObjectType "DomainTrust"

            $trustsRaw = Get-DomainObject -LDAPFilter "(objectClass=trustedDomain)" @PSBoundParameters

            # Filter out self-referencing trust objects (e.g. child domain's trust back to us
            # returned as phantom object from GC, or trust object where trustPartner = own domain)
            $domainDNS = $Script:LDAPContext.DomainDNS
            $trusts = @($trustsRaw) | Where-Object {
                $_.trustPartner -and $_.trustPartner -ne $domainDNS
            }

            if (@($trusts).Count -gt 0) {
                Show-Line "Found $(@($trusts).Count) domain trust(s):" -Class Hint

                foreach ($trust in $trusts) {
                    # trustDirection, trustType and trustAttributes are already decoded
                    # by Invoke-LDAPSearch into readable strings/arrays
                    $direction = $trust.trustDirection
                    $type = $trust.trustType
                    $attrFlags = @($trust.trustAttributes)

                    # Derive boolean flags from decoded trustAttributes array
                    $isBidirectional = ($direction -eq 'Bidirectional')
                    $isTransitive = ($attrFlags -notcontains 'NON_TRANSITIVE')
                    $isQuarantined = ($attrFlags -contains 'QUARANTINED_DOMAIN')
                    $isForestTrust = ($attrFlags -contains 'FOREST_TRANSITIVE')
                    $isCrossOrg = ($attrFlags -contains 'CROSS_ORGANIZATION')
                    $isWithinForest = ($attrFlags -contains 'WITHIN_FOREST')
                    $isTreatAsExternal = ($attrFlags -contains 'TREAT_AS_EXTERNAL')
                    $usesRC4 = ($attrFlags -contains 'USES_RC4_ENCRYPTION')

                    # Create enhanced trust object for Show-Object
                    # No distinguishedName - custom objects without standard AD attributes
                    # use the dynamic fallback in Get-RenderModel for console output
                    $trustObject = [PSCustomObject]@{
                        trustPartner = $trust.trustPartner
                        flatName = $trust.flatName
                        trustDirection = $direction
                        trustType = $type
                        trustAttributes = $attrFlags
                        isBidirectional = $isBidirectional
                        isTransitive = $isTransitive
                        isForestTrust = $isForestTrust
                        isWithinForest = $isWithinForest
                        isQuarantined = $isQuarantined
                        isCrossOrg = $isCrossOrg
                        isTreatAsExternal = $isTreatAsExternal
                        usesRC4 = $usesRC4
                        whenCreated = $trust.whenCreated
                    }

                    $trustObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'DomainTrust' -Force
                    Show-Object $trustObject

                }
            }

            if (@($trusts).Count -eq 0) {
                Show-Line "No external domain trusts found (isolated domain)" -Class Note
            }

        } catch {
            Write-Log "[Get-DomainTrusts] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-DomainTrusts] Check completed"
    }
}
