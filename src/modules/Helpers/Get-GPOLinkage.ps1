function Get-GPOLinkage {
    <#
    .SYNOPSIS
    Retrieves GPO linkage information (which OUs/Domains/Sites link to which GPOs).

    .DESCRIPTION
    Queries LDAP for all objects with gPLink attribute to determine where GPOs are applied.
    Returns a hashtable mapping GPO GUIDs to their linked locations.

    GPO Links in Active Directory:
    - Stored in 'gPLink' attribute on OU/Domain/Site objects
    - Format: [LDAP://cn={GUID},cn=policies,cn=system,DC=domain,DC=com;0]
    - Link Options: 0=Enabled, 1=Disabled, 2=Enforced, 3=Disabled+Enforced

    .EXAMPLE
    $linkage = Get-GPOLinkage
    $linkage["{GUID}"]  # Returns array of OUs where this GPO is linked

    .OUTPUTS
    Hashtable with GPO GUID as key and array of linked locations as value.

    .NOTES
    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    param()

    begin {
        Write-Log "[Get-GPOLinkage] Starting GPO linkage enumeration"
    }

    process {
        # Return cached result if available (GPO linkage is static during a session)
        if ($Script:CachedGPOLinkage) {
            Write-Log "[Get-GPOLinkage] Returning cached GPO linkage data ($($Script:CachedGPOLinkage.Count) GPOs)"
            return $Script:CachedGPOLinkage
        }

        # Internal helper - caller must ensure LDAP connection exists
        # UNIFIED: Check for LdapConnection (works for both LDAP and LDAPS)
        if (-not $Script:LdapConnection) {
            Show-NoSessionError -Context "Get-GPOLinkage"
            Write-Log "[Get-GPOLinkage] No LDAP connection - returning null"
            return $null
        }

        # Get Domain DN from LDAPContext
        $domainDN = $Script:LDAPContext.DomainDN
        $configDN = $Script:LDAPContext.ConfigurationDN

        if (-not $domainDN) {
            Write-Error "Domain DN not available in LDAPContext"
            return $null
        }

        Write-Log "[Get-GPOLinkage] Domain DN: $domainDN"
        Write-Log "[Get-GPOLinkage] Configuration DN: $configDN"

        # Hashtable: GPOGUID -> Array of linked OUs/Domains/Sites
        $gpoLinkage = @{}

        try {
            # ===== Search for all objects with gPLink attribute =====
            # This includes: OUs, Domain root, Sites
            # UNIFIED: Use Invoke-LDAPSearch instead of DirectorySearcher

            Write-Log "[Get-GPOLinkage] Searching for objects with gPLink attribute..."

            $results = Invoke-LDAPSearch -Filter "(gPLink=*)" -Properties "distinguishedName","gPLink","name","objectClass"

            if (-not $results) {
                Write-Log "[Get-GPOLinkage] No objects with GPO links found"
                return $gpoLinkage
            }

            Write-Log "[Get-GPOLinkage] Found $($results.Count) object(s) with GPO links"

            foreach ($result in $results) {
                $dn = $result.distinguishedName
                $gPLink = $result.gPLink
                $name = if ($result.name) { $result.name } else { $dn }
                $objectClass = if ($result.objectClass) { if ($result.objectClass -is [array]) { $result.objectClass[-1] } else { $result.objectClass } } else { "Unknown" }

                Write-Log "[Get-GPOLinkage] Processing: $dn"
                Write-Log "[Get-GPOLinkage] gPLink: $gPLink"

                # Parse gPLink attribute, Format: [LDAP://cn={GUID},cn=policies,cn=system,DC=domain,DC=com;0][LDAP://cn={GUID2},...;1]
                #
                # Each entry is parsed as a unit, because the GUID and its options are not
                # adjacent. The previous version searched for the GUID and its option digit
                # with one pattern - "\{GUID\};(\d+)" - which requires the ";0" to follow
                # the closing brace directly. In a real gPLink the rest of the DN sits in
                # between, so that pattern never matched, the options fell back to 0, and
                # every link came back Enabled and not enforced. Five checks filter on
                # "LinkStatus -ne 'Disabled'", so a GPO whose link an administrator had
                # disabled was still reported as applying, and enforcement - which decides
                # precedence between containers - was never seen at all.
                $entryPattern = '\[LDAP://(?<dn>[^;\]]+);(?<options>\d+)\]'
                $entries = [regex]::Matches($gPLink, $entryPattern)

                # Link order counts only the entries that actually apply, and it counts
                # from the end: the last enabled entry in the string wins within its
                # container. Collected in a first pass so the order is known before any
                # link object is built.
                $enabledGUIDs = [System.Collections.Generic.List[string]]::new()
                foreach ($entry in $entries) {
                    if ((([int]$entry.Groups['options'].Value) -band 1) -ne 0) { continue }  # bit 0 = disabled
                    if ($entry.Groups['dn'].Value -match '\{([0-9A-Fa-f\-]{36})\}') {
                        $enabledGUIDs.Add("{$($Matches[1].ToUpper())}")
                    }
                }

                $linkOrderMap = @{}
                $totalEnabled = $enabledGUIDs.Count
                for ($idx = 0; $idx -lt $totalEnabled; $idx++) {
                    $linkOrderMap[$enabledGUIDs[$idx]] = $totalEnabled - $idx
                }

                foreach ($entry in $entries) {
                    $entryDN = $entry.Groups['dn'].Value
                    if ($entryDN -notmatch '\{([0-9A-Fa-f\-]{36})\}') {
                        Write-Log "[Get-GPOLinkage] Skipping gPLink entry without a GPO GUID: $entryDN"
                        continue
                    }

                    # Normalize GUID to uppercase for consistent hashtable key matching
                    # GPO Name attribute uses uppercase, gPLink may use lowercase
                    $gpoGUID = "{$($Matches[1].ToUpper())}"
                    $linkOptions = [int]$entry.Groups['options'].Value

                    Write-Log "[Get-GPOLinkage] Linked GPO: $gpoGUID (options $linkOptions)"

                    # Decode link options
                    $isDisabled = ($linkOptions -band 1) -ne 0
                    $isEnforced = ($linkOptions -band 2) -ne 0

                    # A disabled link does not apply, whether or not it is also enforced,
                    # so that state is reported first.
                    $linkStatus = if ($isDisabled) {
                        "Disabled"
                    } elseif ($isEnforced) {
                        "Enforced"
                    } else {
                        "Enabled"
                    }

                    # Determine scope (Domain, OU, Site)
                    $scope = "OU"
                    if ($dn -eq $domainDN) {
                        $scope = "Domain"
                    }
                    elseif ($dn -match "CN=Sites,CN=Configuration") {
                        $scope = "Site"
                    }

                    # Create link object
                    # LinkOrder: 1 = highest priority within this container (last entry in gPLink string)
                    #            $null = disabled link (has no effective link order)
                    $linkInfo = [PSCustomObject]@{
                        DistinguishedName = $dn
                        Name = $name
                        Scope = $scope
                        LinkStatus = $linkStatus
                        IsEnforced = $isEnforced
                        IsDisabled = $isDisabled
                        ObjectClass = $objectClass
                        LinkOrder = if ($linkOrderMap.ContainsKey($gpoGUID)) { $linkOrderMap[$gpoGUID] } else { $null }
                    }

                    # Add to hashtable
                    if (-not $gpoLinkage.ContainsKey($gpoGUID)) {
                        $gpoLinkage[$gpoGUID] = @()
                    }

                    $gpoLinkage[$gpoGUID] += $linkInfo
                }
            }

            # No need to Dispose - Invoke-LDAPSearch handles cleanup internally

            Write-Log "[Get-GPOLinkage] GPO linkage enumeration complete. Found links for $($gpoLinkage.Count) GPO(s)"

            # Cache result for subsequent calls within the same session
            $Script:CachedGPOLinkage = $gpoLinkage
        }
        catch {
            Write-Error "Error during GPO linkage enumeration: $_"
            Write-Log $_.Exception.StackTrace
        }

        return $gpoLinkage
    }

    end {
        Write-Log "[Get-GPOLinkage] GPO linkage enumeration finished"
    }
}
