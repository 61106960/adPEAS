<#
.SYNOPSIS
    Performs LDAP searches using System.DirectoryServices.Protocols.LdapConnection.

.DESCRIPTION
    Central search function for all LDAP queries.
    Uses LdapConnection for efficient AD queries (works for both LDAP and LDAPS).

    Features:
    - Server-side LDAP filters
    - Paging for large result sets
    - Attribute selection for performance
    - Scope control (Base, OneLevel, Subtree)

.PARAMETER Filter
    LDAP filter string (e.g. "(&(objectClass=user)(adminCount=1))")

.PARAMETER SearchBase
    Distinguished Name as search base.
    Optional - Default: Domain DN from $Script:LDAPContext

.PARAMETER Properties
    Array of attribute names to load.
    Optional - Default: All attributes

.PARAMETER Scope
    Search scope: Base, OneLevel, Subtree
    Default: Subtree

.PARAMETER PageSize
    Page size for paging (performance for large result sets)
    Default: 1000

.PARAMETER SizeLimit
    Maximum number of results (0 = unlimited)
    Default: 0

.PARAMETER Raw
    Switch to return raw LDAP values without any conversions.
    When specified, all attribute conversions are skipped:
    - objectSid remains as byte array (not converted to string)
    - userAccountControl remains as Int32 (not converted to flag array)
    - DateTime attributes remain as Int64 (not converted to DateTime)
    - etc.
    Use this for performance when programmatically processing results.

.PARAMETER CountOnly
    Switch to return only the count of matching objects without collecting or converting them.
    Significantly reduces memory usage and processing time for large result sets
    where only the total number of matches is needed.
    Returns an integer instead of an array of PSCustomObjects.

.EXAMPLE
    Invoke-LDAPSearch -Filter "(&(objectClass=user)(adminCount=1))"
    Searches all users with adminCount=1

.EXAMPLE
    Invoke-LDAPSearch -Filter "(objectClass=group)" -Properties "sAMAccountName","member"
    Searches groups and loads only specific attributes

.EXAMPLE
    Invoke-LDAPSearch -Filter "(objectClass=user)" -Raw
    Searches users and returns raw LDAP values without conversions (faster for programmatic use)

.EXAMPLE
    Invoke-LDAPSearch -Filter "(&(objectClass=computer)(servicePrincipalName=CmRcService/*))" -CountOnly
    Returns only the count of matching computers without loading any object data

.OUTPUTS
    Array of PSCustomObjects with found AD objects

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function Invoke-LDAPSearch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Filter,

        [Parameter(Mandatory=$false)]
        [string]$SearchBase,

        [Parameter(Mandatory=$false)]
        [string[]]$Properties,

        [Parameter(Mandatory=$false)]
        [string[]]$AdditionalProperties,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Base", "OneLevel", "Subtree")]
        [string]$Scope = "Subtree",

        [Parameter(Mandatory=$false)]
        [int]$PageSize = 1000,

        [Parameter(Mandatory=$false)]
        [int]$SizeLimit = 0,

        [Parameter(Mandatory=$false)]
        [switch]$Raw,

        [Parameter(Mandatory=$false)]
        [switch]$CountOnly,

        [Parameter(Mandatory=$false)]
        [System.DirectoryServices.Protocols.LdapConnection]$LdapConnection
    )

    begin {
        Write-Log "[Invoke-LDAPSearch] Filter: $Filter"

        # Use provided connection or fall back to script-scope connection
        $ActiveConnection = if ($LdapConnection) { $LdapConnection } else { $Script:LdapConnection }

        if (-not $ActiveConnection) {
            throw "No LDAP connection available. Please run Connect-adPEAS first."
        }

        Write-Log "[Invoke-LDAPSearch] Using System.DirectoryServices.Protocols.LdapConnection"
    }

    process {
        try {
            # Determine SearchBase
            if ([string]::IsNullOrEmpty($SearchBase)) {
                if ($LdapConnection) {
                    # External connection (e.g. GC): use empty SearchBase for forest-wide search (default)
                    $SearchBase = ""
                    Write-Log "[Invoke-LDAPSearch] Using empty SearchBase for external connection (forest-wide)"
                } else {
                    $SearchBase = $Script:LDAPContext.DomainDN
                    Write-Log "[Invoke-LDAPSearch] Using domain DN as SearchBase: $SearchBase"
                }
            } else {
                # SearchBase was explicitly provided - use it
                Write-Log "[Invoke-LDAPSearch] Using explicit SearchBase: $SearchBase"
            }

            # Convert results to PSCustomObjects
            $OutputObjects = [System.Collections.ArrayList]@()

            Write-Log "[Invoke-LDAPSearch] Using LdapConnection for search"

            # Map scope
            $ProtocolScope = switch ($Scope) {
                "Base"     { [System.DirectoryServices.Protocols.SearchScope]::Base }
                "OneLevel" { [System.DirectoryServices.Protocols.SearchScope]::OneLevel }
                "Subtree"  { [System.DirectoryServices.Protocols.SearchScope]::Subtree }
                default    { [System.DirectoryServices.Protocols.SearchScope]::Subtree }
            }

            # Build attribute list
            # CRITICAL: Pass $null (not @("*")) to SearchRequest when Properties is null
            # On Global Catalog (port 3268), @("*") behaves differently than $null:
            # - $null -> Returns all PAS attributes (correct for GC)
            # - @("*") -> May return DN-only for cross-partition objects (S.DS.P GC quirk)
            $AttributeList = $null

            # CountOnly: force "1.1" (no attributes) to minimize network traffic
            if ($CountOnly) {
                $AttributeList = [string[]]@("1.1")
                Write-Log "[Invoke-LDAPSearch] CountOnly mode: requesting no attributes (1.1)"
            } elseif ($Properties -and $Properties.Count -gt 0) {
                $AttributeList = [string[]]$Properties
                if ($AdditionalProperties) {
                    $AttributeList = [string[]]($Properties + $AdditionalProperties | Select-Object -Unique)
                }
                Write-Log "[Invoke-LDAPSearch] Requesting attributes: $($AttributeList -join ', ')"
            } else {
                # Request all attributes by passing $null (NOT @("*"))
                # $null works correctly on both port 389 and GC port 3268
                $AttributeList = $null
                Write-Log "[Invoke-LDAPSearch] Requesting ALL attributes (null list for GC compatibility)"
            }

            # Create search request
            $SearchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest($SearchBase,$Filter,$ProtocolScope,$AttributeList)

            # Add paging control
            $PageControl = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($PageSize)
            $SearchRequest.Controls.Add($PageControl) | Out-Null

            # Add DomainScope control to prevent phantom results from other domain partitions
            # When the DC is also a Global Catalog, subtree searches can return objects from
            # child domains (phantom objects) even with ReferralChasing=None on the session.
            # SearchOptionsControl with DomainScope tells the DC to only return objects from
            # the domain partition specified by the SearchBase.
            # CRITICAL: Only apply DomainScope to main connection, NOT to external GC connections
            # (GC connections NEED forest-wide results)
            if (-not $LdapConnection) {
                $DomainScopeControl = New-Object System.DirectoryServices.Protocols.SearchOptionsControl(
                    [System.DirectoryServices.Protocols.SearchOption]::DomainScope
                )
                $SearchRequest.Controls.Add($DomainScopeControl) | Out-Null
            }

            # Add SecurityDescriptor control if nTSecurityDescriptor is requested
            $AllRequestedProps = @()
            if ($Properties) { $AllRequestedProps += $Properties }
            if ($AdditionalProperties) { $AllRequestedProps += $AdditionalProperties }

            if ($AllRequestedProps -contains "nTSecurityDescriptor" -or $AttributeList -contains "*") {
                # SecurityDescriptorFlagControl: Owner (1) + Group (2) + DACL (4) = 7
                $SDControl = New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl(
                    [System.DirectoryServices.Protocols.SecurityMasks]::Dacl -bor
                    [System.DirectoryServices.Protocols.SecurityMasks]::Owner -bor
                    [System.DirectoryServices.Protocols.SecurityMasks]::Group
                )
                $SearchRequest.Controls.Add($SDControl) | Out-Null
                Write-Log "[Invoke-LDAPSearch] Added SecurityDescriptorFlagControl for nTSecurityDescriptor"
            }

            # Known binary attributes that need byte[] extraction (defined once, used per-attribute)
            $BinaryAttributeSet = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::OrdinalIgnoreCase
            )
            foreach ($ba in @(
                'objectsid', 'objectguid', 'ntsecuritydescriptor', 'sidhistory',
                'msexchmailboxguid', 'msexchmailboxsecuritydescriptor', 'msexchblockedsendershash',
                'msexchsafesendershash', 'msexchmasteraccountsid', 'ms-ds-creatorsid',
                'msds-generationid', 'msds-groupmsamembership', 'msds-managedpasswordid',
                'msds-managedpasswordpreviousid', 'ms-ds-consistencyguid', 'logonhours',
                'msds-allowedtoactonbehalfofotheridentity', 'mslaps-encryptedpassword',
                'mslaps-encryptedpasswordhistory', 'mslaps-encrypteddsconfigurationdata',
                'msfve-recoveryguid', 'msfve-volumeguid',
                'thumbnailphoto', 'jpegphoto', 'usercertificate', 'cacertificate',
                'msds-keyversionnumber', 'repluptodatevector', 'replpropertymeta',
                'pkiexpirationperiod', 'pkioverlapperiod', 'pkikeyusage',
                'extensiondata',
                'msmqdigests', 'msmqsigncertificates',
                'userparameters', 'terminalserver'
            )) { [void]$BinaryAttributeSet.Add($ba) }

            # CountOnly mode: only count matching objects without collecting or converting them
            if ($CountOnly) {
                $TotalCount = 0
                do {
                    $SearchResponse = $ActiveConnection.SendRequest($SearchRequest)

                    # Statistics tracking (CountOnly path)
                    if ($Script:LDAPStatistics) {
                        $Script:LDAPStatistics.TotalQueries++
                        # Base overhead per request/response (~search filter + controls + response header)
                        $Script:LDAPStatistics.TotalEstimatedBytes += 200
                        if ($SearchResponse.Entries) {
                            $Script:LDAPStatistics.TotalResults += $SearchResponse.Entries.Count
                            # CountOnly still returns DNs - estimate ~120 bytes per entry (DN + envelope)
                            $Script:LDAPStatistics.TotalEstimatedBytes += $SearchResponse.Entries.Count * 120
                        }
                    }

                    if ($SearchResponse.Entries) {
                        $TotalCount += $SearchResponse.Entries.Count
                    }

                    # Check for paging response control
                    $PageResponseControl = $null
                    foreach ($ctrl in $SearchResponse.Controls) {
                        if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl]) {
                            $PageResponseControl = $ctrl
                            break
                        }
                    }

                    if ($PageResponseControl -and $PageResponseControl.Cookie.Length -gt 0) {
                        $PageControl.Cookie = $PageResponseControl.Cookie
                    } else {
                        break
                    }
                } while ($true)

                Write-Log "[Invoke-LDAPSearch] CountOnly: $TotalCount objects matched"
                return $TotalCount
            }

            # Execute paged search
            $AllEntries = [System.Collections.ArrayList]@()
            do {
                $SearchResponse = $ActiveConnection.SendRequest($SearchRequest)

                # Statistics tracking (full search path)
                if ($Script:LDAPStatistics) {
                    $Script:LDAPStatistics.TotalQueries++
                    # Base overhead per request/response (~search filter + controls + response header)
                    $Script:LDAPStatistics.TotalEstimatedBytes += 200
                    if ($SearchResponse.Entries) {
                        $Script:LDAPStatistics.TotalResults += $SearchResponse.Entries.Count
                    }
                }

                if ($SearchResponse.Entries) {
                    [void]$AllEntries.AddRange($SearchResponse.Entries)
                }

                # Check for paging response control
                $PageResponseControl = $null
                foreach ($ctrl in $SearchResponse.Controls) {
                    if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl]) {
                        $PageResponseControl = $ctrl
                        break
                    }
                }

                if ($PageResponseControl -and $PageResponseControl.Cookie.Length -gt 0) {
                    $PageControl.Cookie = $PageResponseControl.Cookie
                } else {
                    break
                }

                # Check SizeLimit
                if ($SizeLimit -gt 0 -and $AllEntries.Count -ge $SizeLimit) {
                    break
                }

            } while ($true)

            Write-Log "[Invoke-LDAPSearch] Found: $($AllEntries.Count) objects via LdapConnection"

            # Convert LdapConnection results to PSCustomObjects with full attribute conversion
            foreach ($Entry in $AllEntries) {
                $Obj = [PSCustomObject]@{}

                # Add distinguishedName first (use -Force in case it's also in Attributes)
                $Obj | Add-Member -Force -NotePropertyName "distinguishedName" -NotePropertyValue $Entry.DistinguishedName

                # Statistics: count DN bytes per entry (~DN string + LDAP envelope overhead)
                if ($Script:LDAPStatistics -and $Entry.DistinguishedName) {
                    $Script:LDAPStatistics.TotalEstimatedBytes += $Entry.DistinguishedName.Length * 2 + 40
                }

                # Call .get_Item([string]) directly instead of the PowerShell [] indexer:
                # PS's indexer resolution on SearchResultAttributeCollection silently drops
                # some attributes (e.g. objectSid, msExchDelegateListBL) with a null result.
                $EntryAttrs = $Entry.Attributes
                if (-not $EntryAttrs) { continue }
                foreach ($PropName in $EntryAttrs.AttributeNames) {
                    if ([string]::IsNullOrEmpty($PropName)) { continue }
                    $AttrValues = $null
                    try { $AttrValues = $EntryAttrs.get_Item([string]$PropName) } catch {
                        Write-Log "[Invoke-LDAPSearch] Failed to read attribute '$PropName' on '$($Entry.DistinguishedName)': $($_.Exception.Message)" -Level Warning
                        continue
                    }
                    if ($null -eq $AttrValues) { continue }

                    # Statistics: estimate bytes for this attribute
                    if ($Script:LDAPStatistics) {
                        for ($si = 0; $si -lt $AttrValues.Count; $si++) {
                            try {
                                $statVal = $AttrValues[$si]
                                if ($statVal -is [byte[]]) {
                                    $Script:LDAPStatistics.TotalEstimatedBytes += $statVal.Length
                                } elseif ($statVal -is [string]) {
                                    $Script:LDAPStatistics.TotalEstimatedBytes += $statVal.Length * 2  # UTF-16
                                } else {
                                    $Script:LDAPStatistics.TotalEstimatedBytes += 8  # fixed-size estimate
                                }
                            } catch {
                                $Script:LDAPStatistics.TotalEstimatedBytes += 8
                            }
                        }
                        # Add attribute name overhead (~DN length + attribute name)
                        $Script:LDAPStatistics.TotalEstimatedBytes += $PropName.Length + 20
                    }

                    # Build PropValue array from LdapConnection attribute values
                    # NOTE: DirectoryAttribute indexer returns strings by default.
                    # For binary attributes, we need to use GetValues([byte[]]) to get raw bytes.
                    $PropValue = @()
                    $PropNameLower = $PropName.ToLower()

                    if ($BinaryAttributeSet.Contains($PropNameLower)) {
                        # Binary attribute - extract as byte arrays
                        try {
                            $ByteValues = $AttrValues.GetValues([byte[]])
                            foreach ($bv in $ByteValues) {
                                $PropValue += ,$bv  # Use comma to prevent array flattening
                            }
                        } catch {
                            # Fallback to string extraction if byte[] fails
                            for ($i = 0; $i -lt $AttrValues.Count; $i++) {
                                $PropValue += $AttrValues[$i]
                            }
                        }
                    } else {
                        # Non-binary attribute - use default string extraction
                        for ($i = 0; $i -lt $AttrValues.Count; $i++) {
                            $PropValue += $AttrValues[$i]
                        }
                    }

                    # If -Raw is specified, skip all conversions and return raw values
                    if ($Raw) {
                        # Raw mode - no conversions, just add property as-is
                        if ($PropValue.Count -eq 1) {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value $PropValue[0]
                        } else {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $PropName -Value @($PropValue)
                        }
                        continue
                    }

                    # The conversion itself lives in ConvertFrom-LDAPAttribute (Core). It
                    # used to sit here inline, roughly 1400 lines of it, which is why none
                    # of it could be tested: reaching it meant calling this function, and
                    # that needs a real SearchResponse. Split out, it is name and raw value
                    # in, properties out - usually one property, occasionally none (a raw
                    # value that carried nothing usable), three for msLAPS-Password.
                    $ConvertedProps = ConvertFrom-LDAPAttribute -Name $PropName -Value $PropValue
                    if ($ConvertedProps -and $ConvertedProps.Count -gt 0) {
                        foreach ($ConvertedName in $ConvertedProps.Keys) {
                            $Obj | Add-Member -Force -MemberType NoteProperty -Name $ConvertedName -Value $ConvertedProps[$ConvertedName]
                        }
                    }
                }

                # Sort properties alphabetically for consistent output
                $SortedPropertyNames = $Obj.PSObject.Properties.Name | Sort-Object

                $SortedObj = [PSCustomObject]@{}
                foreach ($SortedPropName in $SortedPropertyNames) {
                    $SortedObj | Add-Member -Force -MemberType NoteProperty -Name $SortedPropName -Value $Obj.$SortedPropName
                }

                [void]$OutputObjects.Add($SortedObj)
            }

            Write-Log "[Invoke-LDAPSearch] Processing completed: $($OutputObjects.Count) objects"
            return $OutputObjects

        } catch {
            # Check if it's a "not found" error (expected case when SearchBase doesn't exist)
            # Uses central error handling from adPEAS-ErrorCodes.ps1
            if (Test-LDAPErrorNotFound -Exception $_.Exception) {
                # Not an error - just no results. Return empty array silently.
                Write-Log "[Invoke-LDAPSearch] SearchBase not found: $SearchBase"
                return @()
            } else {
                # Real error - log and re-throw
                Write-Log "[Invoke-LDAPSearch] Error during LDAP search: $_"
                throw
            }
        }
    }

    end {
    }
}
