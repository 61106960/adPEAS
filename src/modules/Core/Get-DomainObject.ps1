function Get-DomainObject {
<#
.SYNOPSIS
    Universal function for querying ANY Active Directory object.

.DESCRIPTION
    Get-DomainObject is a flexible helper function that can query ANY AD object type without needing to know the object class beforehand.
    It supports:

    - Search by Identity (sAMAccountName, DN, SID, GUID, DOMAIN\name)
    - Search by ObjectClass (user, computer, group, contact, organizationalUnit, etc.)
    - Flexible property selection
    - Custom LDAP filters
    - LDAP-optimized account status filters (IsEnabled, IsDisabled, etc.)
    - nTSecurityDescriptor is automatically loaded and converted when querying all properties

    This is useful when you don't know the object type in advance (e.g., resolving ACEs, memberOf attributes, or forensic analysis).

.PARAMETER Identity
    sAMAccountName, DistinguishedName, SID, ObjectGUID, or DOMAIN\name format.
    Wildcards are supported for sAMAccountName.

.PARAMETER ObjectClass
    Filter by specific object class (e.g., "user", "computer", "group", "contact",
    "organizationalUnit", "container", "domainDNS", etc.).

.PARAMETER LDAPFilter
    Custom LDAP filter for special queries.

.PARAMETER Properties
    Array of attribute names to return.
    Default: All default properties from Invoke-LDAPSearch.

.PARAMETER ShowOwner
    Include Owner and OwnerSID properties on returned objects.
    Use Get-ObjectOwner -NonDefaultOnly to filter for non-default owners.

.PARAMETER SearchBase
    Alternative SearchBase (DN). Default: Domain DN.

.PARAMETER Scope
    Search scope: Subtree (default), OneLevel, or Base.
    - Subtree: Search the entire subtree (default)
    - OneLevel: Search only immediate children
    - Base: Search only the base object itself

.PARAMETER Raw
    Switch to return raw LDAP values without conversions (passed through to Invoke-LDAPSearch).
    Use this for performance when programmatically processing results.

.PARAMETER IsEnabled
    LDAP-optimized filter: Return only enabled accounts (ACCOUNTDISABLE flag NOT set).
    Uses bitwise LDAP filter for server-side filtering (fast).

.PARAMETER IsDisabled
    LDAP-optimized filter: Return only disabled accounts (ACCOUNTDISABLE flag set).
    Uses bitwise LDAP filter for server-side filtering (fast).

.PARAMETER PasswordNeverExpires
    LDAP-optimized filter: Return only accounts with PASSWORD_NEVER_EXPIRES flag set.
    Uses bitwise LDAP filter for server-side filtering (fast).

.PARAMETER PasswordNotRequired
    LDAP-optimized filter: Return only accounts with PASSWORD_NOT_REQUIRED flag set.
    Uses bitwise LDAP filter for server-side filtering (fast).

.PARAMETER TrustedForDelegation
    LDAP-optimized filter: Return only accounts with TRUSTED_FOR_DELEGATION flag set.
    Uses bitwise LDAP filter for server-side filtering (fast).

.PARAMETER TrustedToAuthForDelegation
    LDAP-optimized filter: Return only accounts with TRUSTED_TO_AUTH_FOR_DELEGATION flag set.
    Uses bitwise LDAP filter for server-side filtering (fast).

.PARAMETER HasSPN
    LDAP-optimized filter: Return only accounts with servicePrincipalName attribute set.
    Useful for finding Kerberoastable accounts.

.PARAMETER AdminCount
    LDAP-optimized filter: Return only accounts with adminCount=1.
    Indicates accounts that are/were members of privileged groups.

.PARAMETER PasswordMustChange
    LDAP-optimized filter: Return only accounts where pwdLastSet=0.
    These accounts must change their password at next logon.

.PARAMETER LockedOut
    LDAP-optimized filter: Return only locked out accounts (lockoutTime > 0).

.PARAMETER SmartcardRequired
    LDAP-optimized filter: Return only accounts with SMARTCARD_REQUIRED flag set.
    Uses bitwise LDAP filter for server-side filtering (fast).

.PARAMETER AccountExpired
    Return only accounts where accountExpires is in the past.
    Note: Requires post-processing as LDAP cannot compare to current time.

.PARAMETER AccountNeverExpires
    LDAP-optimized filter: Return only accounts where accountExpires is 0 or never set.

.PARAMETER PreauthNotRequired
    LDAP-optimized filter: Return only accounts with DONT_REQ_PREAUTH flag set.
    These accounts are vulnerable to AS-REP Roasting attacks!

.PARAMETER DESOnly
    LDAP-optimized filter: Return only accounts with USE_DES_KEY_ONLY flag set.
    These accounts use weak DES encryption for Kerberos.

.PARAMETER ReversibleEncryption
    LDAP-optimized filter: Return only accounts with ENCRYPTED_TEXT_PWD_ALLOWED flag set.
    These accounts store passwords with reversible encryption - security risk!

.PARAMETER NotDelegated
    LDAP-optimized filter: Return only accounts with NOT_DELEGATED flag set.
    These accounts are protected from delegation attacks.

.EXAMPLE
    Get-DomainObject -Identity "CN=Brad Pitt,OU=Users,DC=contoso,DC=com"
    Returns any object with this DN (automatically detects if User, Group, etc.).

.EXAMPLE
    Get-DomainObject -Identity "Administrator"
    Returns any object with sAMAccountName "Administrator" (could be User or Group).

.EXAMPLE
    Get-DomainObject -Identity "S-1-5-21-...-500"
    Returns any object with this SID.

.EXAMPLE
    Get-DomainObject -ObjectClass "contact"
    Returns all Contact objects in the domain.

.EXAMPLE
    Get-DomainObject -Identity "WORKSTATION01$" -ShowOwner
    Returns the computer object with Owner and OwnerSID properties.

.EXAMPLE
    Get-DomainObject -LDAPFilter "(description=*admin*)"
    Returns all objects with "admin" in their description.

.EXAMPLE
    Get-DomainObject -ObjectClass "user" -IsEnabled -PasswordNeverExpires
    Returns all enabled user accounts with PASSWORD_NEVER_EXPIRES flag (LDAP-optimized).

.EXAMPLE
    Get-DomainObject -ObjectClass "user" -IsEnabled -HasSPN
    Returns all enabled accounts with SPNs set (potential Kerberoast targets).

.OUTPUTS
    PSCustomObject with object attributes, plus objectClass property showing type.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding()]
    param(
        [Parameter(Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('distinguishedName', 'Name')]
        [string]$Identity,

        [Parameter(Mandatory=$false)]
        [string]$ObjectClass,

        [Parameter(Mandatory=$false)]
        [string]$LDAPFilter,

        [Parameter(Mandatory=$false)]
        [string[]]$Properties,

        [Parameter(Mandatory=$false)]
        [switch]$ShowOwner,

        [Parameter(Mandatory=$false)]
        [string]$SearchBase,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Subtree', 'OneLevel', 'Base')]
        [string]$Scope = 'Subtree',

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$Raw,

        [Parameter(Mandatory=$false)]
        [int]$ResultLimit = 0,

        # ===== LDAP-Optimized Account Filters =====
        # These use bitwise LDAP filters for server-side filtering (fast!)

        [Parameter(Mandatory=$false)]
        [switch]$IsEnabled,

        [Parameter(Mandatory=$false)]
        [switch]$IsDisabled,

        [Parameter(Mandatory=$false)]
        [switch]$PasswordNeverExpires,

        [Parameter(Mandatory=$false)]
        [switch]$PasswordNotRequired,

        [Parameter(Mandatory=$false)]
        [switch]$TrustedForDelegation,

        [Parameter(Mandatory=$false)]
        [switch]$TrustedToAuthForDelegation,

        [Parameter(Mandatory=$false)]
        [switch]$HasSPN,

        [Parameter(Mandatory=$false)]
        [switch]$AdminCount,

        [Parameter(Mandatory=$false)]
        [switch]$PasswordMustChange,

        [Parameter(Mandatory=$false)]
        [switch]$LockedOut,

        [Parameter(Mandatory=$false)]
        [switch]$SmartcardRequired,

        [Parameter(Mandatory=$false)]
        [switch]$AccountExpired,

        [Parameter(Mandatory=$false)]
        [switch]$AccountNeverExpires,

        [Parameter(Mandatory=$false)]
        [switch]$PreauthNotRequired,

        [Parameter(Mandatory=$false)]
        [switch]$DESOnly,

        [Parameter(Mandatory=$false)]
        [switch]$ReversibleEncryption,

        [Parameter(Mandatory=$false)]
        [switch]$NotDelegated
    )

    begin {
        Write-Log "[Get-DomainObject] Starting object enumeration"

        # Ensure LDAP connection exists (auto-connect if needed)
        $ConnectionParams = @{}
        if ($Domain) { $ConnectionParams['Domain'] = $Domain }
        if ($Server) { $ConnectionParams['Server'] = $Server }
        if ($Credential) { $ConnectionParams['Credential'] = $Credential }

        if (-not (Ensure-LDAPConnection @ConnectionParams)) {
            # No session - Show-NoSessionError was already called by Ensure-LDAPConnection
            # process{} will check $Script:LDAPContext and skip if not set
            return
        }

        # Reset Verbose cache for SID resolution (so user sees SID resolutions for each query)
        if ($Script:SIDVerboseCache) {
            $Script:SIDVerboseCache.Clear()
            Write-Log "[Get-DomainObject] Reset SID verbose cache for new query"
        }
    }

    process {
        # Skip processing if connection failed in begin{}
        if (-not $Script:LDAPContext) {
            return $null
        }

        try {
            # Build Filter based on what's provided
            if ($LDAPFilter -and -not $Identity -and -not $ObjectClass) {
                # Use LDAPFilter directly when it's the only filter
                $Filter = $LDAPFilter
            } else {
                # Build composite filter
                $Filter = "(objectClass=*)"

                # Build Identity filter
                if ($Identity) {
                    # Resolve cross-domain identity (if DOMAIN\name format)
                    $crossDomainInfo = Resolve-CrossDomainIdentity -Identity $Identity
                    $crossDomainQuery = $crossDomainInfo.IsCrossDomain
                    $targetDomainDN = $crossDomainInfo.TargetDomainDN
                    $targetDomainFQDN = $crossDomainInfo.TargetDomainFQDN

                    # Use the extracted identity (without domain prefix)
                    $Identity = $crossDomainInfo.Identity

                    if ($crossDomainQuery) {
                        Write-Log "[Get-DomainObject] Cross-domain query detected: $($crossDomainInfo.Domain) - using GC"
                    }

                    # Check if SID, DN, GUID, or sAMAccountName
                    if ($Identity -match '^S-1-5-.*') {
                        # SID Format - convert to hex for LDAP
                        $SIDObj = New-Object System.Security.Principal.SecurityIdentifier($Identity)
                        $SIDBytes = New-Object byte[] $SIDObj.BinaryLength
                        $SIDObj.GetBinaryForm($SIDBytes, 0)
                        $SIDHex = ($SIDBytes | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                        $IdentityFilter = "(objectSid=$SIDHex)"
                    } elseif ($Identity -match '^CN=.*|^OU=.*|^DC=.*') {
                        # Distinguished Name
                        $IdentityFilter = "(distinguishedName=$Identity)"
                    } elseif ($Identity -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
                        # GUID Format (e.g., "bf967aba-0de6-11d0-a285-00aa003049e2")
                        $GUIDObj = [System.Guid]::Parse($Identity)
                        $GUIDBytes = $GUIDObj.ToByteArray()
                        $GUIDHex = ($GUIDBytes | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                        $IdentityFilter = "(objectGUID=$GUIDHex)"
                    } else {
                        # sAMAccountName (with wildcard support)
                        # Also try cn and name attributes for objects without sAMAccountName
                        $IdentityFilter = "(|(sAMAccountName=$Identity)(cn=$Identity)(name=$Identity))"
                    }

                    # Combine base filter with identity filter
                    $Filter = "(&$Filter$IdentityFilter)"
                }

                # ObjectClass filter (if specified)
                if ($ObjectClass) {
                    $Filter = "(&$Filter(objectClass=$ObjectClass))"
                }

                # Append custom LDAP filter (only when combined with Identity or ObjectClass)
                if ($LDAPFilter) {
                    $Filter = "(&$Filter$LDAPFilter)"
                }
            }

            # ===== Apply LDAP-optimized account filters =====
            # These use LDAP_MATCHING_RULE_BIT_AND (1.2.840.113556.1.4.803) for bitwise AND
            # or LDAP_MATCHING_RULE_BIT_OR (1.2.840.113556.1.4.804) for bitwise OR

            $accountFilters = @()

            # IsEnabled: ACCOUNTDISABLE (0x0002) flag NOT set
            if ($IsEnabled) {
                $accountFilters += "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
            }

            # IsDisabled: ACCOUNTDISABLE (0x0002) flag IS set
            if ($IsDisabled) {
                $accountFilters += "(userAccountControl:1.2.840.113556.1.4.803:=2)"
            }

            # PasswordNeverExpires: DONT_EXPIRE_PASSWD (0x10000 = 65536) flag set
            if ($PasswordNeverExpires) {
                $accountFilters += "(userAccountControl:1.2.840.113556.1.4.803:=65536)"
            }

            # PasswordNotRequired: PASSWD_NOTREQD (0x0020 = 32) flag set
            if ($PasswordNotRequired) {
                $accountFilters += "(userAccountControl:1.2.840.113556.1.4.803:=32)"
            }

            # TrustedForDelegation: TRUSTED_FOR_DELEGATION (0x80000 = 524288) flag set
            if ($TrustedForDelegation) {
                $accountFilters += "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            }

            # TrustedToAuthForDelegation: TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000 = 16777216) flag set
            if ($TrustedToAuthForDelegation) {
                $accountFilters += "(userAccountControl:1.2.840.113556.1.4.803:=16777216)"
            }

            # HasSPN: servicePrincipalName attribute exists
            if ($HasSPN) {
                $accountFilters += "(servicePrincipalName=*)"
            }

            # AdminCount: adminCount = 1
            if ($AdminCount) {
                $accountFilters += "(adminCount=1)"
            }

            # PasswordMustChange: pwdLastSet = 0 (user must change password at next logon)
            if ($PasswordMustChange) {
                $accountFilters += "(pwdLastSet=0)"
            }

            # LockedOut: lockoutTime > 0 (account is locked)
            if ($LockedOut) {
                $accountFilters += "(lockoutTime>=1)"
            }

            # SmartcardRequired: SMARTCARD_REQUIRED (0x40000 = 262144) flag set
            if ($SmartcardRequired) {
                $accountFilters += "(userAccountControl:1.2.840.113556.1.4.803:=262144)"
            }

            # AccountExpired: accountExpires is set and in the past
            # Note: This requires post-processing as LDAP can't compare timestamps to "now"
            # We filter for accounts where accountExpires is set (not 0 or never)
            if ($AccountExpired) {
                # accountExpires = 0 or 9223372036854775807 means never expires
                # We get accounts with expiration set, then filter in post-processing
                $accountFilters += "(&(accountExpires>=1)(!(accountExpires=9223372036854775807)))"
                $Script:FilterAccountExpired = $true
            }

            # AccountNeverExpires: accountExpires = 0 or 9223372036854775807 (never/not set)
            if ($AccountNeverExpires) {
                $accountFilters += "(|(accountExpires=0)(accountExpires=9223372036854775807))"
            }

            # PreauthNotRequired: DONT_REQ_PREAUTH (0x400000 = 4194304) flag set - AS-REP Roastable!
            if ($PreauthNotRequired) {
                $accountFilters += "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
            }

            # DESOnly: USE_DES_KEY_ONLY (0x200000 = 2097152) flag set - weak encryption
            if ($DESOnly) {
                $accountFilters += "(userAccountControl:1.2.840.113556.1.4.803:=2097152)"
            }

            # ReversibleEncryption: ENCRYPTED_TEXT_PWD_ALLOWED (0x80 = 128) flag set
            if ($ReversibleEncryption) {
                $accountFilters += "(userAccountControl:1.2.840.113556.1.4.803:=128)"
            }

            # NotDelegated: NOT_DELEGATED (0x100000 = 1048576) flag set - protected from delegation
            if ($NotDelegated) {
                $accountFilters += "(userAccountControl:1.2.840.113556.1.4.803:=1048576)"
            }

            # Append all account filters to main filter
            if ($accountFilters.Count -gt 0) {
                $allAccountFilters = $accountFilters -join ''
                $Filter = "(&$Filter$allAccountFilters)"
                Write-Log "[Get-DomainObject] Applied LDAP-optimized filters: $($accountFilters -join ', ')"
            }

            Write-Log "[Get-DomainObject] Using filter: $Filter"

            # Prepare Invoke-LDAPSearch parameters
            $SearchParams = @{
                Filter = $Filter
            }

            if ($Properties) {
                $SearchParams['Properties'] = $Properties
            }

            # If ShowOwner is set, ensure nTSecurityDescriptor is loaded
            # (nTSecurityDescriptor is automatically converted by Invoke-LDAPSearch when requested)
            if ($ShowOwner) {
                if ($Properties) {
                    # Add nTSecurityDescriptor to Properties if not already present
                    if ($Properties -inotcontains 'nTSecurityDescriptor') {
                        $SearchParams['Properties'] = $Properties + 'nTSecurityDescriptor'
                    }
                } else {
                    # Use AdditionalProperties to load nTSecurityDescriptor alongside all other properties
                    $SearchParams['AdditionalProperties'] = @('nTSecurityDescriptor')
                }
                Write-Log "[Get-DomainObject] ShowOwner enabled - nTSecurityDescriptor will be included in results"
            }

            # Set SearchBase: cross-domain DN takes precedence over user-specified SearchBase
            if ($targetDomainDN) {
                $SearchParams['SearchBase'] = $targetDomainDN
                Write-Log "[Get-DomainObject] Using cross-domain SearchBase: $targetDomainDN"
            } elseif ($SearchBase) {
                $SearchParams['SearchBase'] = $SearchBase
            }

            if ($Scope) {
                $SearchParams['Scope'] = $Scope
            }

            if ($Raw) {
                $SearchParams['Raw'] = $true
            }

            if ($ResultLimit -gt 0) {
                $SearchParams['SizeLimit'] = $ResultLimit
            }

            # For cross-domain queries, use Global Catalog
            if ($crossDomainQuery) {
                $gcConn = Get-GCConnection
                if ($gcConn) {
                    Write-Log "[Get-DomainObject] Using GC connection for cross-domain query"
                    $SearchParams['LdapConnection'] = $gcConn
                    # Keep SearchBase if set (for domain-specific cross-domain queries)
                    # Only remove if not set by cross-domain logic (= forest-wide fallback)
                    if (-not $targetDomainDN -and $SearchParams.ContainsKey('SearchBase')) {
                        $SearchParams.Remove('SearchBase')
                        Write-Log "[Get-DomainObject] Removed SearchBase for forest-wide fallback"
                    }
                } else {
                    Write-Log "[Get-DomainObject] GC connection unavailable - query may return incorrect results" -Level Warning
                }
            }

            # Execute search
            $Objects = @(Invoke-LDAPSearch @SearchParams)

            Write-Log "[Get-DomainObject] Found $($Objects.Count) object(s)"

            # Post-processing for cross-domain queries: filter out child domains
            # SearchBase with Subtree scope includes child domains (e.g., DC=dev,DC=contoso,DC=com when searching DC=contoso,DC=com)
            # We use Test-DomainMatch to extract domain FQDN from distinguishedName (DN) and compare with target domain
            if ($targetDomainFQDN -and $Objects.Count -gt 0) {
                $FilteredObjects = @()

                foreach ($Obj in $Objects) {
                    if ($Obj.distinguishedName) {
                        # Use centralized Test-DomainMatch function for domain filtering
                        if (Test-DomainMatch -DistinguishedName $Obj.distinguishedName -TargetDomainFQDN $targetDomainFQDN) {
                            $FilteredObjects += $Obj
                        }
                        # Test-DomainMatch logs mismatches internally, no need for extra logging here
                    } else {
                        # Fallback: if DN missing (shouldn't happen), include object
                        Write-Log "[Get-DomainObject] Warning: Object has no distinguishedName - including anyway" -Level Warning
                        $FilteredObjects += $Obj
                    }
                }

                $Objects = $FilteredObjects
                Write-Log "[Get-DomainObject] After cross-domain post-filter: $($Objects.Count) object(s)"
            }

            # Post-processing for AccountExpired filter (LDAP can't compare to "now")
            if ($AccountExpired -and $Objects.Count -gt 0) {
                $Now = [DateTime]::UtcNow
                $NowFileTime = $Now.ToFileTimeUtc()
                $FilteredObjects = @()

                foreach ($Obj in $Objects) {
                    if ($Obj.accountExpires) {
                        try {
                            $ExpireTime = $Obj.accountExpires
                            # Convert to Int64 if it's a string
                            if ($ExpireTime -is [string]) {
                                $ExpireTime = [Int64]::Parse($ExpireTime)
                            }
                            # Check if expired (value is less than now)
                            if ($ExpireTime -lt $NowFileTime) {
                                $FilteredObjects += $Obj
                            }
                        } catch {
                            Write-Log "[Get-DomainObject] Error parsing accountExpires for '$($Obj.distinguishedName)': $_"
                        }
                    }
                }

                $Objects = $FilteredObjects
                Write-Log "[Get-DomainObject] After AccountExpired post-filter: $($Objects.Count) object(s)"
            }

            # If ShowOwner is set, add Owner properties from nTSecurityDescriptor.Owner
            if ($ShowOwner) {
                Write-Log "[Get-DomainObject] Adding Owner properties to objects..."

                foreach ($Object in $Objects) {
                    # Owner is now part of the unified nTSecurityDescriptor structure
                    if ($Object.nTSecurityDescriptor -and $Object.nTSecurityDescriptor.Owner) {
                        # Add user-facing properties (Owner and OwnerSID only)
                        $Object | Add-Member -NotePropertyName 'Owner' -NotePropertyValue $Object.nTSecurityDescriptor.Owner.Name -Force
                        $Object | Add-Member -NotePropertyName 'OwnerSID' -NotePropertyValue $Object.nTSecurityDescriptor.Owner.SID -Force

                        Write-Log "[Get-DomainObject] Owner for '$($Object.distinguishedName)': $($Object.nTSecurityDescriptor.Owner.Name)"
                    } else {
                        Write-Log "[Get-DomainObject] No owner info in nTSecurityDescriptor for '$($Object.distinguishedName)'"
                    }
                }
            }

            return $Objects

        } catch {
            Write-Log "[Get-DomainObject] Error: $_"
            throw
        }
    }

    end {
        Write-Log "[Get-DomainObject] Object enumeration completed"
    }
}
