function Get-DomainUser {
<#
.SYNOPSIS
    Retrieves user objects from Active Directory (wrapper for Get-DomainObject).

.DESCRIPTION
    Get-DomainUser is a convenience wrapper around Get-DomainObject that provides user-specific filters and functionality:

    - Search by Identity (sAMAccountName, DN, SID, DOMAIN\user)
    - Filter by specific criteria (AdminCount, SPN, Delegation, etc.)
    - Flexible property selection
    - Custom LDAP filters
    - gMSA-specific features (ShowGMSADetails)

.PARAMETER Identity
    sAMAccountName, DistinguishedName, SID or DOMAIN\user format.
    Wildcards are supported.

.PARAMETER SPN
    Return only users with Service Principal Names.

.PARAMETER AdminCount
    Return only users with adminCount=1 (privileged accounts).

.PARAMETER Unconstrained
    Users with Unconstrained Delegation (TRUSTED_FOR_DELEGATION flag).

.PARAMETER Constrained
    Users with Constrained Delegation (msDS-AllowedToDelegateTo attribute).
    Includes both regular Constrained Delegation and Protocol Transition variants.

.PARAMETER RBCD
    Users with Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity attribute).
    RBCD allows the target resource to control who can delegate to it.

.PARAMETER TrustedToAuth
    Users with Protocol Transition (TRUSTED_TO_AUTH_FOR_DELEGATION flag).
    This is the more dangerous variant of Constrained Delegation with S4U2Self.

.PARAMETER DisallowDelegation
    Users NOT allowed for delegation (NOT_DELEGATED flag set).

.PARAMETER PreauthNotRequired
    Users with DONT_REQ_PREAUTH flag (AS-REP Roastable).

.PARAMETER PasswordNotRequired
    Users with PASSWD_NOTREQD flag.

.PARAMETER PasswordNeverExpires
    Users with DONT_EXPIRE_PASSWORD flag.

.PARAMETER PasswordMustChange
    Users where pwdLastSet=0 (must change password at next logon).

.PARAMETER Enabled
    Only enabled users (ACCOUNTDISABLE flag not set).

.PARAMETER Disabled
    Only disabled users (ACCOUNTDISABLE flag set).

.PARAMETER LockedOut
    Only locked out users (lockoutTime > 0).

.PARAMETER SmartcardRequired
    Users with SMARTCARD_REQUIRED flag set.

.PARAMETER AccountExpired
    Users where accountExpires is in the past.

.PARAMETER AccountNeverExpires
    Users where accountExpires is 0 or never set.

.PARAMETER DESOnly
    Users with USE_DES_KEY_ONLY flag set (weak encryption).

.PARAMETER ReversibleEncryption
    Users with ENCRYPTED_TEXT_PWD_ALLOWED flag set (security risk).

.PARAMETER GMSA
    Return only Managed Service Accounts (MSA and gMSA).
    Includes both standalone MSA (Server 2008 R2+) and Group MSA (Server 2012+).

.PARAMETER ShowGMSADetails
    Shows extended MSA/gMSA information (password access, rotation, SPNs).
    Must be used together with -GMSA.

.PARAMETER LDAPFilter
    Custom LDAP filter for special queries.

.PARAMETER Properties
    Array of attribute names to return.
    Default: All default properties from Get-DomainObject.

.PARAMETER ShowOwner
    Include Owner and OwnerSID properties on returned objects.

.PARAMETER SearchBase
    Alternative SearchBase (DN). Default: Domain DN.

.PARAMETER Domain
    Target domain (FQDN).

.PARAMETER Server
    Specific Domain Controller to query.

.PARAMETER Credential
    PSCredential object for authentication.

.EXAMPLE
    Get-DomainUser -Identity "Administrator"
    Returns the Administrator account.

.EXAMPLE
    Get-DomainUser -AdminCount
    Returns all users with adminCount=1.

.EXAMPLE
    Get-DomainUser -SPN
    Returns all Kerberoastable users (with SPNs).

.EXAMPLE
    Get-DomainUser -Unconstrained
    Returns all users with Unconstrained Delegation.

.EXAMPLE
    Get-DomainUser -Constrained
    Returns all users with Constrained Delegation.

.EXAMPLE
    Get-DomainUser -TrustedToAuth
    Returns all users with Protocol Transition (S4U2Self).

.EXAMPLE
    Get-DomainUser -RBCD
    Returns all users with Resource-Based Constrained Delegation configured.

.EXAMPLE
    Get-DomainUser -PreauthNotRequired
    Returns all AS-REP Roastable users.

.EXAMPLE
    Get-DomainUser -GMSA
    Returns all Managed Service Accounts (standalone MSA and gMSA).

.EXAMPLE
    Get-DomainUser -GMSA -ShowGMSADetails
    Returns all MSAs/gMSAs with extended details (password access, rotation interval, etc.).

.OUTPUTS
    PSCustomObject with user attributes

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding(DefaultParameterSetName='Default')]
    param(
        [Parameter(Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('samAccountName', 'Name', 'User')]
        [string]$Identity,

        # All filter parameters are combinable (no ParameterSetName restriction)
        [Parameter(Mandatory=$false)]
        [switch]$SPN,

        [Parameter(Mandatory=$false)]
        [switch]$AdminCount,

        [Parameter(Mandatory=$false)]
        [switch]$Unconstrained,

        [Parameter(Mandatory=$false)]
        [switch]$Constrained,

        [Parameter(Mandatory=$false)]
        [switch]$RBCD,

        [Parameter(Mandatory=$false)]
        [switch]$TrustedToAuth,

        [Parameter(Mandatory=$false)]
        [switch]$DisallowDelegation,

        [Parameter(Mandatory=$false)]
        [switch]$PreauthNotRequired,

        [Parameter(Mandatory=$false)]
        [switch]$PasswordNotRequired,

        [Parameter(Mandatory=$false)]
        [switch]$PasswordNeverExpires,

        [Parameter(Mandatory=$false)]
        [switch]$PasswordMustChange,

        [Parameter(Mandatory=$false)]
        [switch]$Enabled,

        [Parameter(Mandatory=$false)]
        [switch]$Disabled,

        [Parameter(Mandatory=$false)]
        [switch]$LockedOut,

        [Parameter(Mandatory=$false)]
        [switch]$SmartcardRequired,

        [Parameter(Mandatory=$false)]
        [switch]$AccountExpired,

        [Parameter(Mandatory=$false)]
        [switch]$AccountNeverExpires,

        [Parameter(Mandatory=$false)]
        [switch]$DESOnly,

        [Parameter(Mandatory=$false)]
        [switch]$ReversibleEncryption,

        [Parameter(ParameterSetName='GMSA')]
        [switch]$GMSA,

        [Parameter(Mandatory=$false)]
        [switch]$ShowGMSADetails,

        [Parameter(Mandatory=$false)]
        [string]$LDAPFilter,

        [Parameter(Mandatory=$false)]
        [string[]]$Properties,

        [Parameter(Mandatory=$false)]
        [switch]$ShowOwner,

        [Parameter(Mandatory=$false)]
        [string]$SearchBase,

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$Raw,

        [Parameter(Mandatory=$false)]
        [int]$ResultLimit = 0
    )

    begin {
        Write-Log "[Get-DomainUser] Starting user enumeration (wrapper for Get-DomainObject)"

        # Info: ShowGMSADetails only works with -GMSA
        if ($ShowGMSADetails -and -not $GMSA) {
            Write-Log "[Get-DomainUser] -ShowGMSADetails was specified without -GMSA, ignoring extended properties"
        }
    }

    process {
        try {
            # Build base filter depending on what we're searching for
            if ($GMSA) {
                # Managed Service Accounts (both standalone MSA and gMSA)
                # - Standalone MSA: objectClass=msDS-ManagedServiceAccount (Server 2008 R2+)
                # - Group MSA (gMSA): objectClass=msDS-GroupManagedServiceAccount (Server 2012+)
                # Note: gMSA inherits from MSA, so we need OR filter to catch both
                $Filter = "(|(objectClass=msDS-ManagedServiceAccount)(objectClass=msDS-GroupManagedServiceAccount))"
            } else {
                # Standard users: only user objects, no computers, no gMSAs
                $Filter = "(&(objectCategory=person)(objectClass=user)(!(objectClass=computer)))"
            }

            if ($Unconstrained) {
                # TRUSTED_FOR_DELEGATION Flag (524288) - keep here as it's user-specific context
                $Filter = "(&$Filter(userAccountControl:1.2.840.113556.1.4.803:=524288))"
            }

            if ($Constrained) {
                # Constrained Delegation: Has msDS-AllowedToDelegateTo attribute
                # This includes both regular Constrained Delegation and Protocol Transition
                $Filter = "(&$Filter(msDS-AllowedToDelegateTo=*))"
            }

            if ($RBCD) {
                # Resource-Based Constrained Delegation: Has msDS-AllowedToActOnBehalfOfOtherIdentity attribute
                # The target resource controls who can delegate to it (stored as Security Descriptor)
                $Filter = "(&$Filter(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"
            }

            # Custom LDAP filter
            if ($LDAPFilter) {
                $Filter = "(&$Filter$LDAPFilter)"
            }

            Write-Log "[Get-DomainUser] Using filter: $Filter"

            # Build parameters for Get-DomainObject
            $GetParams = @{
                LDAPFilter = $Filter
            }

            # Add MSA/gMSA-specific properties if ShowGMSADetails is set (only with -GMSA)
            if ($ShowGMSADetails -and $GMSA) {
                if ($Properties) {
                    # Merge user-specified properties with MSA-specific properties
                    $MSAProperties = @(
                        # Standalone MSA attributes (Server 2008 R2+)
                        'msds-hostserviceaccountbl',
                        'pwdlastset',

                        # gMSA attributes (Server 2012+)
                        'msds-managedpasswordinterval',
                        'msds-groupmsamembership',
                        'msds-managedpasswordid',
                        'msds-managedpasswordpreviousid',
                        'principalsallowedtoretrievemanagedpassword',

                        # Common attributes
                        'serviceprincipalname',
                        'objectclass'
                    )
                    $GetParams['Properties'] = $Properties + $MSAProperties | Select-Object -Unique
                }
                Write-Log "[Get-DomainUser] ShowGMSADetails enabled - MSA/gMSA-specific properties will be included"
            } elseif ($Properties) {
                $GetParams['Properties'] = $Properties
            }

            # Pass through Identity parameter
            if ($Identity) {
                $GetParams['Identity'] = $Identity
            }

            # Pass through other parameters
            if ($ShowOwner) { $GetParams['ShowOwner'] = $true }
            if ($SearchBase) { $GetParams['SearchBase'] = $SearchBase }
            if ($Domain) { $GetParams['Domain'] = $Domain }
            if ($Server) { $GetParams['Server'] = $Server }
            if ($Credential) { $GetParams['Credential'] = $Credential }
            if ($Raw) { $GetParams['Raw'] = $true }

            # Pass through LDAP-optimized account filters to Get-DomainObject
            if ($Enabled) { $GetParams['IsEnabled'] = $true }
            if ($Disabled) { $GetParams['IsDisabled'] = $true }
            if ($PasswordNeverExpires) { $GetParams['PasswordNeverExpires'] = $true }
            if ($PasswordNotRequired) { $GetParams['PasswordNotRequired'] = $true }
            if ($PasswordMustChange) { $GetParams['PasswordMustChange'] = $true }
            if ($SPN) { $GetParams['HasSPN'] = $true }
            if ($AdminCount) { $GetParams['AdminCount'] = $true }
            if ($TrustedToAuth) { $GetParams['TrustedToAuthForDelegation'] = $true }
            if ($DisallowDelegation) { $GetParams['NotDelegated'] = $true }
            if ($PreauthNotRequired) { $GetParams['PreauthNotRequired'] = $true }
            if ($LockedOut) { $GetParams['LockedOut'] = $true }
            if ($SmartcardRequired) { $GetParams['SmartcardRequired'] = $true }
            if ($AccountExpired) { $GetParams['AccountExpired'] = $true }
            if ($AccountNeverExpires) { $GetParams['AccountNeverExpires'] = $true }
            if ($DESOnly) { $GetParams['DESOnly'] = $true }
            if ($ReversibleEncryption) { $GetParams['ReversibleEncryption'] = $true }
            if ($ResultLimit -gt 0) { $GetParams['ResultLimit'] = $ResultLimit }

            $Users = @(Get-DomainObject @GetParams)

            Write-Log "[Get-DomainUser] Found $($Users.Count) user(s)"

            # Post-processing for MSA/gMSA details (parse binary attributes, only with -GMSA)
            if ($ShowGMSADetails -and $GMSA -and $Users.Count -gt 0) {
                Write-Log "[Get-DomainUser] Parsing MSA/gMSA attributes to readable format..."

                foreach ($User in $Users) {
                    # Parse msds-groupmsamembership (Security Descriptor)
                    if ($User.'msds-groupmsamembership') {
                        $AllowedPrincipals = @()
                        try {
                            $SD = New-Object System.DirectoryServices.ActiveDirectorySecurity
                            $SD.SetSecurityDescriptorBinaryForm($User.'msds-groupmsamembership')

                            $DACL = $SD.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

                            foreach ($ACE in $DACL) {
                                if ($ACE.AccessControlType -eq 'Allow') {
                                    $TrusteeSID = $ACE.IdentityReference.Value

                                    # Resolve SID to name using LDAP-based ConvertFrom-SID
                                    $PrincipalName = ConvertFrom-SID -SID $TrusteeSID
                                    if (-not $PrincipalName) {
                                        $PrincipalName = $TrusteeSID
                                    }

                                    # Store as structured object with SID for classification
                                    $AllowedPrincipals += [PSCustomObject]@{
                                        Name = $PrincipalName
                                        SID = $TrusteeSID
                                        DisplayText = $PrincipalName
                                    }
                                    Write-Log "[Get-DomainUser] gMSA '$($User.sAMAccountName)' allows password retrieval by: $PrincipalName"
                                }
                            }

                            # Replace byte array with structured principal objects (includes SID for classification)
                            $User.'msds-groupmsamembership' = $AllowedPrincipals
                        } catch {
                            Write-Log "[Get-DomainUser] Error parsing msds-groupmsamembership: $_"
                        }
                    }

                    # Parse msDS-ManagedPasswordId
                    if ($User.'msds-managedpasswordid') {
                        try {
                            $PasswordIdBytes = $User.'msds-managedpasswordid'
                            if ($PasswordIdBytes.Length -ge 16) {
                                $GuidBytes = [byte[]]::new(16)
                                [Array]::Copy($PasswordIdBytes, 0, $GuidBytes, 0, 16)
                                $KeyGUID = [GUID]::new($GuidBytes)

                                $TimeString = ""
                                if ($PasswordIdBytes.Length -ge 24) {
                                    $FileTimeBytes = [byte[]]::new(8)
                                    [Array]::Copy($PasswordIdBytes, 16, $FileTimeBytes, 0, 8)
                                    $FileTime = [BitConverter]::ToInt64($FileTimeBytes, 0)

                                    if ($FileTime -ge 119600064000000000 -and $FileTime -lt 2650467743990000000) {
                                        try {
                                            $PasswordCreationTime = [DateTime]::FromFileTime($FileTime)
                                            $TimeString = ", Created: $PasswordCreationTime"
                                        } catch {}
                                    }
                                }

                                $User.'msds-managedpasswordid' = "Key GUID: $($KeyGUID.ToString())$TimeString"
                                Write-Log "[Get-DomainUser] gMSA '$($User.sAMAccountName)' current password key: $($KeyGUID.ToString())"
                            }
                        } catch {
                            Write-Log "[Get-DomainUser] Error parsing msds-managedpasswordid: $_"
                        }
                    }

                    # Parse msDS-ManagedPasswordPreviousId
                    if ($User.'msds-managedpasswordpreviousid') {
                        try {
                            $PrevPasswordIdBytes = $User.'msds-managedpasswordpreviousid'
                            if ($PrevPasswordIdBytes.Length -ge 16) {
                                $GuidBytes = [byte[]]::new(16)
                                [Array]::Copy($PrevPasswordIdBytes, 0, $GuidBytes, 0, 16)
                                $KeyGUID = [GUID]::new($GuidBytes)

                                $TimeString = ""
                                if ($PrevPasswordIdBytes.Length -ge 24) {
                                    $FileTimeBytes = [byte[]]::new(8)
                                    [Array]::Copy($PrevPasswordIdBytes, 16, $FileTimeBytes, 0, 8)
                                    $FileTime = [BitConverter]::ToInt64($FileTimeBytes, 0)

                                    if ($FileTime -ge 119600064000000000 -and $FileTime -lt 2650467743990000000) {
                                        try {
                                            $PrevPasswordCreationTime = [DateTime]::FromFileTime($FileTime)
                                            $TimeString = ", Created: $PrevPasswordCreationTime"
                                        } catch {}
                                    }
                                }

                                $User.'msds-managedpasswordpreviousid' = "Key GUID: $($KeyGUID.ToString())$TimeString"
                                Write-Log "[Get-DomainUser] gMSA '$($User.sAMAccountName)' previous password key: $($KeyGUID.ToString())"
                            }
                        } catch {
                            Write-Log "[Get-DomainUser] Error parsing msds-managedpasswordpreviousid: $_"
                        }
                    }
                }
            }

            return $Users

        } catch {
            Write-Log "[Get-DomainUser] Error: $_"
            throw
        }
    }

    end {
        Write-Log "[Get-DomainUser] User enumeration completed"
    }
}
