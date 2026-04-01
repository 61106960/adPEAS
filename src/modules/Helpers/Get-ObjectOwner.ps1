<#
.SYNOPSIS
    Retrieves the owner of an AD object's security descriptor.

.DESCRIPTION
    Queries the nTSecurityDescriptor of an AD object to extract the owner SID and determines if it's a non-default owner.

    Default Owners (expected for User/Computer objects):
    - Domain Admins (-512)
    - Enterprise Admins (-519)
    - BUILTIN\Administrators (S-1-5-32-544)
    - NT AUTHORITY\SYSTEM (S-1-5-18)

.PARAMETER DistinguishedName
    The distinguishedName of the AD object to check.

.PARAMETER ADObject
    An AD object (from Get-DomainUser, Get-DomainComputer, etc.) with distinguishedName property.

.PARAMETER NonDefaultOnly
    Only return results for objects with non-default owners.
    If the owner is a default owner (Domain Admins, Enterprise Admins, etc.), returns $null.
    Useful for filtering to find security-relevant owner configurations.

.EXAMPLE
    Get-ObjectOwner -DistinguishedName "CN=JohnDoe,OU=Users,DC=contoso,DC=com"

.EXAMPLE
    $user | Get-ObjectOwner

.EXAMPLE
    Get-DomainComputer -Identity "WORKSTATION01" | Get-ObjectOwner

.EXAMPLE
    Get-DomainComputer | Get-ObjectOwner -NonDefaultOnly
    Returns only computers with non-default owners (potential security findings).

.OUTPUTS
    PSCustomObject with:
    - OwnerSID: The SID of the owner
    - OwnerName: Resolved name of the owner
    - IsDefaultOwner: $true if owner is Domain Admins/Enterprise Admins/Administrators/SYSTEM
    - DistinguishedName: The DN that was queried

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

# Default owner SIDs - accounts expected to own AD objects
$Script:DefaultOwnerRIDSuffixes = @(
    '-512',   # Domain Admins
    '-519'    # Enterprise Admins
)

$Script:DefaultOwnerStaticSIDs = @(
    'S-1-5-32-544',  # BUILTIN\Administrators
    'S-1-5-18'       # NT AUTHORITY\SYSTEM
)

function Get-ObjectOwner {
    [CmdletBinding(DefaultParameterSetName='ByDN')]
    param(
        [Parameter(Mandatory=$true, ParameterSetName='ByDN', Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$DistinguishedName,

        [Parameter(Mandatory=$true, ParameterSetName='ByObject', ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [object]$ADObject,

        [Parameter(Mandatory=$false)]
        [switch]$NonDefaultOnly
    )

    process {
        # Get DN from parameter or object
        $targetDN = if ($PSCmdlet.ParameterSetName -eq 'ByObject') {
            if ($ADObject.distinguishedName) {
                $ADObject.distinguishedName
            } else {
                Write-Log "[Get-ObjectOwner] ADObject has no distinguishedName property"
                return $null
            }
        } else {
            $DistinguishedName
        }

        # Internal helper - caller must ensure LDAP connection exists
        # UNIFIED: Check for LdapConnection (works for both LDAP and LDAPS)
        if (-not $Script:LdapConnection) {
            Write-Log "[Get-ObjectOwner] No LDAP connection - returning null"
            return $null
        }

        Write-Log "[Get-ObjectOwner] Querying owner for: $targetDN"

        try {
            # Use Invoke-LDAPSearch with Base scope to query the specific object, this ensures we use the central LDAP access mechanism
            $result = Invoke-LDAPSearch -Filter "(objectClass=*)" -SearchBase $targetDN -Scope Base -Properties @("nTSecurityDescriptor")

            if (-not $result) {
                Write-Log "[Get-ObjectOwner] Object not found: $targetDN"
                return $null
            }

            # Get first result (Base scope returns single object)
            $objectResult = if ($result -is [array]) { $result[0] } else { $result }

            # nTSecurityDescriptor is now a unified object with Owner property
            # Owner has: SID, Name, DisplayText
            if (-not $objectResult.nTSecurityDescriptor -or -not $objectResult.nTSecurityDescriptor.Owner) {
                Write-Log "[Get-ObjectOwner] Could not retrieve owner information from nTSecurityDescriptor"
                return $null
            }

            $ownerSID = $objectResult.nTSecurityDescriptor.Owner.SID
            $ownerName = $objectResult.nTSecurityDescriptor.Owner.Name

            Write-Log "[Get-ObjectOwner] Owner SID: $ownerSID"

            # Determine if this is a default owner using Test-IsDefaultOwner
            $isDefault = Test-IsDefaultOwner -SID $ownerSID

            Write-Log "[Get-ObjectOwner] Owner: $ownerName (IsDefault: $isDefault)"

            # If NonDefaultOnly is set and this is a default owner, return nothing
            if ($NonDefaultOnly -and $isDefault) {
                Write-Log "[Get-ObjectOwner] Skipping default owner (NonDefaultOnly filter)"
                return $null
            }

            # Return result object
            return [PSCustomObject]@{
                OwnerSID          = $ownerSID
                OwnerName         = $ownerName
                IsDefaultOwner    = $isDefault
                DistinguishedName = $targetDN
            }

        } catch {
            Write-Log "[Get-ObjectOwner] Error querying owner: $_"
            return $null
        }
    }
}

<#
.SYNOPSIS
    Tests if a SID is a default/expected owner for AD objects.

.DESCRIPTION
    Checks if the given SID is one of the expected default owners:
    - Domain Admins (-512)
    - Enterprise Admins (-519)
    - BUILTIN\Administrators (S-1-5-32-544)
    - NT AUTHORITY\SYSTEM (S-1-5-18)

.PARAMETER SID
    The SID to check.

.PARAMETER DomainSID
    The domain SID (optional - uses $Script:LDAPContext.DomainSID if not provided).

.EXAMPLE
    Test-IsDefaultOwner -SID "S-1-5-21-123456789-123456789-123456789-512"
    Returns: $true (Domain Admins)

.EXAMPLE
    Test-IsDefaultOwner -SID "S-1-5-21-123456789-123456789-123456789-1234"
    Returns: $false (regular user)

.OUTPUTS
    Boolean - $true if default owner, $false otherwise
#>
function Test-IsDefaultOwner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SID,

        [Parameter(Mandatory=$false)]
        [string]$DomainSID  # Kept for backward compatibility, no longer used
    )

    # Check static SIDs first
    if ($Script:DefaultOwnerStaticSIDs -contains $SID) {
        return $true
    }

    # Check domain-relative RID suffixes
    # Use pattern matching (S-1-5-21-*-512) to support multi-domain environments
    # where the owner may be Domain Admins/Enterprise Admins from ANY domain
    # (e.g. child domain objects owned by child domain's DA)
    foreach ($ridSuffix in $Script:DefaultOwnerRIDSuffixes) {
        if ($SID -like "S-1-5-21-*$ridSuffix") {
            return $true
        }
    }

    return $false
}
