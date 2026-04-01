function Get-DomainGroup {
<#
.SYNOPSIS
    Central function for querying group objects from Active Directory.

.DESCRIPTION
    Get-DomainGroup is a flexible helper function that unifies all group queries in adPEAS v2.
    It builds on Invoke-LDAPSearch and provides:

    - Search by Identity (sAMAccountName, DN, SID, DOMAIN\group)
    - Filter by specific criteria (AdminCount, GroupScope, GroupCategory, etc.)
    - Flexible property selection
    - Custom LDAP filters

.PARAMETER Identity
    sAMAccountName, DistinguishedName, SID or DOMAIN\group format.
    Wildcards are supported.

.PARAMETER AdminCount
    Only groups with adminCount=1 (privileged groups).

.PARAMETER GroupScope
    Filter by Group Scope: DomainLocal, Global, Universal.

.PARAMETER GroupCategory
    Filter by Group Category: Security, Distribution.

.PARAMETER LDAPFilter
    Custom LDAP filter for special queries.

.PARAMETER Properties
    Array of attribute names to return.
    Default: All default properties from Invoke-LDAPSearch.

.PARAMETER ShowOwner
    Retrieves and displays the owner of the group object.
    The owner has implicit control over the object.

.PARAMETER ShowMembers
    Resolves and displays all group members with their type and description.
    Members are shown in a formatted list (User, Computer, Group, gMSA, etc.).

.PARAMETER SearchBase
    Alternative SearchBase (DN). Default: Domain DN.

.EXAMPLE
    Get-DomainGroup -Identity "Domain Admins"
    Returns the Domain Admins group.

.EXAMPLE
    Get-DomainGroup -AdminCount
    Returns all privileged groups.

.EXAMPLE
    Get-DomainGroup -GroupScope Global -GroupCategory Security
    Returns all global security groups.

.EXAMPLE
    Get-DomainGroup -LDAPFilter "(description=*admin*)"
    Custom LDAP filter for special searches.

.EXAMPLE
    Get-DomainGroup -Identity "Domain Admins" -ShowMembers
    Shows all members of Domain Admins group with their types.

.OUTPUTS
    PSCustomObject with group attributes

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding(DefaultParameterSetName='Default')]
    param(
        [Parameter(Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('samAccountName', 'Name', 'Group')]
        [string]$Identity,

        [Parameter(Mandatory=$false)]
        [switch]$AdminCount,

        [Parameter(Mandatory=$false)]
        [ValidateSet('DomainLocal','Global','Universal')]
        [string]$GroupScope,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Security','Distribution')]
        [string]$GroupCategory,

        [Parameter(Mandatory=$false)]
        [string]$LDAPFilter,

        [Parameter(Mandatory=$false)]
        [string[]]$Properties,

        [Parameter(Mandatory=$false)]
        [switch]$ShowOwner,

        [Parameter(Mandatory=$false)]
        [switch]$ShowMembers,

        [Parameter(Mandatory=$false)]
        [string]$SearchBase,

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$Raw
    )

    begin {
        Write-Log "[Get-DomainGroup] Starting group enumeration (wrapper for Get-DomainObject)"
    }

    process {
        try {
            # Validation: ShowMembers requires Identity (ignore if not provided)
            if ($ShowMembers -and -not $Identity) {
                Write-Log "[Get-DomainGroup] -ShowMembers requires -Identity parameter - ignoring ShowMembers switch"
                $ShowMembers = $false
            }

            # Base Filter: group objects only
            $Filter = "(objectClass=group)"

            # AdminCount filter
            if ($AdminCount) {
                $Filter = "(&$Filter(adminCount=1))"
            }

            # GroupScope filter
            if ($GroupScope) {
                switch ($GroupScope) {
                    'Global' {
                        $Filter = "(&$Filter(groupType:1.2.840.113556.1.4.803:=2))"
                    }
                    'DomainLocal' {
                        $Filter = "(&$Filter(groupType:1.2.840.113556.1.4.803:=4))"
                    }
                    'Universal' {
                        $Filter = "(&$Filter(groupType:1.2.840.113556.1.4.803:=8))"
                    }
                }
            }

            # GroupCategory filter
            if ($GroupCategory) {
                switch ($GroupCategory) {
                    'Security' {
                        $Filter = "(&$Filter(groupType:1.2.840.113556.1.4.803:=2147483648))"
                    }
                    'Distribution' {
                        $Filter = "(&$Filter(!(groupType:1.2.840.113556.1.4.803:=2147483648)))"
                    }
                }
            }

            # Append custom LDAP filter
            if ($LDAPFilter) {
                $Filter = "(&$Filter$LDAPFilter)"
            }

            Write-Log "[Get-DomainGroup] Using filter: $Filter"

            # Build parameters for Get-DomainObject
            $GetParams = @{
                LDAPFilter = $Filter
            }

            # Pass through Identity parameter
            if ($Identity) {
                $GetParams['Identity'] = $Identity
            }

            # Pass through other parameters
            if ($Properties) { $GetParams['Properties'] = $Properties }
            if ($ShowOwner) { $GetParams['ShowOwner'] = $true }
            if ($SearchBase) { $GetParams['SearchBase'] = $SearchBase }
            if ($Domain) { $GetParams['Domain'] = $Domain }
            if ($Server) { $GetParams['Server'] = $Server }
            if ($Credential) { $GetParams['Credential'] = $Credential }
            if ($Raw) { $GetParams['Raw'] = $true }

            $Groups = @(Get-DomainObject @GetParams)

            Write-Log "[Get-DomainGroup] Found $($Groups.Count) group(s)"

            # If ShowMembers is set, return only member DNs as array
            if ($ShowMembers) {
                foreach ($Group in $Groups) {
                    if ($Group.member) {
                        # Return member DNs directly
                        return $Group.member
                    } else {
                        # No members
                        return @()
                    }
                }
            }

            return $Groups

        } catch {
            Write-Log "[Get-DomainGroup] Error: $_"
            throw
        }
    }

    end {
        Write-Log "[Get-DomainGroup] Group enumeration completed"
    }
}
