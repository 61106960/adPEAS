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
    Returns the DNs in the member attribute of the group instead of the group: its direct
    members. Requires -Identity; where it matches several groups, the first one.

.PARAMETER Recurse
    With -ShowMembers, which it implies: every member instead - direct ones, the members
    of nested groups at any depth, and the accounts whose primary group is the group or a
    group nested in it, which no member attribute lists. One object per member, with
    Name, ObjectClass, Membership ('Direct', 'Nested' or 'Primary group'), Via (the
    group that holds it), DistinguishedName and SID. Nested groups are listed as members
    too. A member in another domain or forest reached through a foreign security
    principal is listed as that principal, not resolved further.

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
    Returns the DNs of the direct members of Domain Admins.

.EXAMPLE
    Get-DomainGroup -Identity "Domain Admins" -ShowMembers -Recurse
    Returns every member of Domain Admins, nested and by primary group included, each
    with the group that holds it.

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
        [switch]$Recurse,

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
            # -Recurse is a way of showing the members, so it implies -ShowMembers.
            if ($Recurse) { $ShowMembers = $true }

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

            # Pass through other parameters. -Recurse reads the DN, the SID and the members
            # of the group, where a property list would leave them out.
            if ($Properties) {
                $GetParams['Properties'] = $Properties
                if ($Recurse -and $ShowMembers) {
                    $GetParams['Properties'] = @(@($Properties) + @('distinguishedName', 'objectSid', 'member') | Select-Object -Unique)
                }
            }
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
                    if ($Recurse) {
                        $nestingParams = @{}
                        if ($Domain) { $nestingParams['Domain'] = $Domain }
                        if ($Server) { $nestingParams['Server'] = $Server }
                        if ($Credential) { $nestingParams['Credential'] = $Credential }
                        return @(Resolve-GroupMemberNesting -Group $Group -ConnectionParams $nestingParams)
                    }
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
