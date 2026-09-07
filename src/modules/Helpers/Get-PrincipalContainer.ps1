<#
.SYNOPSIS
    Returns the containers directly under the domain root, alongside its OUs.

.DESCRIPTION
    The permission checks that walk the directory looking for delegated rights asked for
    (objectClass=organizationalUnit) and nothing else. CN=Users and CN=Computers are
    containers, not organizational units, and in a great many domains that is where most
    accounts actually sit - everything nobody deliberately moved. A delegation granting
    password resets or GenericAll over CN=Users was therefore invisible, while the same
    delegation one OU further along was reported.

    This returns those containers: one query, scoped to a single level below the domain
    root, for the container class and for builtinDomain, which is what CN=Builtin is. The
    scope is deliberate. A subtree search would drag in the whole CN=System hierarchy -
    dozens of objects whose delegations are a different subject - and multiply the ACL
    reads that follow by the same factor.

    Everything one level down is included rather than an allow-list of names. CN=Users,
    CN=Computers, CN=Managed Service Accounts, CN=ForeignSecurityPrincipals and CN=Builtin
    hold security principals outright; CN=System and CN=Program Data hold objects whose
    delegation matters as well, and a name list would need maintaining for every container
    a future Windows version adds.

    Note on redirection: redircmp and redirusr point the default location at an
    organizational unit, which the OU query in the caller already covers. The container
    stays where it is and keeps whatever delegation it carries, so both are worth reading.

    The result is cached for the session; Disconnect-adPEAS clears it.

.PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

.PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

.PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

.OUTPUTS
    Object[] - the container objects, each with distinguishedName and name.

.EXAMPLE
    $scope = @(Get-DomainObject -LDAPFilter "(objectClass=organizationalUnit)") +
             @(Get-PrincipalContainer @connectionParams)

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function Get-PrincipalContainer {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    process {
        if ($null -ne $Script:PrincipalContainerCache) {
            Write-Log "[Get-PrincipalContainer] Using cached list of $(@($Script:PrincipalContainerCache).Count) container(s)"
            return $Script:PrincipalContainerCache
        }

        $connectionParams = @{}
        if ($PSBoundParameters.ContainsKey('Domain'))     { $connectionParams['Domain'] = $Domain }
        if ($PSBoundParameters.ContainsKey('Server'))     { $connectionParams['Server'] = $Server }
        if ($PSBoundParameters.ContainsKey('Credential')) { $connectionParams['Credential'] = $Credential }

        $domainDN = $Script:LDAPContext.DomainDN
        if (-not $domainDN) {
            Write-Log "[Get-PrincipalContainer] No domain DN in session - returning nothing"
            return @()
        }

        $containers = @()
        try {
            # builtinDomain alongside container: CN=Builtin is not of the container class,
            # and it holds Administrators, Account Operators and the rest of them.
            $containers = @(Get-DomainObject `
                -LDAPFilter '(|(objectClass=container)(objectClass=builtinDomain))' `
                -SearchBase $domainDN -Scope OneLevel `
                -Properties 'distinguishedName', 'name', 'objectClass' @connectionParams)
        } catch {
            # Not fatal: the caller's OU list is the main scope and losing this one costs
            # coverage rather than the whole check.
            Write-Log "[Get-PrincipalContainer] Container query failed: $($_.Exception.Message)" -Level Warning
            return @()
        }

        Write-Log "[Get-PrincipalContainer] $($containers.Count) container(s) directly under $domainDN"

        # Emit the containers as individual pipeline items, the way Get-DomainObject does.
        # The callers concatenate this onto their OU list as
        #   @(Get-DomainObject ...) + @(Get-PrincipalContainer ...)
        # and @() collects pipeline items without flattening them: a ',$containers' return
        # arrives there as ONE element holding the whole array, so the foreach that follows
        # hands a nested array to the [string]$DistinguishedName parameter of
        # Get-OUPermissions and the check dies with "Cannot process argument
        # transformation". The cached branch above always returned unrolled, so only the
        # first caller in a session was hit.
        $Script:PrincipalContainerCache = $containers
        return $containers
    }
}
