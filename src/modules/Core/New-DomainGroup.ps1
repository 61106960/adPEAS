function New-DomainGroup {
<#
.SYNOPSIS
    Creates a new group object in Active Directory.

.DESCRIPTION
    New-DomainGroup creates a new security or distribution group in Active Directory via LDAP AddRequest.
    This function is designed for offensive security operations where native AD tools may not be available or stealthy operation is required.

    Groups can be created as:
    - Security groups (default) - Used for permissions and access control
    - Distribution groups - Used for email distribution lists

    Group scopes:
    - Global (default) - Can contain members from same domain
    - Universal - Can contain members from any domain in forest
    - DomainLocal - Can contain members from any domain, but only used in local domain

.PARAMETER Name
    sAMAccountName for the new group.

.PARAMETER OrganizationalUnit
    DistinguishedName of the OU where the group should be created.
    Default: CN=Users,DC=domain,DC=com

.PARAMETER Description
    Description attribute for the group.

.PARAMETER GroupScope
    Group scope: Global, Universal, or DomainLocal. Default: Global

.PARAMETER GroupType
    Group type: Security or Distribution. Default: Security

.PARAMETER Domain
    Target domain (FQDN).

.PARAMETER Server
    Specific Domain Controller to target.

.PARAMETER Credential
    PSCredential object for authentication.

.EXAMPLE
    New-DomainGroup -Name "Backup Operators Local"
    Creates a new global security group in the default Users container.

.EXAMPLE
    New-DomainGroup -Name "IT-Admins" -GroupScope Universal -OrganizationalUnit "OU=Groups,DC=contoso,DC=com" -Description "IT Administration Team"
    Creates a universal security group in a specific OU with description.

.EXAMPLE
    New-DomainGroup -Name "EmailList" -GroupType Distribution -GroupScope Universal
    Creates a universal distribution group for email lists.

.EXAMPLE
    New-DomainGroup -Name "LocalAdmins" -GroupScope DomainLocal -Domain "contoso.com" -Credential (Get-Credential)
    Creates a domain-local security group in a remote domain using alternative credentials.

.EXAMPLE
    $result = New-DomainGroup -Name "TestGroup" -PassThru
    Creates a group and returns the result object for programmatic use.

.PARAMETER PassThru
    Returns a result object instead of only console output.
    Useful for scripting and automation.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true)]
        [Alias('GroupName')]
        [string]$Name,

        [Parameter(Mandatory=$false)]
        [string]$OrganizationalUnit,

        [Parameter(Mandatory=$false)]
        [string]$Description,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Global', 'Universal', 'DomainLocal')]
        [string]$GroupScope = 'Global',

        [Parameter(Mandatory=$false)]
        [ValidateSet('Security', 'Distribution')]
        [string]$GroupType = 'Security',

        # Connection parameters
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$PassThru
    )

    begin {
        Write-Log "[New-DomainGroup] Starting group creation"
    }

    process {
        # Ensure LDAP connection at start of process block
        $ConnectionParams = @{}
        if ($Domain) { $ConnectionParams['Domain'] = $Domain }
        if ($Server) { $ConnectionParams['Server'] = $Server }
        if ($Credential) { $ConnectionParams['Credential'] = $Credential }

        if (-not (Ensure-LDAPConnection @ConnectionParams)) {
            if ($PassThru) {
                return [PSCustomObject]@{
                    Operation = "CreateGroup"
                    Group = $Name
                    Success = $false
                    Message = "No LDAP connection available"
                }
            }
            return
        }

        try {
            Write-Log "[New-DomainGroup] Creating new group: $Name"

            # Determine target OU
            if ($OrganizationalUnit) {
                $TargetOU = $OrganizationalUnit
            } else {
                # Use default Users container
                $TargetOU = "CN=Users,$($Script:LDAPContext.DomainDN)"
            }

            Write-Log "[New-DomainGroup] Target OU: $TargetOU"

            # Calculate groupType flag
            $GroupTypeFlag = 0

            # Set scope
            switch ($GroupScope) {
                'Global'      { $GroupTypeFlag = 0x00000002 }
                'DomainLocal' { $GroupTypeFlag = 0x00000004 }
                'Universal'   { $GroupTypeFlag = 0x00000008 }
            }

            # Add Security flag if Security group
            if ($GroupType -eq 'Security') {
                $GroupTypeFlag = $GroupTypeFlag -bor 0x80000000
            }

            Write-Log "[New-DomainGroup] Group type flag: 0x$($GroupTypeFlag.ToString('X8')) ($GroupType, $GroupScope)"

            # Create group via AddRequest (uses $Script:LdapConnection - works with all auth methods)
            $GroupDN = "CN=$Name,$TargetOU"

            $AddRequest = New-Object System.DirectoryServices.Protocols.AddRequest
            $AddRequest.DistinguishedName = $GroupDN

            $AddRequest.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("objectClass", "group"))) | Out-Null
            $AddRequest.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("sAMAccountName", $Name))) | Out-Null
            $AddRequest.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("groupType", [string]$GroupTypeFlag))) | Out-Null

            if ($Description) {
                $AddRequest.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("description", $Description))) | Out-Null
            }

            $Response = $Script:LdapConnection.SendRequest($AddRequest)
            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                throw "LDAP AddRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
            }

            Write-Log "[New-DomainGroup] Group object created: $GroupDN"

            # Return result object only if -PassThru is specified (no console output)
            if ($PassThru) {
                return [PSCustomObject]@{
                    Operation = "CreateGroup"
                    Group = $Name
                    DistinguishedName = $GroupDN
                    GroupType = $GroupType
                    GroupScope = $GroupScope
                    Success = $true
                    Message = "Group successfully created"
                }
            } else {
                # Console output (default behavior)
                Show-Line "Successfully created group: $Name" -Class Hint
                Show-KeyValue "Distinguished Name:" $GroupDN
                Show-KeyValue "Type:" $GroupType
                Show-KeyValue "Scope:" $GroupScope
            }
        }
        catch {
            Write-Error "[New-DomainGroup] Failed to create group '$Name': $_"
            if ($PassThru) {
                return [PSCustomObject]@{
                    Operation = "CreateGroup"
                    Group = $Name
                    Success = $false
                    Message = $_.Exception.Message
                }
            }
        }
    }
}
