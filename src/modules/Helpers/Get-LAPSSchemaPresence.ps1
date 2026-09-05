<#
.SYNOPSIS
    Reports which LAPS schema extensions the domain carries, Legacy and Windows LAPS.

.DESCRIPTION
    Three checks need this answer before they do anything else - Get-LAPSConfiguration,
    Get-LAPSCredentialAccess and Get-LAPSPermissions - and each of them used to work it out
    for itself with its own copy of the same two schema queries. The copies had already
    drifted: two passed the caller's connection parameters into the fallback and one did
    not, and all three reached past Get-Domain* into Invoke-LDAPSearch, which check modules
    are not supposed to do. Get-BitLockerRecoveryKeyAccess answers the same kind of
    question through Get-DomainObject -SearchBase, and that is what this does.

    Two ways of asking, in order:

    1. The schema partition, for the attribute that each variant defines. This is the
       reliable one: it answers even in a domain where the schema is extended but nothing
       has been deployed yet.
    2. A single computer object carrying the attribute. The fallback for a session that
       cannot read the schema partition - a value in the directory proves the attribute
       exists whatever the schema query said.

    The result is cached in $Script:LAPSSchemaInfo for the rest of the session, so the
    second and third caller pay nothing. Disconnect-adPEAS clears it.

.PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

.PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

.PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

.PARAMETER Refresh
    Ignore the cached answer and query again.

.OUTPUTS
    Hashtable with LegacyPresent and NativePresent, both [bool].

.EXAMPLE
    $schema = Get-LAPSSchemaPresence @connectionParams
    if (-not $schema.LegacyPresent -and -not $schema.NativePresent) { return }

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function Get-LAPSSchemaPresence {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$Refresh
    )

    process {
        if ($Script:LAPSSchemaInfo -and -not $Refresh) {
            Write-Log "[Get-LAPSSchemaPresence] Using cached schema info: Legacy=$($Script:LAPSSchemaInfo.LegacyPresent), Native=$($Script:LAPSSchemaInfo.NativePresent)"
            return $Script:LAPSSchemaInfo
        }

        # Only the connection parameters travel on; -Refresh is ours.
        $connectionParams = @{}
        if ($PSBoundParameters.ContainsKey('Domain'))     { $connectionParams['Domain'] = $Domain }
        if ($PSBoundParameters.ContainsKey('Server'))     { $connectionParams['Server'] = $Server }
        if ($PSBoundParameters.ContainsKey('Credential')) { $connectionParams['Credential'] = $Credential }

        $legacyPresent = $false
        $nativePresent = $false

        # Each variant is recognised by the expiration attribute rather than by the password
        # attribute: the password is ACL-gated and a reader without rights sees nothing,
        # while the expiration time is readable to any authenticated user. Asking about the
        # password would answer "no LAPS here" for a domain that runs it everywhere.
        $schemaDN = $Script:LDAPContext.SchemaNamingContext
        if ($schemaDN) {
            try {
                $legacyFilter = "(&(objectClass=attributeSchema)(|(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)(cn=ms-Mcs-AdmPwdExpirationTime)))"
                if (@(Get-DomainObject -LDAPFilter $legacyFilter -SearchBase $schemaDN -Properties 'cn' -ResultLimit 1 @connectionParams).Count -gt 0) {
                    $legacyPresent = $true
                    Write-Log "[Get-LAPSSchemaPresence] Legacy LAPS schema attribute found"
                }

                $nativeFilter = "(&(objectClass=attributeSchema)(|(lDAPDisplayName=msLAPS-PasswordExpirationTime)(cn=msLAPS-PasswordExpirationTime)))"
                if (@(Get-DomainObject -LDAPFilter $nativeFilter -SearchBase $schemaDN -Properties 'cn' -ResultLimit 1 @connectionParams).Count -gt 0) {
                    $nativePresent = $true
                    Write-Log "[Get-LAPSSchemaPresence] Windows LAPS schema attribute found"
                }
            } catch {
                Write-Log "[Get-LAPSSchemaPresence] Schema query error: $($_.Exception.Message)"
            }
        }

        # Fallback: a deployed value proves the attribute exists.
        if (-not $legacyPresent -and -not $nativePresent) {
            Write-Log "[Get-LAPSSchemaPresence] Schema partition gave no answer, probing computer objects"
            try {
                if (@(Get-DomainComputer -LDAPFilter "(ms-Mcs-AdmPwdExpirationTime=*)" -Properties 'distinguishedName' -ResultLimit 1 @connectionParams).Count -gt 0) {
                    $legacyPresent = $true
                    Write-Log "[Get-LAPSSchemaPresence] Legacy LAPS detected on a computer object"
                }
                if (@(Get-DomainComputer -LDAPFilter "(msLAPS-PasswordExpirationTime=*)" -Properties 'distinguishedName' -ResultLimit 1 @connectionParams).Count -gt 0) {
                    $nativePresent = $true
                    Write-Log "[Get-LAPSSchemaPresence] Windows LAPS detected on a computer object"
                }
            } catch {
                Write-Log "[Get-LAPSSchemaPresence] Computer probe error: $($_.Exception.Message)"
            }
        }

        $Script:LAPSSchemaInfo = @{
            LegacyPresent = $legacyPresent
            NativePresent = $nativePresent
        }
        return $Script:LAPSSchemaInfo
    }
}
