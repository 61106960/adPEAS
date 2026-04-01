<#
.SYNOPSIS
    Gets an authenticated DirectoryEntry object for LDAP operations.

.DESCRIPTION
    Get-AuthenticatedDirectoryEntry is a helper function that returns a DirectoryEntry object
    with proper authentication handling. It centralizes the credential logic used across all
    New-Domain*, Set-Domain*, and other modules that need direct LDAP access.

    The function handles three authentication scenarios:
    1. Explicit Credential parameter provided
    2. Script-level LDAPCredential from established session
    3. Current user context (no credentials)

    Path construction uses $Script:LDAPContext to build the correct LDAP path.
    For LDAPS sessions, the path uses LDAP://server:636/DN with SecureSocketsLayer
    authentication type, since DirectoryEntry does not support the LDAPS:// scheme.

    This function uses $Credential.UserName (with domain prefix) instead of
    $NetworkCred.UserName which strips the domain prefix and causes authentication failures.

.PARAMETER DistinguishedName
    The distinguishedName of the AD object (e.g., "CN=Users,DC=contoso,DC=com").
    The function automatically constructs the full LDAP path using $Script:LDAPContext.

.PARAMETER Credential
    Optional PSCredential object for authentication. If not provided, uses
    $Script:LDAPCredential from an established session, or falls back to current user context.

.EXAMPLE
    $entry = Get-AuthenticatedDirectoryEntry -DistinguishedName "CN=Users,DC=contoso,DC=com"
    Gets a DirectoryEntry using session context (Server/Port) and credentials.

.EXAMPLE
    $entry = Get-AuthenticatedDirectoryEntry -DistinguishedName $dn -Credential (Get-Credential)
    Gets a DirectoryEntry with explicit credentials.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function Get-AuthenticatedDirectoryEntry {
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectoryEntry])]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$DistinguishedName,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    process {
        try {
            # Ensure we have a valid LDAP context
            if (-not $Script:LDAPContext) {
                Write-Error "[Get-AuthenticatedDirectoryEntry] No LDAP context available. Use Connect-adPEAS first."
                return $null
            }

            $server = $Script:LDAPContext.Server
            $useLDAPS = $Script:LDAPContext.UseLDAPS
            $port = $Script:LDAPContext.Port

            # DirectoryEntry only supports LDAP:// scheme (not LDAPS://)
            # For SSL, use LDAP://server:636/DN with AuthenticationTypes.SecureSocketsLayer
            if ($server) {
                if ($useLDAPS) {
                    $Path = "LDAP://${server}:${port}/$DistinguishedName"
                } else {
                    $Path = "LDAP://$server/$DistinguishedName"
                }
            } else {
                $Path = "LDAP://$DistinguishedName"
            }

            Write-Log "[Get-AuthenticatedDirectoryEntry] Path: $Path (SSL: $useLDAPS)"

            # Determine authentication types
            # SecureSocketsLayer = SSL/TLS, Secure = Negotiate (Kerberos/NTLM)
            $authTypes = [System.DirectoryServices.AuthenticationTypes]::Secure
            if ($useLDAPS) {
                $authTypes = $authTypes -bor [System.DirectoryServices.AuthenticationTypes]::SecureSocketsLayer
            }

            # Resolve credentials: explicit > session > current user
            $cred = if ($Credential) { $Credential } elseif ($Script:LDAPCredential) { $Script:LDAPCredential } else { $null }

            if ($cred) {
                # Use $cred.UserName (with domain prefix) NOT GetNetworkCredential().UserName (strips domain)
                $NetworkCred = $cred.GetNetworkCredential()
                $Entry = New-Object System.DirectoryServices.DirectoryEntry(
                    $Path,
                    $cred.UserName,
                    $NetworkCred.Password,
                    $authTypes
                )
            }
            else {
                # Current user context
                $Entry = New-Object System.DirectoryServices.DirectoryEntry($Path, $null, $null, $authTypes)
            }

            return $Entry
        }
        catch {
            Write-Error "[Get-AuthenticatedDirectoryEntry] Failed to get DirectoryEntry for '$DistinguishedName': $_"
            return $null
        }
    }
}
