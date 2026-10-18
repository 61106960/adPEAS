function Get-CurrentUserTokenGroups {
    <#
    .SYNOPSIS
    Returns the SIDs in the token of the current LDAP session.

    .DESCRIPTION
    Reads the tokenGroups attribute of the rootDSE, which returns "the SIDs contained in
    the security context as which the client has authenticated the LDAP connection"
    (MS-ADTS 3.1.1.3.2.41): the account's own SID, its groups with nesting resolved, and
    the well-known groups of the logon such as Authenticated Users.

    This is what checks whether the current user can decrypt an encrypted LAPS password:
    the blob names the one principal allowed to, a group or an account.

    The function caches results in $Script:CurrentUserTokenGroups for performance.

    .PARAMETER Force
    Force refresh of cached token groups.

    .EXAMPLE
    $groups = Get-CurrentUserTokenGroups
    if ($groups -contains 'S-1-5-21-...-512') {
        # User is in Domain Admins
    }

    .NOTES
    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )

    # Return cached result if available and not forcing refresh
    if (-not $Force -and $Script:CurrentUserTokenGroups) {
        Write-Log "[Get-CurrentUserTokenGroups] Returning cached token groups ($($Script:CurrentUserTokenGroups.Count) SIDs)"
        return ,$Script:CurrentUserTokenGroups
    }

    # Need active LDAP connection
    # UNIFIED: Check for LdapConnection (works for both LDAP and LDAPS)
    if (-not $Script:LdapConnection -or -not $Script:LDAPContext) {
        Write-Log "[Get-CurrentUserTokenGroups] No active LDAP connection"
        return ,@()
    }

    try {
        Write-Log "[Get-CurrentUserTokenGroups] Reading the token of the LDAP session off the rootDSE..."

        # The rootDSE, not an object. tokenGroups read off the account's own object - the
        # way this worked before - never produced a SID: Invoke-LDAPSearch did not know the
        # attribute as binary, so a SID that happened to decode as UTF-8 arrived as a string
        # and every other one as loose bytes. Measured in a lab domain: three SIDs, one string
        # and 56 bytes, nothing parsed. It needed the account's DN as well, which no
        # Kerberos session had, and the attribute of an object leaves out the object's own
        # SID - which the decryptor of a LAPS password can be.
        #
        # What hung off it: the encrypted-LAPS authorization gate, which compares these
        # SIDs against the decryptor named in each blob. Without them it falls back to
        # sampling three computers.
        $sidValues = @(Read-RootDSETokenGroups -Connection $Script:LdapConnection)

        $TokenGroupSIDs = @()
        foreach ($sidBytes in $sidValues) {
            try {
                $sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
                $TokenGroupSIDs += $sid.Value
            } catch {
                Write-Log "[Get-CurrentUserTokenGroups] Failed to parse SID bytes: $_"
            }
        }
        Write-Log "[Get-CurrentUserTokenGroups] Found $($TokenGroupSIDs.Count) SIDs in the session token"

        # Cache the result
        $Script:CurrentUserTokenGroups = $TokenGroupSIDs

        return ,$TokenGroupSIDs

    } catch {
        Write-Log "[Get-CurrentUserTokenGroups] Error: $_"
        return ,@()
    }
}


function Read-RootDSETokenGroups {
    <#
    .SYNOPSIS
    Reads the tokenGroups values of the rootDSE, one byte array per SID.

    .DESCRIPTION
    Through the connection itself: Invoke-LDAPSearch puts the domain DN in place of an
    empty search base, so it cannot read the rootDSE. GetValues([byte[]]) rather than the
    indexer, which on a search result returns a string for a SID whose bytes happen to
    decode as UTF-8 - BUILTIN\Users is one.

    .PARAMETER Connection
    The bound System.DirectoryServices.Protocols.LdapConnection.

    .OUTPUTS
    byte[], one per SID; nothing when the rootDSE carries no tokenGroups.

    .NOTES
    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Connection
    )

    $request = New-Object System.DirectoryServices.Protocols.SearchRequest(
        '', '(objectClass=*)', [System.DirectoryServices.Protocols.SearchScope]::Base, [string[]]@('tokenGroups'))
    $response = $Connection.SendRequest($request)
    if (-not $response -or @($response.Entries).Count -eq 0) { return }

    $attribute = @($response.Entries)[0].Attributes.get_Item('tokengroups')
    if (-not $attribute) { return }

    # One byte[] per pipeline object - the comma keeps the pipeline from unrolling it.
    foreach ($value in $attribute.GetValues([byte[]])) { ,$value }
}

function Test-SIDInTokenGroups {
    <#
    .SYNOPSIS
    Tests if a given SID is in the current user's token groups.

    .DESCRIPTION
    Checks if the specified SID (typically a LAPS Target SID) is in the
    current user's group memberships. This is a fast local check that
    can be used to determine if the user can decrypt an encrypted LAPS password.

    .PARAMETER SID
    The SID to check for membership.

    .EXAMPLE
    if (Test-SIDInTokenGroups -SID 'S-1-5-21-1234-5678-9012-512') {
        # User is authorized for this Target SID
    }

    .NOTES
    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SID
    )

    $tokenGroups = Get-CurrentUserTokenGroups

    if (-not $tokenGroups -or $tokenGroups.Count -eq 0) {
        return $false
    }

    return ($tokenGroups -contains $SID)
}
