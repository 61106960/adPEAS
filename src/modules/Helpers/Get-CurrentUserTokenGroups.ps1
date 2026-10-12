function Get-CurrentUserTokenGroups {
    <#
    .SYNOPSIS
    Returns all SIDs the current authenticated user is a member of.

    .DESCRIPTION
    Queries the tokenGroups attribute for the current LDAP session to get all
    group memberships (including nested groups) of the authenticated user.

    This is useful for checking if the current user can decrypt LAPS encrypted
    passwords, as the Target SID must be in the user's token groups.

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
        Write-Log "[Get-CurrentUserTokenGroups] Querying tokenGroups for current session..."

        # tokenGroups on the bound principal's own object, Base scope.
        #
        # It used to read the domain root, with a comment claiming that returns the groups
        # of the authenticated user. It does not: tokenGroups is a constructed attribute
        # that AD computes for the object being read (MS-ADTS 3.1.1.4.5.19), and the
        # documented way to read your own is a Base-scope search on your own DN. Without a
        # SearchBase, Invoke-LDAPSearch uses the domain DN, so the best case was an empty
        # attribute and the realistic case the domain object's own SID and nothing else.
        #
        # What hung off it: the encrypted-LAPS authorization gate, which compares these
        # SIDs against the decryptor group named in each blob. It never matched, so a
        # domain using encrypted Windows LAPS - the configuration Microsoft recommends -
        # had every computer silently discarded.
        #
        # Note: tokenGroups is a special constructed attribute that returns raw byte arrays
        $principalDN = $null
        if ($Script:LDAPContext.AuthenticatedUserDN) {
            $principalDN = [string]$Script:LDAPContext.AuthenticatedUserDN
        }
        if ([string]::IsNullOrWhiteSpace($principalDN)) {
            # Honest empty rather than a wrong answer: without the principal's DN there is
            # no object to compute the groups for, and the caller treats an empty list as
            # "could not be determined" rather than as "member of nothing".
            Write-Log "[Get-CurrentUserTokenGroups] No DN for the bound principal, cannot read its tokenGroups"
            return ,@()
        }
        # @() wrap required: a Base-scope self-lookup always returns exactly one entry,
        # and Invoke-LDAPSearch's own bare "return $OutputObjects" unrolls a one-element
        # result to that bare entry rather than a one-item array (PSCustomObject has no
        # synthetic .Count, so the check below would silently always see 0). Every other
        # Invoke-LDAPSearch call site in this codebase already wraps the call the same way.
        $TokenResults = @(Invoke-LDAPSearch -Filter "(objectClass=*)" -Properties "tokenGroups" -Scope "Base" -SearchBase $principalDN -Raw)

        $TokenGroupSIDs = @()

        if ($TokenResults -and $TokenResults.Count -gt 0) {
            $TokenResult = $TokenResults[0]
            $tokenGroupsAttr = $TokenResult.tokenGroups

            if ($tokenGroupsAttr) {
                # tokenGroups can be a single SID (one byte[]) or multiple (an array of
                # byte[]). "-is [array]" cannot tell these apart: byte[] IS an array, so
                # it was always true and a lone-group user's single byte[] fell into the
                # "already an array" branch, where the foreach below iterated individual
                # bytes instead of the one SID - "$sidBytes -is [byte[]]" then never
                # matched a lone byte, and the user's only group membership was silently
                # dropped. "-is [byte[]]" is unambiguous: only the single-SID case is
                # itself typed byte[]; wrap it as a one-element list with a leading comma.
                #
                # The comma has to sit inside an "if" used as a STATEMENT, assigned
                # separately in each branch - not "$x = if (...) { ,$y } else { $y }".
                # An "if" captured as an expression value re-enumerates whatever each
                # branch produced the same way a bare "return" does, and silently strips
                # the comma's one-element wrapping right back off (confirmed: the
                # assignment form measurably loses it, the statement form does not).
                if ($tokenGroupsAttr -is [byte[]]) {
                    $tokenGroupsArray = ,$tokenGroupsAttr
                } else {
                    $tokenGroupsArray = $tokenGroupsAttr
                }

                foreach ($sidBytes in $tokenGroupsArray) {
                    try {
                        if ($sidBytes -is [byte[]]) {
                            $sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
                            $TokenGroupSIDs += $sid.Value
                        }
                    } catch {
                        Write-Log "[Get-CurrentUserTokenGroups] Failed to parse SID bytes: $_"
                    }
                }
                Write-Log "[Get-CurrentUserTokenGroups] Found $($TokenGroupSIDs.Count) token groups"
            } else {
                Write-Log "[Get-CurrentUserTokenGroups] tokenGroups attribute not found"
            }
        } else {
            Write-Log "[Get-CurrentUserTokenGroups] tokenGroups query returned no results"
        }

        # Cache the result
        $Script:CurrentUserTokenGroups = $TokenGroupSIDs

        return ,$TokenGroupSIDs

    } catch {
        Write-Log "[Get-CurrentUserTokenGroups] Error: $_"
        return ,@()
    }
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
