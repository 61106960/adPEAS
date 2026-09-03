<#
.SYNOPSIS
    Converts raw nTSecurityDescriptor bytes to an ActiveDirectorySecurity object with access rules.

.DESCRIPTION
    ConvertTo-AccessRules is a shared helper that eliminates the duplicated pattern of:
    1. Unwrapping array-wrapped nTSecurityDescriptor bytes
    2. Creating an ActiveDirectorySecurity object
    3. Parsing the binary security descriptor
    4. Extracting access rules with SecurityIdentifier as identity type

    This pattern was previously duplicated in Get-ObjectACL, Get-OUPermissions,
    and Get-ACEInheritanceSource.

    By using [SecurityIdentifier] as the identity type, all IdentityReferences
    are guaranteed to be SIDs - no Windows name resolution is needed.

.PARAMETER SecurityDescriptorBytes
    The raw nTSecurityDescriptor value. Can be:
    - byte[] (raw binary SD)
    - Array containing a byte[] element (Invoke-LDAPSearch sometimes wraps in array)
    - ActiveDirectorySecurity object (already parsed, returned as-is)

.EXAMPLE
    $result = @(Invoke-LDAPSearch -Filter "(objectClass=*)" -SearchBase $DN -Scope Base -Properties 'nTSecurityDescriptor' -Raw)[0]
    $sd = ConvertTo-AccessRules -SecurityDescriptorBytes $result.nTSecurityDescriptor
    $sd.AccessRules | Where-Object { $_.AccessControlType -eq 'Allow' }

.OUTPUTS
    PSCustomObject with:
    - SecurityDescriptor: The ActiveDirectorySecurity object
    - AccessRules: AuthorizationRuleCollection from GetAccessRules (identity type: SecurityIdentifier)
    - OwnerSID: String SID of the object owner

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
function ConvertTo-AccessRules {
    [CmdletBinding()]
    param(
        # AllowNull/AllowEmptyCollection so the type test below decides, rather than the
        # parameter binder throwing in front of it. An attribute that came back empty is
        # a normal outcome of an ACL-filtered read, not a caller error.
        [Parameter(Mandatory=$true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        $SecurityDescriptorBytes
    )

    if ($null -eq $SecurityDescriptorBytes) {
        Write-Log "[ConvertTo-AccessRules] No security descriptor supplied"
        return $null
    }

    # Handle already-parsed ActiveDirectorySecurity objects
    if ($SecurityDescriptorBytes -is [System.DirectoryServices.ActiveDirectorySecurity]) {
        $SD = $SecurityDescriptorBytes
    }
    else {
        # Unwrap array wrapper: Invoke-LDAPSearch sometimes returns arrays of objects
        # BUT: byte[] is also a System.Array, so check for byte[] first before unwrapping
        $sdBytes = $SecurityDescriptorBytes
        if ($sdBytes -is [System.Array] -and -not ($sdBytes -is [byte[]])) {
            # An Object[] is one of two things here: the single-element wrapper LDAP
            # returns, or a byte array that lost its type on the way in - a function
            # returning a byte[] with a plain return emits the bytes one at a time and
            # the caller collects them into Object[]. The first element tells them apart,
            # and getting it wrong means silently answering $null for a valid descriptor.
            if ($sdBytes.Length -gt 0 -and $sdBytes[0] -is [byte]) {
                $sdBytes = [byte[]]$sdBytes
            } else {
                $sdBytes = $sdBytes[0]
            }
        }

        if (-not ($sdBytes -is [byte[]])) {
            # GetType() on the unwrapped value only after it is known to be non-null:
            # an empty array unwraps to $null, and reporting the unexpected type then
            # threw out of a function whose contract is to return $null.
            $typeName = if ($null -eq $sdBytes) { '<null>' } else { $sdBytes.GetType().FullName }
            Write-Log "[ConvertTo-AccessRules] Unexpected type: $typeName"
            return $null
        }

        if ($sdBytes.Length -eq 0) {
            Write-Log "[ConvertTo-AccessRules] Security descriptor is empty"
            return $null
        }

        # Parse raw security descriptor bytes into ActiveDirectorySecurity
        $SD = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $SD.SetSecurityDescriptorBinaryForm($sdBytes)
    }

    # Get owner SID
    $OwnerSID = $SD.GetOwner([System.Security.Principal.SecurityIdentifier]).Value

    # Get DACL with SecurityIdentifier as identity type
    # This ensures ALL IdentityReferences are SIDs (no Windows name resolution needed)
    $AccessRules = $SD.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

    return [PSCustomObject]@{
        SecurityDescriptor = $SD
        AccessRules        = $AccessRules
        OwnerSID           = $OwnerSID
    }
}
