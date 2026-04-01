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
    are guaranteed to be SIDs — no Windows name resolution is needed.

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
        [Parameter(Mandatory=$true)]
        $SecurityDescriptorBytes
    )

    # Handle already-parsed ActiveDirectorySecurity objects
    if ($SecurityDescriptorBytes -is [System.DirectoryServices.ActiveDirectorySecurity]) {
        $SD = $SecurityDescriptorBytes
    }
    else {
        # Unwrap array wrapper: Invoke-LDAPSearch sometimes returns arrays of objects
        # BUT: byte[] is also a System.Array, so check for byte[] first before unwrapping
        $sdBytes = $SecurityDescriptorBytes
        if ($sdBytes -is [System.Array] -and -not ($sdBytes -is [byte[]])) {
            $sdBytes = $sdBytes[0]
        }

        if (-not ($sdBytes -is [byte[]])) {
            Write-Log "[ConvertTo-AccessRules] Unexpected type: $($sdBytes.GetType().FullName)"
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
