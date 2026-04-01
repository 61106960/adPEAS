function Set-DomainUser {
<#
.SYNOPSIS
    Modifies user objects in Active Directory.

.DESCRIPTION
    Set-DomainUser is a flexible helper function for creating and modifying user objects in AD.
    All operations use ModifyRequest via $Script:LdapConnection. Password operations use
    unicodePwd (ModifyRequest) with DirectoryEntry (ADSI) fallback.
    It supports various operations via parameter sets:
    - Password Reset (unicodePwd ModifyRequest, ADSI fallback)
    - Password Change (unicodePwd Delete+Add, ADSI fallback)
    - Owner modification (requires TakeOwnership permission)
    - ACL modification (requires WriteDacl permission)
    - RBCD configuration (requires WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity)
    - Shadow Credentials (adds/removes Key Credentials for PKINIT authentication)
    - UAC Flag Manipulation (DontReqPreauth, PasswordNotRequired, PasswordNeverExpires, PasswordCantChange,
      ReversibleEncryption, SmartcardRequired, NotDelegated, PasswordExpired - each with Set/Clear)

.PARAMETER Identity
    sAMAccountName, DistinguishedName, SID or DOMAIN\user format (for modifying existing users).

.PARAMETER NewPassword
    New password to set. If used alone, performs password reset.
    If used with -OldPassword, performs password change.

.PARAMETER OldPassword
    Old password (required for password change operation).

.PARAMETER Owner
    New owner for the user object (DOMAIN\user or DN format).

.PARAMETER GrantRights
    Rights to grant to a principal. Values: GenericAll, GenericWrite, ResetPassword, WriteDacl, WriteOwner.

.PARAMETER Principal
    Principal for ACL or RBCD operations.
    With -GrantRights: Principal to grant rights to (required).
    With -ClearRBCD: Specific principal to remove from RBCD (optional, lists entries if not specified).

.PARAMETER AddRBCD
    Computer account to allow delegation FROM (for RBCD on service accounts with SPN).
    This principal will be allowed to impersonate users TO the target service account.
    Sets msDS-AllowedToActOnBehalfOfOtherIdentity on the target.

.PARAMETER ClearRBCD
    Removes RBCD configuration (clears msDS-AllowedToActOnBehalfOfOtherIdentity).
    If multiple principals are configured, use -Principal to remove a specific one.
    Use -Force to remove all principals at once.

.PARAMETER AddShadowCredential
    Adds a Shadow Credential (Key Credential) to the user object for PKINIT authentication.

.PARAMETER ClearShadowCredentials
    Removes all Shadow Credentials from the user object.

.PARAMETER DeviceID
    Device GUID for Shadow Credential operations.
    With -AddShadowCredential: Optional custom Device ID (random GUID if not specified).
    With -ClearShadowCredentials: Specific DeviceID to remove (required if multiple credentials exist).

.PARAMETER NoPassword
    With -AddShadowCredential: Export the PFX certificate without password protection.

.PARAMETER SetSPN
    Add a Service Principal Name to the user account.
    Enables Targeted Kerberoasting - the user can then be Kerberoasted.
    Example: -SetSPN "HTTP/fakeservice.contoso.com"

.PARAMETER ClearSPN
    Remove a specific SPN from the user account.
    Used for cleanup after Targeted Kerberoasting.
    Use -Force to remove ALL SPNs.

.PARAMETER DontReqPreauth
    Set the DONT_REQ_PREAUTH flag on a user account (UAC 0x400000).
    Disables Kerberos pre-authentication, making the account AS-REP roastable.

.PARAMETER ClearDontReqPreauth
    Remove the DONT_REQ_PREAUTH flag from a user account (UAC 0x400000).
    Re-enables Kerberos pre-authentication (cleanup).

.PARAMETER Enable
    Enable a disabled user account (remove ACCOUNTDISABLE flag).

.PARAMETER Disable
    Disable a user account (set ACCOUNTDISABLE flag).

.PARAMETER Unlock
    Unlock a locked-out user account (clear lockoutTime attribute).

.PARAMETER PasswordNotRequired
    Set the PASSWD_NOTREQD flag on a user account (UAC 0x0020).
    Allows the account to have an empty password.

.PARAMETER ClearPasswordNotRequired
    Remove the PASSWD_NOTREQD flag from a user account (UAC 0x0020).
    Requires a password again (cleanup).

.PARAMETER PasswordCantChange
    Set the PASSWD_CANT_CHANGE flag on a user account (UAC 0x0040).
    Prevents the user from changing their own password.

.PARAMETER ClearPasswordCantChange
    Remove the PASSWD_CANT_CHANGE flag from a user account (UAC 0x0040).
    Allows the user to change their password again (cleanup).

.PARAMETER ReversibleEncryption
    Set the ENCRYPTED_TEXT_PWD_ALLOWED flag on a user account (UAC 0x0080).
    Stores the password using reversible encryption.

.PARAMETER ClearReversibleEncryption
    Remove the ENCRYPTED_TEXT_PWD_ALLOWED flag from a user account (UAC 0x0080).
    Disables reversible encryption (cleanup).

.PARAMETER PasswordNeverExpires
    Set the DONT_EXPIRE_PASSWORD flag on a user account (UAC 0x10000).
    Password will never expire regardless of domain policy.

.PARAMETER ClearPasswordNeverExpires
    Remove the DONT_EXPIRE_PASSWORD flag from a user account (UAC 0x10000).
    Password expiry follows domain policy again (cleanup).

.PARAMETER SmartcardRequired
    Set the SMARTCARD_REQUIRED flag on a user account (UAC 0x40000).
    Requires smartcard for interactive logon.

.PARAMETER ClearSmartcardRequired
    Remove the SMARTCARD_REQUIRED flag from a user account (UAC 0x40000).
    No longer requires smartcard for logon (cleanup).

.PARAMETER NotDelegated
    Set the NOT_DELEGATED flag on a user account (UAC 0x100000).
    Prevents the account from being delegated (sensitive account).

.PARAMETER ClearNotDelegated
    Remove the NOT_DELEGATED flag from a user account (UAC 0x100000).
    Allows the account to be delegated again (cleanup).

.PARAMETER PasswordExpired
    Force password expiry on a user account (set pwdLastSet to 0).
    User must change password at next logon.

.PARAMETER ClearPasswordExpired
    Clear the PASSWORD_EXPIRED flag from a user account (UAC 0x800000).
    Removes forced password change requirement (cleanup).

.PARAMETER PassThru
    Returns a result object instead of only console output.
    Useful for scripting and automation.

.PARAMETER Domain
    Target domain.

.PARAMETER Server
    Specific Domain Controller.

.PARAMETER Credential
    PSCredential object for authentication.

.EXAMPLE
    Set-DomainUser -Identity "targetuser" -NewPassword "NewPass123!"
    Resets password (requires Reset-Password permission).

.EXAMPLE
    Set-DomainUser -Identity "targetuser" -OldPassword "OldPass" -NewPassword "NewPass123!"
    Changes password (requires old password).

.EXAMPLE
    Set-DomainUser -Identity "targetuser" -Owner "DOMAIN\attacker"
    Takes ownership of user object.

.EXAMPLE
    Set-DomainUser -Identity "targetuser" -GrantRights GenericAll -Principal "DOMAIN\attacker"
    Grants GenericAll rights to attacker.

.EXAMPLE
    Set-DomainUser -Identity "serviceuser" -AddRBCD "DOMAIN\evilcomputer$"
    Configures RBCD: evilcomputer$ can now impersonate users TO serviceuser.

.EXAMPLE
    Set-DomainUser -Identity "serviceuser" -ClearRBCD
    Removes RBCD configuration from service account (if only one principal configured).

.EXAMPLE
    Set-DomainUser -Identity "serviceuser" -ClearRBCD -Principal "EVILCOMPUTER$"
    Removes specific principal from RBCD configuration.

.EXAMPLE
    Set-DomainUser -Identity "serviceuser" -ClearRBCD -Force
    Removes all principals from RBCD configuration.

.EXAMPLE
    Set-DomainUser -Identity "targetuser" -AddShadowCredential
    Adds a Shadow Credential to the user. Returns certificate for PKINIT authentication.

.EXAMPLE
    Set-DomainUser -Identity "targetuser" -ClearShadowCredentials
    Removes all Shadow Credentials from the user.

.EXAMPLE
    Set-DomainUser -Identity "serviceaccount" -SetSPN "HTTP/fakeservice.contoso.com"
    Adds SPN to enable Targeted Kerberoasting.

.EXAMPLE
    Set-DomainUser -Identity "serviceaccount" -ClearSPN "HTTP/fakeservice.contoso.com"
    Removes specific SPN from account.

.EXAMPLE
    Set-DomainUser -Identity "targetuser" -DontReqPreauth
    Disables Kerberos pre-authentication to enable ASREPRoasting.

.EXAMPLE
    Set-DomainUser -Identity "targetuser" -ClearDontReqPreauth
    Re-enables Kerberos pre-authentication (cleanup).

.EXAMPLE
    Set-DomainUser -Identity "hiddenuser" -Enable
    Enables a disabled user account.

.EXAMPLE
    Set-DomainUser -Identity "targetuser" -Disable
    Disables a user account.

.EXAMPLE
    Set-DomainUser -Identity "lockeduser" -Unlock
    Unlocks a locked-out user account.

.EXAMPLE
    Set-DomainUser -Identity "targetuser" -PasswordNotRequired
    Sets the PASSWD_NOTREQD flag, allowing an empty password.

.EXAMPLE
    Set-DomainUser -Identity "targetuser" -ClearPasswordNotRequired
    Removes the PASSWD_NOTREQD flag (cleanup).

.EXAMPLE
    Set-DomainUser -Identity "targetuser" -PasswordNeverExpires
    Sets the DONT_EXPIRE_PASSWORD flag so the password never expires.

.EXAMPLE
    Set-DomainUser -Identity "targetuser" -ClearPasswordNeverExpires
    Removes the DONT_EXPIRE_PASSWORD flag (cleanup).

.EXAMPLE
    Set-DomainUser -Identity "targetuser" -ReversibleEncryption
    Enables reversible encryption for the account password.

.EXAMPLE
    Set-DomainUser -Identity "targetuser" -ClearReversibleEncryption
    Disables reversible encryption (cleanup).

.EXAMPLE
    Set-DomainUser -Identity "targetuser" -SmartcardRequired
    Forces the account to require a smartcard for interactive logon.

.EXAMPLE
    Set-DomainUser -Identity "targetuser" -ClearSmartcardRequired
    Removes the smartcard requirement (cleanup).

.EXAMPLE
    Set-DomainUser -Identity "targetuser" -NotDelegated
    Marks the account as sensitive and prevents delegation.

.EXAMPLE
    Set-DomainUser -Identity "targetuser" -ClearNotDelegated
    Allows the account to be delegated again (cleanup).

.EXAMPLE
    Set-DomainUser -Identity "targetuser" -PasswordExpired
    Forces the user to change their password at next logon.

.EXAMPLE
    Set-DomainUser -Identity "targetuser" -ClearPasswordExpired
    Removes the forced password change requirement (cleanup).

.OUTPUTS
    PSCustomObject with operation result

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding(DefaultParameterSetName='SetPassword')]
    param(
        # Identity for existing users
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='SetPassword')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ChangePassword')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='SetOwner')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='GrantRights')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='SetRBCD')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ClearRBCD')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='AddShadowCredential')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ClearShadowCredentials')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='SetSPN')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ClearSPN')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='SetDontReqPreauth')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ClearDontReqPreauth')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='EnableAccount')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='DisableAccount')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='UnlockAccount')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='SetPasswordNotRequired')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ClearPasswordNotRequired')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='SetPasswordCantChange')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ClearPasswordCantChange')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='SetReversibleEncryption')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ClearReversibleEncryption')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='SetPasswordNeverExpires')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ClearPasswordNeverExpires')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='SetSmartcardRequired')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ClearSmartcardRequired')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='SetNotDelegated')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ClearNotDelegated')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='SetPasswordExpired')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ClearPasswordExpired')]
        [Alias('samAccountName', 'User')]
        [string]$Identity,

        # Password operations
        [Parameter(ParameterSetName='SetPassword', Mandatory=$true)]
        [Parameter(ParameterSetName='ChangePassword', Mandatory=$true)]
        [string]$NewPassword,

        [Parameter(ParameterSetName='ChangePassword', Mandatory=$true)]
        [string]$OldPassword,

        # Owner modification
        [Parameter(ParameterSetName='SetOwner', Mandatory=$true)]
        [string]$Owner,

        # ACL modification
        [Parameter(ParameterSetName='GrantRights', Mandatory=$true)]
        [ValidateSet('GenericAll','GenericWrite','ResetPassword','WriteDacl','WriteOwner')]
        [string]$GrantRights,

        [Parameter(ParameterSetName='GrantRights', Mandatory=$true)]
        [Parameter(ParameterSetName='ClearRBCD', Mandatory=$false)]
        [string]$Principal,

        # RBCD configuration
        [Parameter(ParameterSetName='SetRBCD', Mandatory=$true)]
        [string]$AddRBCD,

        [Parameter(ParameterSetName='ClearRBCD', Mandatory=$true)]
        [switch]$ClearRBCD,

        # Shadow Credentials
        [Parameter(ParameterSetName='AddShadowCredential', Mandatory=$true)]
        [switch]$AddShadowCredential,

        [Parameter(ParameterSetName='ClearShadowCredentials', Mandatory=$true)]
        [switch]$ClearShadowCredentials,

        [Parameter(ParameterSetName='AddShadowCredential', Mandatory=$false)]
        [Parameter(ParameterSetName='ClearShadowCredentials', Mandatory=$false)]
        [string]$DeviceID,

        [Parameter(ParameterSetName='AddShadowCredential', Mandatory=$false)]
        [switch]$NoPassword,

        [Parameter(ParameterSetName='ClearRBCD', Mandatory=$false)]
        [Parameter(ParameterSetName='ClearShadowCredentials', Mandatory=$false)]
        [Parameter(ParameterSetName='ClearSPN', Mandatory=$false)]
        [switch]$Force,

        # SPN Manipulation (Targeted Kerberoasting)
        [Parameter(ParameterSetName='SetSPN', Mandatory=$true)]
        [string]$SetSPN,

        [Parameter(ParameterSetName='ClearSPN', Mandatory=$true)]
        [string]$ClearSPN,

        # UAC Flag: DONT_REQ_PREAUTH (0x400000)
        [Parameter(ParameterSetName='SetDontReqPreauth', Mandatory=$true)]
        [switch]$DontReqPreauth,

        # UAC Flag: DONT_REQ_PREAUTH - Clear (0x400000)
        [Parameter(ParameterSetName='ClearDontReqPreauth', Mandatory=$true)]
        [switch]$ClearDontReqPreauth,

        # Account State Management
        [Parameter(ParameterSetName='EnableAccount', Mandatory=$true)]
        [switch]$Enable,

        [Parameter(ParameterSetName='DisableAccount', Mandatory=$true)]
        [switch]$Disable,

        [Parameter(ParameterSetName='UnlockAccount', Mandatory=$true)]
        [switch]$Unlock,

        # UAC Flag: PASSWD_NOTREQD (0x0020)
        [Parameter(ParameterSetName='SetPasswordNotRequired', Mandatory=$true)]
        [switch]$PasswordNotRequired,

        [Parameter(ParameterSetName='ClearPasswordNotRequired', Mandatory=$true)]
        [switch]$ClearPasswordNotRequired,

        # UAC Flag: PASSWD_CANT_CHANGE (0x0040)
        [Parameter(ParameterSetName='SetPasswordCantChange', Mandatory=$true)]
        [switch]$PasswordCantChange,

        [Parameter(ParameterSetName='ClearPasswordCantChange', Mandatory=$true)]
        [switch]$ClearPasswordCantChange,

        # UAC Flag: ENCRYPTED_TEXT_PWD_ALLOWED (0x0080)
        [Parameter(ParameterSetName='SetReversibleEncryption', Mandatory=$true)]
        [switch]$ReversibleEncryption,

        [Parameter(ParameterSetName='ClearReversibleEncryption', Mandatory=$true)]
        [switch]$ClearReversibleEncryption,

        # UAC Flag: DONT_EXPIRE_PASSWORD (0x10000)
        [Parameter(ParameterSetName='SetPasswordNeverExpires', Mandatory=$true)]
        [switch]$PasswordNeverExpires,

        [Parameter(ParameterSetName='ClearPasswordNeverExpires', Mandatory=$true)]
        [switch]$ClearPasswordNeverExpires,

        # UAC Flag: SMARTCARD_REQUIRED (0x40000)
        [Parameter(ParameterSetName='SetSmartcardRequired', Mandatory=$true)]
        [switch]$SmartcardRequired,

        [Parameter(ParameterSetName='ClearSmartcardRequired', Mandatory=$true)]
        [switch]$ClearSmartcardRequired,

        # UAC Flag: NOT_DELEGATED (0x100000)
        [Parameter(ParameterSetName='SetNotDelegated', Mandatory=$true)]
        [switch]$NotDelegated,

        [Parameter(ParameterSetName='ClearNotDelegated', Mandatory=$true)]
        [switch]$ClearNotDelegated,

        # UAC Flag: PASSWORD_EXPIRED (0x800000)
        [Parameter(ParameterSetName='SetPasswordExpired', Mandatory=$true)]
        [switch]$PasswordExpired,

        [Parameter(ParameterSetName='ClearPasswordExpired', Mandatory=$true)]
        [switch]$ClearPasswordExpired,

        # Authentication parameters
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [switch]$PassThru,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    begin {
        Write-Log "[Set-DomainUser] Starting user operation: $Identity (ParameterSet: $($PSCmdlet.ParameterSetName))"
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
                    Operation = $PSCmdlet.ParameterSetName
                    User = $Identity
                    Success = $false
                    Message = "No LDAP connection available"
                }
            }
            return
        }

        try {
            # Find the target user
            Write-Log "[Set-DomainUser] Searching for user: $Identity"
            $TargetUser = @(Get-DomainUser -Identity $Identity @ConnectionParams)[0]

            if (-not $TargetUser) {
                throw "User '$Identity' not Found"
            }

            $UserDN = $TargetUser.distinguishedName
            Write-Log "[Set-DomainUser] Found user: $UserDN"

            # Perform operation based on ParameterSet
            $UserEntry = $null
            switch ($PSCmdlet.ParameterSetName) {
                'SetPassword' {
                    Write-Log "[Set-DomainUser] Resetting password for: $($TargetUser.sAMAccountName)"

                    # Try unicodePwd via ModifyRequest (works over LDAPS and Kerberos-encrypted LDAP)
                    $PasswordSet = $false
                    $primaryError = $null
                    try {
                        $quotedPwd = '"' + $NewPassword + '"'
                        $pwdBytes = [System.Text.Encoding]::Unicode.GetBytes($quotedPwd)

                        $PwdModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                        $PwdModifyRequest.DistinguishedName = $UserDN

                        $PwdMod = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                        $PwdMod.Name = "unicodePwd"
                        $PwdMod.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                        $PwdMod.Add($pwdBytes) | Out-Null

                        $PwdModifyRequest.Modifications.Add($PwdMod) | Out-Null

                        $PwdResponse = $Script:LdapConnection.SendRequest($PwdModifyRequest)
                        if ($PwdResponse.ResultCode -eq [System.DirectoryServices.Protocols.ResultCode]::Success) {
                            $PasswordSet = $true
                            Write-Log "[Set-DomainUser] Password reset via unicodePwd ModifyRequest"
                        }
                    }
                    catch {
                        $primaryError = $_.Exception.Message
                        Write-Log "[Set-DomainUser] unicodePwd failed, falling back to DirectoryEntry: $primaryError"
                    }

                    # Fallback: DirectoryEntry SetPassword (ADSI)
                    if (-not $PasswordSet) {
                        # Warn if no credentials available for DirectoryEntry (Hash/Key/Cert auth has no PSCredential)
                        if (-not $Credential -and -not $Script:LDAPCredential) {
                            Write-Warning "[Set-DomainUser] DirectoryEntry fallback uses current Windows user context, not the Kerberos-authenticated session identity. Password operation may fail or use wrong identity."
                        }
                        $UserEntry = Get-AuthenticatedDirectoryEntry -DistinguishedName $UserDN -Credential $Credential
                        if (-not $UserEntry) { throw "Failed to get DirectoryEntry for password reset" }
                        try {
                            $UserEntry.Invoke("SetPassword", $NewPassword)
                            $UserEntry.CommitChanges()
                            $PasswordSet = $true
                            Write-Log "[Set-DomainUser] Password reset via DirectoryEntry SetPassword"
                        }
                        catch {
                            $errorMsg = "Failed to reset password."
                            if ($primaryError) {
                                $errorMsg += " LDAP: $primaryError"
                            }
                            $errorMsg += " ADSI fallback: $_"
                            throw $errorMsg
                        }
                    }

                    if ($PassThru) {
                        return [PSCustomObject]@{
                            Operation = "PasswordReset"
                            User = $TargetUser.sAMAccountName
                            DistinguishedName = $UserDN
                            Success = $true
                            Message = "Password successfully reset"
                        }
                    } else {
                        Show-Line "Successfully reset password for user: $($TargetUser.sAMAccountName)" -Class Hint
                    }
                }

                'ChangePassword' {
                    Write-Log "[Set-DomainUser] Changing password for: $($TargetUser.sAMAccountName)"

                    # Try unicodePwd via ModifyRequest (Delete old + Add new in single request)
                    $PasswordChanged = $false
                    $primaryError = $null
                    try {
                        $quotedOld = '"' + $OldPassword + '"'
                        $quotedNew = '"' + $NewPassword + '"'
                        $oldPwdBytes = [System.Text.Encoding]::Unicode.GetBytes($quotedOld)
                        $newPwdBytes = [System.Text.Encoding]::Unicode.GetBytes($quotedNew)

                        $ChgModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                        $ChgModifyRequest.DistinguishedName = $UserDN

                        # Delete old password
                        $DelMod = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                        $DelMod.Name = "unicodePwd"
                        $DelMod.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete
                        $DelMod.Add($oldPwdBytes) | Out-Null
                        $ChgModifyRequest.Modifications.Add($DelMod) | Out-Null

                        # Add new password
                        $AddMod = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                        $AddMod.Name = "unicodePwd"
                        $AddMod.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Add
                        $AddMod.Add($newPwdBytes) | Out-Null
                        $ChgModifyRequest.Modifications.Add($AddMod) | Out-Null

                        $ChgResponse = $Script:LdapConnection.SendRequest($ChgModifyRequest)
                        if ($ChgResponse.ResultCode -eq [System.DirectoryServices.Protocols.ResultCode]::Success) {
                            $PasswordChanged = $true
                            Write-Log "[Set-DomainUser] Password changed via unicodePwd ModifyRequest"
                        }
                    }
                    catch {
                        $primaryError = $_.Exception.Message
                        Write-Log "[Set-DomainUser] unicodePwd change failed, falling back to DirectoryEntry: $primaryError"
                    }

                    # Fallback: DirectoryEntry ChangePassword (ADSI)
                    if (-not $PasswordChanged) {
                        # Warn if no credentials available for DirectoryEntry (Hash/Key/Cert auth has no PSCredential)
                        if (-not $Credential -and -not $Script:LDAPCredential) {
                            Write-Warning "[Set-DomainUser] DirectoryEntry fallback uses current Windows user context, not the Kerberos-authenticated session identity. Password operation may fail or use wrong identity."
                        }
                        $UserEntry = Get-AuthenticatedDirectoryEntry -DistinguishedName $UserDN -Credential $Credential
                        if (-not $UserEntry) { throw "Failed to get DirectoryEntry for password change" }
                        try {
                            $UserEntry.Invoke("ChangePassword", @($OldPassword, $NewPassword))
                            $UserEntry.CommitChanges()
                            $PasswordChanged = $true
                            Write-Log "[Set-DomainUser] Password changed via DirectoryEntry ChangePassword"
                        }
                        catch {
                            # Show LDAP error from primary attempt (more informative than ADSI error)
                            $errorMsg = "Failed to change password."
                            if ($primaryError) {
                                $errorMsg += " LDAP: $primaryError"
                            }
                            $errorMsg += " ADSI fallback: $_. Verify the old password is correct and the new password meets the domain password policy."
                            throw $errorMsg
                        }
                    }

                    if ($PassThru) {
                        return [PSCustomObject]@{
                            Operation = "PasswordChange"
                            User = $TargetUser.sAMAccountName
                            DistinguishedName = $UserDN
                            Success = $true
                            Message = "Password successfully changed"
                        }
                    } else {
                        Show-Line "Successfully changed password for user: $($TargetUser.sAMAccountName)" -Class Hint
                    }
                }

                'SetOwner' {
                    Write-Log "[Set-DomainUser] Setting owner for: $($TargetUser.sAMAccountName)"

                    try {
                        $Result = Set-DomainObject -Identity $UserDN -SetOwner -Principal $Owner @ConnectionParams

                        if ($Result) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetOwner"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    NewOwner = $Owner
                                    Success = $true
                                    Message = "Owner successfully changed"
                                }
                            } else {
                                Show-Line "Successfully changed owner of $($TargetUser.sAMAccountName) to: $Owner" -Class Hint
                            }
                        } else {
                            throw "Set-DomainObject returned false"
                        }
                    } catch {
                        throw "Failed to set owner: $_"
                    }
                }

                'GrantRights' {
                    Write-Log "[Set-DomainUser] Granting $GrantRights rights to $Principal on: $($TargetUser.sAMAccountName)"

                    try {
                        # Map GrantRights to either Rights or ExtendedRight and call Set-DomainObject
                        $Result = switch ($GrantRights) {
                            'GenericAll'    { Set-DomainObject -Identity $UserDN -GrantACE -Principal $Principal -Rights GenericAll @ConnectionParams }
                            'GenericWrite'  { Set-DomainObject -Identity $UserDN -GrantACE -Principal $Principal -Rights GenericWrite @ConnectionParams }
                            'WriteDacl'     { Set-DomainObject -Identity $UserDN -GrantACE -Principal $Principal -Rights WriteDacl @ConnectionParams }
                            'WriteOwner'    { Set-DomainObject -Identity $UserDN -GrantACE -Principal $Principal -Rights WriteOwner @ConnectionParams }
                            'ResetPassword' { Set-DomainObject -Identity $UserDN -GrantACE -Principal $Principal -ExtendedRight ForceChangePassword @ConnectionParams }
                        }

                        if ($Result) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "GrantRights"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    Principal = $Principal
                                    Rights = $GrantRights
                                    Success = $true
                                    Message = "Rights successfully granted"
                                }
                            } else {
                                Show-Line "Successfully granted $GrantRights to $Principal on: $($TargetUser.sAMAccountName)" -Class Hint
                            }
                        } else {
                            throw "Set-DomainObject returned false"
                        }
                    } catch {
                        throw "Failed to grant rights: $_"
                    }
                }

                'SetRBCD' {
                    $result = Invoke-RBCDOperation -TargetDN $UserDN -TargetSAMAccountName $TargetUser.sAMAccountName -TargetType 'User' -AddRBCD $AddRBCD -PassThru:$PassThru -ConnectionParams $ConnectionParams

                    if ($PassThru -and $result) {
                        return $result
                    }
                }

                'ClearRBCD' {
                    $result = Invoke-RBCDOperation -TargetDN $UserDN -TargetSAMAccountName $TargetUser.sAMAccountName -TargetType 'User' -ClearRBCD -Principal $Principal -Force:$Force -PassThru:$PassThru -ConnectionParams $ConnectionParams

                    if ($PassThru -and $result) {
                        return $result
                    }
                }

                'AddShadowCredential' {
                    # Determine UPN for certificate SAN
                    $UserUPN = if ($TargetUser.userPrincipalName) {
                        $TargetUser.userPrincipalName
                    } else {
                        "$($TargetUser.sAMAccountName)@$($Script:LDAPContext.Domain.ToUpper())"
                    }

                    $result = Invoke-ShadowCredentialOperation -TargetDN $UserDN -TargetSAMAccountName $TargetUser.sAMAccountName -TargetType 'User' -TargetUPN $UserUPN -AddShadowCredential -DeviceID $DeviceID -NoPassword:$NoPassword -PassThru:$PassThru

                    if ($PassThru -and $result) {
                        return $result
                    }
                }

                'ClearShadowCredentials' {
                    $result = Invoke-ShadowCredentialOperation -TargetDN $UserDN -TargetSAMAccountName $TargetUser.sAMAccountName -TargetType 'User' -ClearShadowCredentials -DeviceID $DeviceID -Force:$Force -PassThru:$PassThru

                    if ($PassThru -and $result) {
                        return $result
                    }
                }

                # ===== SPN Manipulation (Targeted Kerberoasting) =====
                'SetSPN' {
                    Write-Log "[Set-DomainUser] Adding SPN to: $($TargetUser.sAMAccountName)"

                    try {
                        # Get current SPNs
                        $CurrentSPNs = @()
                        if ($TargetUser.servicePrincipalName) {
                            $spnValue = $TargetUser.servicePrincipalName
                            if ($spnValue -is [System.Array]) {
                                $CurrentSPNs = @($spnValue | ForEach-Object { [string]$_ })
                            }
                            else {
                                $CurrentSPNs = @([string]$spnValue)
                            }
                        }

                        Write-Log "[Set-DomainUser] Current SPNs ($($CurrentSPNs.Count)): $($CurrentSPNs -join ', ')"

                        # Check if SPN already exists
                        if ($CurrentSPNs -contains $SetSPN) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetSPN"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    SPN = $SetSPN
                                    Success = $true
                                    Message = "SPN already present (no change)"
                                }
                            } else {
                                Show-Line "SPN '$SetSPN' already present on: $($TargetUser.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            # Add new SPN via ModifyRequest
                            $NewSPNs = [string[]]@($CurrentSPNs + $SetSPN)
                            Write-Log "[Set-DomainUser] New SPNs ($($NewSPNs.Count)): $($NewSPNs -join ', ')"

                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $UserDN

                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "servicePrincipalName"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            foreach ($spn in $NewSPNs) {
                                $Modification.Add($spn) | Out-Null
                            }

                            $ModifyRequest.Modifications.Add($Modification) | Out-Null

                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }

                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetSPN"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    SPN = $SetSPN
                                    AllSPNs = $NewSPNs
                                    Success = $true
                                    Message = "SPN added - user is now Kerberoastable"
                                }
                            } else {
                                Show-Line "Successfully added SPN '$SetSPN' to: $($TargetUser.sAMAccountName)" -Class Hint
                                Show-Line "User is now Kerberoastable!" -Class Finding
                            }
                        }
                    } catch {
                        throw "Failed to set SPN: $_"
                    }
                }

                'ClearSPN' {
                    Write-Log "[Set-DomainUser] Removing SPN from: $($TargetUser.sAMAccountName)"

                    try {
                        # Get current SPNs
                        $CurrentSPNs = @()
                        if ($TargetUser.servicePrincipalName) {
                            $spnValue = $TargetUser.servicePrincipalName
                            if ($spnValue -is [System.Array]) {
                                $CurrentSPNs = @($spnValue | ForEach-Object { [string]$_ })
                            }
                            else {
                                $CurrentSPNs = @([string]$spnValue)
                            }
                        }

                        Write-Log "[Set-DomainUser] Current SPNs ($($CurrentSPNs.Count)): $($CurrentSPNs -join ', ')"

                        if ($CurrentSPNs.Count -eq 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearSPN"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    Success = $true
                                    Message = "No SPNs present (no change)"
                                }
                            } else {
                                Show-Line "No SPNs present on: $($TargetUser.sAMAccountName)" -Class Note
                            }
                        }
                        elseif ($Force) {
                            # Remove ALL SPNs via ModifyRequest
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $UserDN

                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "servicePrincipalName"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete

                            $ModifyRequest.Modifications.Add($Modification) | Out-Null

                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }

                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearSPN"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    RemovedSPNs = $CurrentSPNs
                                    Success = $true
                                    Message = "All $($CurrentSPNs.Count) SPN(s) removed"
                                }
                            } else {
                                Show-Line "Successfully removed all $($CurrentSPNs.Count) SPN(s) from: $($TargetUser.sAMAccountName)" -Class Hint
                            }
                        }
                        elseif ($CurrentSPNs -contains $ClearSPN) {
                            # Remove specific SPN via ModifyRequest
                            $NewSPNs = [string[]]@($CurrentSPNs | Where-Object { $_ -ne $ClearSPN })
                            Write-Log "[Set-DomainUser] New SPNs ($($NewSPNs.Count)): $($NewSPNs -join ', ')"

                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $UserDN

                            if ($NewSPNs.Count -eq 0) {
                                # Last SPN removed - clear attribute entirely
                                $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                                $Modification.Name = "servicePrincipalName"
                                $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete
                            } else {
                                # Replace with remaining SPNs
                                $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                                $Modification.Name = "servicePrincipalName"
                                $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                                foreach ($spn in $NewSPNs) {
                                    $Modification.Add($spn) | Out-Null
                                }
                            }

                            $ModifyRequest.Modifications.Add($Modification) | Out-Null

                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }

                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearSPN"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    RemovedSPN = $ClearSPN
                                    RemainingSPNs = $NewSPNs
                                    Success = $true
                                    Message = "SPN removed"
                                }
                            } else {
                                Show-Line "Successfully removed SPN '$ClearSPN' from: $($TargetUser.sAMAccountName)" -Class Hint
                            }
                        }
                        else {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearSPN"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    Success = $false
                                    Message = "SPN '$ClearSPN' not found on user. Use -Force to remove all SPNs."
                                }
                            } else {
                                Show-Line "SPN '$ClearSPN' not found on: $($TargetUser.sAMAccountName)" -Class Note
                                Show-Line "Current SPNs: $($CurrentSPNs -join ', ')" -Class Note
                                Show-Line "Use -Force to remove all SPNs" -Class Note
                            }
                        }
                    } catch {
                        throw "Failed to clear SPN: $_"
                    }
                }

                # ===== DONT_REQ_PREAUTH (0x400000) =====
                'SetDontReqPreauth' {
                    Write-Log "[Set-DomainUser] Setting DONT_REQ_PREAUTH flag for: $($TargetUser.sAMAccountName)"

                    try {
                        # Get current userAccountControl
                        $CurrentUAC = if ($TargetUser.userAccountControl) {
                            [int]$TargetUser.userAccountControl
                        } else { 512 }  # Default: NORMAL_ACCOUNT

                        Write-Log "[Set-DomainUser] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"

                        # DONT_REQ_PREAUTH = 0x400000 (4194304)
                        $DONT_REQ_PREAUTH = 0x400000

                        if (($CurrentUAC -band $DONT_REQ_PREAUTH) -ne 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetDontReqPreauth"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    Success = $true
                                    Message = "DONT_REQ_PREAUTH already set (no change)"
                                }
                            } else {
                                Show-Line "DONT_REQ_PREAUTH already set on: $($TargetUser.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            $NewUAC = $CurrentUAC -bor $DONT_REQ_PREAUTH
                            Write-Log "[Set-DomainUser] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"

                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $UserDN

                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "userAccountControl"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add([string]$NewUAC) | Out-Null

                            $ModifyRequest.Modifications.Add($Modification) | Out-Null

                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }

                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetDontReqPreauth"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "DONT_REQ_PREAUTH flag set - user is now AS-REP roastable!"
                                }
                            } else {
                                Show-Line "Successfully set DONT_REQ_PREAUTH on: $($TargetUser.sAMAccountName)" -Class Hint
                                Show-Line "User is now ASREPRoastable!" -Class Finding
                            }
                        }
                    } catch {
                        throw "Failed to set DONT_REQ_PREAUTH: $_"
                    }
                }

                'ClearDontReqPreauth' {
                    Write-Log "[Set-DomainUser] Clearing DONT_REQ_PREAUTH flag for: $($TargetUser.sAMAccountName)"

                    try {
                        # Get current userAccountControl
                        $CurrentUAC = if ($TargetUser.userAccountControl) {
                            [int]$TargetUser.userAccountControl
                        } else { 512 }

                        Write-Log "[Set-DomainUser] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"

                        # DONT_REQ_PREAUTH = 0x400000 (4194304)
                        $DONT_REQ_PREAUTH = 0x400000

                        if (($CurrentUAC -band $DONT_REQ_PREAUTH) -eq 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearDontReqPreauth"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    Success = $true
                                    Message = "DONT_REQ_PREAUTH already cleared (no change)"
                                }
                            } else {
                                Show-Line "DONT_REQ_PREAUTH already cleared on: $($TargetUser.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            $NewUAC = $CurrentUAC -band (-bnot $DONT_REQ_PREAUTH)
                            Write-Log "[Set-DomainUser] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"

                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $UserDN

                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "userAccountControl"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add([string]$NewUAC) | Out-Null

                            $ModifyRequest.Modifications.Add($Modification) | Out-Null

                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }

                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearDontReqPreauth"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "DONT_REQ_PREAUTH flag cleared - pre-authentication is required again"
                                }
                            } else {
                                Show-Line "Successfully cleared DONT_REQ_PREAUTH on: $($TargetUser.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to clear DONT_REQ_PREAUTH: $_"
                    }
                }

                # ===== Account State Management =====
                'EnableAccount' {
                    Write-Log "[Set-DomainUser] Enabling account: $($TargetUser.sAMAccountName)"

                    try {
                        # Get current userAccountControl
                        $CurrentUAC = if ($TargetUser.userAccountControl) {
                            [int]$TargetUser.userAccountControl
                        } else { 512 }

                        Write-Log "[Set-DomainUser] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"

                        # ACCOUNTDISABLE = 0x2
                        $ACCOUNTDISABLE = 0x2

                        if (($CurrentUAC -band $ACCOUNTDISABLE) -eq 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "EnableAccount"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    Success = $true
                                    Message = "Account already enabled (no change)"
                                }
                            } else {
                                Show-Line "Account already enabled: $($TargetUser.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            $NewUAC = $CurrentUAC -band (-bnot $ACCOUNTDISABLE)
                            Write-Log "[Set-DomainUser] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"

                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $UserDN

                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "userAccountControl"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add([string]$NewUAC) | Out-Null

                            $ModifyRequest.Modifications.Add($Modification) | Out-Null

                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }

                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "EnableAccount"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "Account enabled"
                                }
                            } else {
                                Show-Line "Successfully enabled account: $($TargetUser.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to enable account: $_"
                    }
                }

                'DisableAccount' {
                    Write-Log "[Set-DomainUser] Disabling account: $($TargetUser.sAMAccountName)"

                    try {
                        # Get current userAccountControl
                        $CurrentUAC = if ($TargetUser.userAccountControl) {
                            [int]$TargetUser.userAccountControl
                        } else { 512 }

                        Write-Log "[Set-DomainUser] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"

                        # ACCOUNTDISABLE = 0x2
                        $ACCOUNTDISABLE = 0x2

                        if (($CurrentUAC -band $ACCOUNTDISABLE) -ne 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "DisableAccount"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    Success = $true
                                    Message = "Account already disabled (no change)"
                                }
                            } else {
                                Show-Line "Account already disabled: $($TargetUser.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            $NewUAC = $CurrentUAC -bor $ACCOUNTDISABLE
                            Write-Log "[Set-DomainUser] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"

                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $UserDN

                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "userAccountControl"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add([string]$NewUAC) | Out-Null

                            $ModifyRequest.Modifications.Add($Modification) | Out-Null

                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }

                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "DisableAccount"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "Account disabled"
                                }
                            } else {
                                Show-Line "Successfully disabled account: $($TargetUser.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to disable account: $_"
                    }
                }

                'UnlockAccount' {
                    Write-Log "[Set-DomainUser] Unlocking account: $($TargetUser.sAMAccountName)"

                    try {
                        # Check if account is locked
                        $LockoutTime = $TargetUser.lockoutTime
                        $IsLocked = $LockoutTime -and ($LockoutTime -gt 0)

                        if (-not $IsLocked) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "UnlockAccount"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    Success = $true
                                    Message = "Account not locked (no change)"
                                }
                            } else {
                                Show-Line "Account not locked: $($TargetUser.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            Write-Log "[Set-DomainUser] Account is locked (lockoutTime: $LockoutTime)"

                            # Clear lockoutTime to unlock via ModifyRequest
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $UserDN

                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "lockoutTime"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add("0") | Out-Null

                            $ModifyRequest.Modifications.Add($Modification) | Out-Null

                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }

                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "UnlockAccount"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    PreviousLockoutTime = $LockoutTime
                                    Success = $true
                                    Message = "Account unlocked"
                                }
                            } else {
                                Show-Line "Successfully unlocked account: $($TargetUser.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to unlock account: $_"
                    }
                }

                'SetPasswordNotRequired' {
                    Write-Log "[Set-DomainUser] Setting PASSWD_NOTREQD flag: $($TargetUser.sAMAccountName)"
                    try {
                        $CurrentUAC = if ($TargetUser.userAccountControl) { [int]$TargetUser.userAccountControl } else { 512 }
                        Write-Log "[Set-DomainUser] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"
                        $PASSWD_NOTREQD = 0x0020
                        if (($CurrentUAC -band $PASSWD_NOTREQD) -ne 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetPasswordNotRequired"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    Success = $true
                                    Message = "PASSWD_NOTREQD already set (no change)"
                                }
                            } else {
                                Show-Line "PASSWD_NOTREQD already set on: $($TargetUser.sAMAccountName)" -Class Note
                            }
                        } else {
                            $NewUAC = $CurrentUAC -bor $PASSWD_NOTREQD
                            Write-Log "[Set-DomainUser] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $UserDN
                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "userAccountControl"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add([string]$NewUAC) | Out-Null
                            $ModifyRequest.Modifications.Add($Modification) | Out-Null
                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetPasswordNotRequired"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "PASSWD_NOTREQD flag set"
                                }
                            } else {
                                Show-Line "Successfully set PASSWD_NOTREQD on: $($TargetUser.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to set PASSWD_NOTREQD: $_"
                    }
                }

                'ClearPasswordNotRequired' {
                    Write-Log "[Set-DomainUser] Clearing PASSWD_NOTREQD flag: $($TargetUser.sAMAccountName)"
                    try {
                        $CurrentUAC = if ($TargetUser.userAccountControl) { [int]$TargetUser.userAccountControl } else { 512 }
                        Write-Log "[Set-DomainUser] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"
                        $PASSWD_NOTREQD = 0x0020
                        if (($CurrentUAC -band $PASSWD_NOTREQD) -eq 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearPasswordNotRequired"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    Success = $true
                                    Message = "PASSWD_NOTREQD already cleared (no change)"
                                }
                            } else {
                                Show-Line "PASSWD_NOTREQD already cleared on: $($TargetUser.sAMAccountName)" -Class Note
                            }
                        } else {
                            $NewUAC = $CurrentUAC -band (-bnot $PASSWD_NOTREQD)
                            Write-Log "[Set-DomainUser] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $UserDN
                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "userAccountControl"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add([string]$NewUAC) | Out-Null
                            $ModifyRequest.Modifications.Add($Modification) | Out-Null
                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearPasswordNotRequired"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "PASSWD_NOTREQD flag cleared - password is required again"
                                }
                            } else {
                                Show-Line "Successfully cleared PASSWD_NOTREQD on: $($TargetUser.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to clear PASSWD_NOTREQD: $_"
                    }
                }

                'SetPasswordCantChange' {
                    Write-Log "[Set-DomainUser] Setting PASSWD_CANT_CHANGE flag: $($TargetUser.sAMAccountName)"
                    try {
                        $CurrentUAC = if ($TargetUser.userAccountControl) { [int]$TargetUser.userAccountControl } else { 512 }
                        Write-Log "[Set-DomainUser] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"
                        $PASSWD_CANT_CHANGE = 0x0040
                        if (($CurrentUAC -band $PASSWD_CANT_CHANGE) -ne 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetPasswordCantChange"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    Success = $true
                                    Message = "PASSWD_CANT_CHANGE already set (no change)"
                                }
                            } else {
                                Show-Line "PASSWD_CANT_CHANGE already set on: $($TargetUser.sAMAccountName)" -Class Note
                            }
                        } else {
                            $NewUAC = $CurrentUAC -bor $PASSWD_CANT_CHANGE
                            Write-Log "[Set-DomainUser] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $UserDN
                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "userAccountControl"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add([string]$NewUAC) | Out-Null
                            $ModifyRequest.Modifications.Add($Modification) | Out-Null
                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetPasswordCantChange"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "PASSWD_CANT_CHANGE flag set"
                                }
                            } else {
                                Show-Line "Successfully set PASSWD_CANT_CHANGE on: $($TargetUser.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to set PASSWD_CANT_CHANGE: $_"
                    }
                }

                'ClearPasswordCantChange' {
                    Write-Log "[Set-DomainUser] Clearing PASSWD_CANT_CHANGE flag: $($TargetUser.sAMAccountName)"
                    try {
                        $CurrentUAC = if ($TargetUser.userAccountControl) { [int]$TargetUser.userAccountControl } else { 512 }
                        Write-Log "[Set-DomainUser] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"
                        $PASSWD_CANT_CHANGE = 0x0040
                        if (($CurrentUAC -band $PASSWD_CANT_CHANGE) -eq 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearPasswordCantChange"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    Success = $true
                                    Message = "PASSWD_CANT_CHANGE already cleared (no change)"
                                }
                            } else {
                                Show-Line "PASSWD_CANT_CHANGE already cleared on: $($TargetUser.sAMAccountName)" -Class Note
                            }
                        } else {
                            $NewUAC = $CurrentUAC -band (-bnot $PASSWD_CANT_CHANGE)
                            Write-Log "[Set-DomainUser] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $UserDN
                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "userAccountControl"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add([string]$NewUAC) | Out-Null
                            $ModifyRequest.Modifications.Add($Modification) | Out-Null
                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearPasswordCantChange"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "PASSWD_CANT_CHANGE flag cleared - user can change password again"
                                }
                            } else {
                                Show-Line "Successfully cleared PASSWD_CANT_CHANGE on: $($TargetUser.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to clear PASSWD_CANT_CHANGE: $_"
                    }
                }

                'SetReversibleEncryption' {
                    Write-Log "[Set-DomainUser] Setting ENCRYPTED_TEXT_PWD_ALLOWED flag: $($TargetUser.sAMAccountName)"
                    try {
                        $CurrentUAC = if ($TargetUser.userAccountControl) { [int]$TargetUser.userAccountControl } else { 512 }
                        Write-Log "[Set-DomainUser] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"
                        $ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080
                        if (($CurrentUAC -band $ENCRYPTED_TEXT_PWD_ALLOWED) -ne 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetReversibleEncryption"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    Success = $true
                                    Message = "ENCRYPTED_TEXT_PWD_ALLOWED already set (no change)"
                                }
                            } else {
                                Show-Line "ENCRYPTED_TEXT_PWD_ALLOWED already set on: $($TargetUser.sAMAccountName)" -Class Note
                            }
                        } else {
                            $NewUAC = $CurrentUAC -bor $ENCRYPTED_TEXT_PWD_ALLOWED
                            Write-Log "[Set-DomainUser] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $UserDN
                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "userAccountControl"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add([string]$NewUAC) | Out-Null
                            $ModifyRequest.Modifications.Add($Modification) | Out-Null
                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetReversibleEncryption"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "ENCRYPTED_TEXT_PWD_ALLOWED flag set"
                                }
                            } else {
                                Show-Line "Successfully set ENCRYPTED_TEXT_PWD_ALLOWED on: $($TargetUser.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to set ENCRYPTED_TEXT_PWD_ALLOWED: $_"
                    }
                }

                'ClearReversibleEncryption' {
                    Write-Log "[Set-DomainUser] Clearing ENCRYPTED_TEXT_PWD_ALLOWED flag: $($TargetUser.sAMAccountName)"
                    try {
                        $CurrentUAC = if ($TargetUser.userAccountControl) { [int]$TargetUser.userAccountControl } else { 512 }
                        Write-Log "[Set-DomainUser] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"
                        $ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080
                        if (($CurrentUAC -band $ENCRYPTED_TEXT_PWD_ALLOWED) -eq 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearReversibleEncryption"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    Success = $true
                                    Message = "ENCRYPTED_TEXT_PWD_ALLOWED already cleared (no change)"
                                }
                            } else {
                                Show-Line "ENCRYPTED_TEXT_PWD_ALLOWED already cleared on: $($TargetUser.sAMAccountName)" -Class Note
                            }
                        } else {
                            $NewUAC = $CurrentUAC -band (-bnot $ENCRYPTED_TEXT_PWD_ALLOWED)
                            Write-Log "[Set-DomainUser] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $UserDN
                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "userAccountControl"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add([string]$NewUAC) | Out-Null
                            $ModifyRequest.Modifications.Add($Modification) | Out-Null
                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearReversibleEncryption"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "ENCRYPTED_TEXT_PWD_ALLOWED flag cleared - reversible encryption disabled"
                                }
                            } else {
                                Show-Line "Successfully cleared ENCRYPTED_TEXT_PWD_ALLOWED on: $($TargetUser.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to clear ENCRYPTED_TEXT_PWD_ALLOWED: $_"
                    }
                }

                'SetPasswordNeverExpires' {
                    Write-Log "[Set-DomainUser] Setting DONT_EXPIRE_PASSWORD flag: $($TargetUser.sAMAccountName)"
                    try {
                        $CurrentUAC = if ($TargetUser.userAccountControl) { [int]$TargetUser.userAccountControl } else { 512 }
                        Write-Log "[Set-DomainUser] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"
                        $DONT_EXPIRE_PASSWORD = 0x10000
                        if (($CurrentUAC -band $DONT_EXPIRE_PASSWORD) -ne 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetPasswordNeverExpires"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    Success = $true
                                    Message = "DONT_EXPIRE_PASSWORD already set (no change)"
                                }
                            } else {
                                Show-Line "DONT_EXPIRE_PASSWORD already set on: $($TargetUser.sAMAccountName)" -Class Note
                            }
                        } else {
                            $NewUAC = $CurrentUAC -bor $DONT_EXPIRE_PASSWORD
                            Write-Log "[Set-DomainUser] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $UserDN
                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "userAccountControl"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add([string]$NewUAC) | Out-Null
                            $ModifyRequest.Modifications.Add($Modification) | Out-Null
                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetPasswordNeverExpires"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "DONT_EXPIRE_PASSWORD flag set"
                                }
                            } else {
                                Show-Line "Successfully set DONT_EXPIRE_PASSWORD on: $($TargetUser.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to set DONT_EXPIRE_PASSWORD: $_"
                    }
                }

                'ClearPasswordNeverExpires' {
                    Write-Log "[Set-DomainUser] Clearing DONT_EXPIRE_PASSWORD flag: $($TargetUser.sAMAccountName)"
                    try {
                        $CurrentUAC = if ($TargetUser.userAccountControl) { [int]$TargetUser.userAccountControl } else { 512 }
                        Write-Log "[Set-DomainUser] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"
                        $DONT_EXPIRE_PASSWORD = 0x10000
                        if (($CurrentUAC -band $DONT_EXPIRE_PASSWORD) -eq 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearPasswordNeverExpires"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    Success = $true
                                    Message = "DONT_EXPIRE_PASSWORD already cleared (no change)"
                                }
                            } else {
                                Show-Line "DONT_EXPIRE_PASSWORD already cleared on: $($TargetUser.sAMAccountName)" -Class Note
                            }
                        } else {
                            $NewUAC = $CurrentUAC -band (-bnot $DONT_EXPIRE_PASSWORD)
                            Write-Log "[Set-DomainUser] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $UserDN
                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "userAccountControl"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add([string]$NewUAC) | Out-Null
                            $ModifyRequest.Modifications.Add($Modification) | Out-Null
                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearPasswordNeverExpires"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "DONT_EXPIRE_PASSWORD flag cleared - password expiry follows domain policy"
                                }
                            } else {
                                Show-Line "Successfully cleared DONT_EXPIRE_PASSWORD on: $($TargetUser.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to clear DONT_EXPIRE_PASSWORD: $_"
                    }
                }

                'SetSmartcardRequired' {
                    Write-Log "[Set-DomainUser] Setting SMARTCARD_REQUIRED flag: $($TargetUser.sAMAccountName)"
                    try {
                        $CurrentUAC = if ($TargetUser.userAccountControl) { [int]$TargetUser.userAccountControl } else { 512 }
                        Write-Log "[Set-DomainUser] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"
                        $SMARTCARD_REQUIRED = 0x40000
                        if (($CurrentUAC -band $SMARTCARD_REQUIRED) -ne 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetSmartcardRequired"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    Success = $true
                                    Message = "SMARTCARD_REQUIRED already set (no change)"
                                }
                            } else {
                                Show-Line "SMARTCARD_REQUIRED already set on: $($TargetUser.sAMAccountName)" -Class Note
                            }
                        } else {
                            $NewUAC = $CurrentUAC -bor $SMARTCARD_REQUIRED
                            Write-Log "[Set-DomainUser] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $UserDN
                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "userAccountControl"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add([string]$NewUAC) | Out-Null
                            $ModifyRequest.Modifications.Add($Modification) | Out-Null
                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetSmartcardRequired"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "SMARTCARD_REQUIRED flag set"
                                }
                            } else {
                                Show-Line "Successfully set SMARTCARD_REQUIRED on: $($TargetUser.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to set SMARTCARD_REQUIRED: $_"
                    }
                }

                'ClearSmartcardRequired' {
                    Write-Log "[Set-DomainUser] Clearing SMARTCARD_REQUIRED flag: $($TargetUser.sAMAccountName)"
                    try {
                        $CurrentUAC = if ($TargetUser.userAccountControl) { [int]$TargetUser.userAccountControl } else { 512 }
                        Write-Log "[Set-DomainUser] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"
                        $SMARTCARD_REQUIRED = 0x40000
                        if (($CurrentUAC -band $SMARTCARD_REQUIRED) -eq 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearSmartcardRequired"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    Success = $true
                                    Message = "SMARTCARD_REQUIRED already cleared (no change)"
                                }
                            } else {
                                Show-Line "SMARTCARD_REQUIRED already cleared on: $($TargetUser.sAMAccountName)" -Class Note
                            }
                        } else {
                            $NewUAC = $CurrentUAC -band (-bnot $SMARTCARD_REQUIRED)
                            Write-Log "[Set-DomainUser] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $UserDN
                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "userAccountControl"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add([string]$NewUAC) | Out-Null
                            $ModifyRequest.Modifications.Add($Modification) | Out-Null
                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearSmartcardRequired"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "SMARTCARD_REQUIRED flag cleared - smartcard no longer required"
                                }
                            } else {
                                Show-Line "Successfully cleared SMARTCARD_REQUIRED on: $($TargetUser.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to clear SMARTCARD_REQUIRED: $_"
                    }
                }

                'SetNotDelegated' {
                    Write-Log "[Set-DomainUser] Setting NOT_DELEGATED flag: $($TargetUser.sAMAccountName)"
                    try {
                        $CurrentUAC = if ($TargetUser.userAccountControl) { [int]$TargetUser.userAccountControl } else { 512 }
                        Write-Log "[Set-DomainUser] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"
                        $NOT_DELEGATED = 0x100000
                        if (($CurrentUAC -band $NOT_DELEGATED) -ne 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetNotDelegated"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    Success = $true
                                    Message = "NOT_DELEGATED already set (no change)"
                                }
                            } else {
                                Show-Line "NOT_DELEGATED already set on: $($TargetUser.sAMAccountName)" -Class Note
                            }
                        } else {
                            $NewUAC = $CurrentUAC -bor $NOT_DELEGATED
                            Write-Log "[Set-DomainUser] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $UserDN
                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "userAccountControl"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add([string]$NewUAC) | Out-Null
                            $ModifyRequest.Modifications.Add($Modification) | Out-Null
                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetNotDelegated"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "NOT_DELEGATED flag set - account marked as sensitive"
                                }
                            } else {
                                Show-Line "Successfully set NOT_DELEGATED on: $($TargetUser.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to set NOT_DELEGATED: $_"
                    }
                }

                'ClearNotDelegated' {
                    Write-Log "[Set-DomainUser] Clearing NOT_DELEGATED flag: $($TargetUser.sAMAccountName)"
                    try {
                        $CurrentUAC = if ($TargetUser.userAccountControl) { [int]$TargetUser.userAccountControl } else { 512 }
                        Write-Log "[Set-DomainUser] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"
                        $NOT_DELEGATED = 0x100000
                        if (($CurrentUAC -band $NOT_DELEGATED) -eq 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearNotDelegated"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    Success = $true
                                    Message = "NOT_DELEGATED already cleared (no change)"
                                }
                            } else {
                                Show-Line "NOT_DELEGATED already cleared on: $($TargetUser.sAMAccountName)" -Class Note
                            }
                        } else {
                            $NewUAC = $CurrentUAC -band (-bnot $NOT_DELEGATED)
                            Write-Log "[Set-DomainUser] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $UserDN
                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "userAccountControl"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add([string]$NewUAC) | Out-Null
                            $ModifyRequest.Modifications.Add($Modification) | Out-Null
                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearNotDelegated"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "NOT_DELEGATED flag cleared - account can be delegated again"
                                }
                            } else {
                                Show-Line "Successfully cleared NOT_DELEGATED on: $($TargetUser.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to clear NOT_DELEGATED: $_"
                    }
                }

                'SetPasswordExpired' {
                    Write-Log "[Set-DomainUser] Setting PASSWORD_EXPIRED flag: $($TargetUser.sAMAccountName)"
                    try {
                        $CurrentUAC = if ($TargetUser.userAccountControl) { [int]$TargetUser.userAccountControl } else { 512 }
                        Write-Log "[Set-DomainUser] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"
                        $PASSWORD_EXPIRED = 0x800000
                        if (($CurrentUAC -band $PASSWORD_EXPIRED) -ne 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetPasswordExpired"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    Success = $true
                                    Message = "PASSWORD_EXPIRED already set (no change)"
                                }
                            } else {
                                Show-Line "PASSWORD_EXPIRED already set on: $($TargetUser.sAMAccountName)" -Class Note
                            }
                        } else {
                            $NewUAC = $CurrentUAC -bor $PASSWORD_EXPIRED
                            Write-Log "[Set-DomainUser] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $UserDN
                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "userAccountControl"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add([string]$NewUAC) | Out-Null
                            $ModifyRequest.Modifications.Add($Modification) | Out-Null
                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetPasswordExpired"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "PASSWORD_EXPIRED flag set"
                                }
                            } else {
                                Show-Line "Successfully set PASSWORD_EXPIRED on: $($TargetUser.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to set PASSWORD_EXPIRED: $_"
                    }
                }

                'ClearPasswordExpired' {
                    Write-Log "[Set-DomainUser] Clearing PASSWORD_EXPIRED flag: $($TargetUser.sAMAccountName)"
                    try {
                        $CurrentUAC = if ($TargetUser.userAccountControl) { [int]$TargetUser.userAccountControl } else { 512 }
                        Write-Log "[Set-DomainUser] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"
                        $PASSWORD_EXPIRED = 0x800000
                        if (($CurrentUAC -band $PASSWORD_EXPIRED) -eq 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearPasswordExpired"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    Success = $true
                                    Message = "PASSWORD_EXPIRED already cleared (no change)"
                                }
                            } else {
                                Show-Line "PASSWORD_EXPIRED already cleared on: $($TargetUser.sAMAccountName)" -Class Note
                            }
                        } else {
                            $NewUAC = $CurrentUAC -band (-bnot $PASSWORD_EXPIRED)
                            Write-Log "[Set-DomainUser] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $UserDN
                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "userAccountControl"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add([string]$NewUAC) | Out-Null
                            $ModifyRequest.Modifications.Add($Modification) | Out-Null
                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearPasswordExpired"
                                    User = $TargetUser.sAMAccountName
                                    DistinguishedName = $UserDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "PASSWORD_EXPIRED flag cleared"
                                }
                            } else {
                                Show-Line "Successfully cleared PASSWORD_EXPIRED on: $($TargetUser.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to clear PASSWORD_EXPIRED: $_"
                    }
                }
            }

        } catch {
            Write-Log "[Set-DomainUser] Error: $_"

            $UserIdentifier = $Identity
            $ErrorMsg = $_.Exception.Message

            # Translate auth errors for password operations
            if ($PSCmdlet.ParameterSetName -in @('SetPassword', 'ChangePassword') -and $ErrorMsg -match "user name or password is incorrect|password is incorrect") {
                $ErrorMsg = "Authentication failed for password operation on '$UserIdentifier'. This typically occurs when using a computer account or non-interactive session. Try using explicit credentials with -Credential or -Username/-Password, or use LDAPS (-UseLDAPS) for unicodePwd support."
            }

            if ($PassThru) {
                return [PSCustomObject]@{
                    Operation = $PSCmdlet.ParameterSetName
                    User = $UserIdentifier
                    Success = $false
                    Message = $ErrorMsg
                }
            } else {
                Write-Warning "[!] $ErrorMsg"
            }
        } finally {
            if ($UserEntry) {
                try { $UserEntry.Dispose() } catch { }
            }
        }
    }

    end {
        Write-Log "[Set-DomainUser] User modification completed"
    }
}
