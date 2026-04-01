function New-DomainUser {
<#
.SYNOPSIS
    Creates a new user object in Active Directory.

.DESCRIPTION
    New-DomainUser creates a new user account in Active Directory via LDAP AddRequest/ModifyRequest.
    This function is designed for offensive security operations where native AD tools may not be available or stealthy operation is required.

    Uses $Script:LdapConnection (AddRequest) for object creation, unicodePwd (ModifyRequest) for
    password setting with DirectoryEntry fallback, and ModifyRequest for account enabling.

.PARAMETER Name
    sAMAccountName for the new user. This will also be used for the CN and UPN.

.PARAMETER Password
    Password for the new user account (plaintext).
    If not specified, a random 20-character complex password is generated.

.PARAMETER OrganizationalUnit
    DistinguishedName of the OU where the user should be created.
    Default: CN=Users,DC=domain,DC=com

.PARAMETER Description
    Description attribute for the user account.

.PARAMETER Enabled
    Whether the account should be enabled after creation. Default: $true

.PARAMETER Domain
    Target domain (FQDN).

.PARAMETER Server
    Specific Domain Controller to target.

.PARAMETER Credential
    PSCredential object for authentication.

.EXAMPLE
    New-DomainUser -Name "testuser"
    Creates a new user with auto-generated password in the default Users container.

.EXAMPLE
    New-DomainUser -Name "testuser" -Password "P@ssw0rd123!"
    Creates a new user with custom password in the default Users container.

.EXAMPLE
    New-DomainUser -Name "serviceaccount" -Password "C0mpl3x!" -OrganizationalUnit "OU=Service Accounts,DC=contoso,DC=com" -Enabled $false
    Creates a disabled service account in a specific OU.

.EXAMPLE
    New-DomainUser -Name "backdoor" -Password "Secret123" -Domain "contoso.com" -Credential (Get-Credential)
    Creates a user in a remote domain using alternative credentials.

.EXAMPLE
    $result = New-DomainUser -Name "testuser" -PassThru
    Creates a user and returns the result object for programmatic use.

.PARAMETER PassThru
    Returns a result object instead of only console output.
    Useful for scripting and automation.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true)]
        [string]$Name,

        [Parameter(Position=1, Mandatory=$false)]
        [Alias('NewPassword')]
        [string]$Password,

        [Parameter(Mandatory=$false)]
        [string]$OrganizationalUnit,

        [Parameter(Mandatory=$false)]
        [string]$Description,

        [Parameter(Mandatory=$false)]
        [bool]$Enabled = $true,

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
        Write-Log "[New-DomainUser] Starting user creation"
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
                    Operation = "CreateUser"
                    User = $Name
                    Success = $false
                    Message = "No LDAP connection available"
                }
            }
            return
        }

        try {
            Write-Log "[New-DomainUser] Creating new user: $Name"

            # Determine target OU
            if ($OrganizationalUnit) {
                $TargetOU = $OrganizationalUnit
            } else {
                # Use default Users container
                $TargetOU = "CN=Users,$($Script:LDAPContext.DomainDN)"
            }

            Write-Log "[New-DomainUser] Target OU: $TargetOU"

            # Phase A: Create user object via AddRequest (DISABLED)
            $UserDN = "CN=$Name,$TargetOU"

            $AddRequest = New-Object System.DirectoryServices.Protocols.AddRequest
            $AddRequest.DistinguishedName = $UserDN

            # NORMAL_ACCOUNT (0x0200=512) + ACCOUNTDISABLE (0x0002=2) = 514
            # Create DISABLED first, then set password, then enable
            $AddRequest.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("objectClass", "user"))) | Out-Null
            $AddRequest.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("sAMAccountName", $Name))) | Out-Null
            $AddRequest.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("userPrincipalName", "$Name@$($Script:LDAPContext.Domain)"))) | Out-Null
            $AddRequest.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("userAccountControl", "514"))) | Out-Null

            if ($Description) {
                $AddRequest.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("description", $Description))) | Out-Null
            }

            $AddResponse = $Script:LdapConnection.SendRequest($AddRequest)
            if ($AddResponse.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                throw "LDAP AddRequest failed: $($AddResponse.ResultCode) - $($AddResponse.ErrorMessage)"
            }
            Write-Log "[New-DomainUser] User object created (disabled): $UserDN"

            # Phase B: Set password
            $PasswordToSet = $Password
            $PasswordGenerated = $false

            if (-not $PasswordToSet) {
                $PasswordToSet = New-SafePassword -Length 20
                $PasswordGenerated = $true
                Write-Log "[New-DomainUser] Generated random password"
            }

            # Try unicodePwd via ModifyRequest (works over LDAPS and Kerberos-encrypted LDAP)
            $PasswordSet = $false
            try {
                $quotedPwd = '"' + $PasswordToSet + '"'
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
                    Write-Log "[New-DomainUser] Password set via unicodePwd ModifyRequest"
                }
            }
            catch {
                $primaryError = $_.Exception.Message
                Write-Log "[New-DomainUser] unicodePwd failed (expected on non-encrypted LDAP): $primaryError"
            }

            # Fallback: DirectoryEntry SetPassword (ADSI) - works on both LDAP and LDAPS
            if (-not $PasswordSet) {
                # Warn if no credentials available for DirectoryEntry (Hash/Key/Cert auth has no PSCredential)
                if (-not $Credential -and -not $Script:LDAPCredential) {
                    Write-Warning "[New-DomainUser] DirectoryEntry fallback uses current Windows user context, not the Kerberos-authenticated session identity. Password operation may fail or use wrong identity."
                }
                Write-Log "[New-DomainUser] Falling back to DirectoryEntry SetPassword"
                $UserEntry = Get-AuthenticatedDirectoryEntry -DistinguishedName $UserDN -Credential $Credential
                if (-not $UserEntry) {
                    # Cleanup orphaned disabled object
                    try {
                        $DelReq = New-Object System.DirectoryServices.Protocols.DeleteRequest($UserDN)
                        $Script:LdapConnection.SendRequest($DelReq) | Out-Null
                        Write-Log "[New-DomainUser] Cleaned up orphaned object"
                    } catch { }
                    throw "Failed to get DirectoryEntry for password setting"
                }
                try {
                    $UserEntry.Invoke("SetPassword", $PasswordToSet)
                    $UserEntry.CommitChanges()
                    $PasswordSet = $true
                    Write-Log "[New-DomainUser] Password set via DirectoryEntry SetPassword"
                }
                catch {
                    # Cleanup orphaned disabled object
                    try {
                        $DelReq = New-Object System.DirectoryServices.Protocols.DeleteRequest($UserDN)
                        $Script:LdapConnection.SendRequest($DelReq) | Out-Null
                        Write-Log "[New-DomainUser] Cleaned up orphaned object after password failure"
                    } catch { }
                    $errorMsg = "Failed to set password."
                    if ($primaryError) {
                        $errorMsg += " LDAP: $primaryError"
                    }
                    $errorMsg += " ADSI fallback: $_"
                    throw $errorMsg
                }
                finally {
                    if ($UserEntry) { $UserEntry.Dispose() }
                }
            }

            # Phase C: Enable account via ModifyRequest (password is now set)
            if ($Enabled) {
                $EnableRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                $EnableRequest.DistinguishedName = $UserDN

                $EnableMod = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                $EnableMod.Name = "userAccountControl"
                $EnableMod.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                $EnableMod.Add("512") | Out-Null  # NORMAL_ACCOUNT only (enabled)

                $EnableRequest.Modifications.Add($EnableMod) | Out-Null

                $EnableResponse = $Script:LdapConnection.SendRequest($EnableRequest)
                if ($EnableResponse.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                    throw "Failed to enable account: $($EnableResponse.ResultCode) - $($EnableResponse.ErrorMessage)"
                }
                Write-Log "[New-DomainUser] Account enabled"
            }

            # Return result object only if -PassThru is specified (no console output)
            if ($PassThru) {
                $Result = [PSCustomObject]@{
                    Operation = "CreateUser"
                    User = $Name
                    DistinguishedName = $UserDN
                    Enabled = $Enabled
                    Success = $true
                    Message = "User successfully created"
                }

                # Add password to result if it was generated
                if ($PasswordGenerated) {
                    $Result | Add-Member -NotePropertyName "Password" -NotePropertyValue $PasswordToSet
                }

                return $Result
            } else {
                # Console output (default behavior)
                Show-Line "Successfully created user: $Name" -Class Hint
                Show-KeyValue "Distinguished Name:" $UserDN
                Show-KeyValue "Enabled:" $Enabled

                if ($PasswordGenerated) {
                    Show-KeyValue "Password (SAVE THIS!):" $PasswordToSet -Class Finding
                } else {
                    Show-KeyValue "Password:" "[Custom password set]"
                }
            }
        }
        catch {
            Write-Error "[New-DomainUser] Failed to create user '$Name': $_"
            if ($PassThru) {
                return [PSCustomObject]@{
                    Operation = "CreateUser"
                    User = $Name
                    Success = $false
                    Message = $_.Exception.Message
                }
            }
        }
    }
}
