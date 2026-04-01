function Set-DomainGroup {
<#
.SYNOPSIS
    Modifies group objects in Active Directory.

.DESCRIPTION
    Set-DomainGroup is a flexible helper function for modifying group objects in AD.
    It supports various operations via parameter sets:

    - Add members to group (requires WriteProperty on member attribute)
    - Remove members from group (requires WriteProperty on member attribute)
    - Clear all members from group (requires WriteProperty on member attribute)
    - Set/Clear group description
    - Convert between Security and Distribution group types
    - Owner modification (requires TakeOwnership permission)
    - ACL modification (requires WriteDacl permission)

.PARAMETER Identity
    sAMAccountName, DistinguishedName, SID or DOMAIN\group format.

.PARAMETER AddMember
    User/computer/group to add as member. Accepts sAMAccountName, DN, or DOMAIN\name format.
    Can be array for multiple members.

.PARAMETER RemoveMember
    User/computer/group to remove from group. Accepts sAMAccountName, DN, or DOMAIN\name format.
    Can be array for multiple members.

.PARAMETER ClearMembers
    Remove ALL members from the group.
    Requires -Force parameter to confirm the destructive operation.

.PARAMETER SetDescription
    Set the description attribute of the group.
    Useful for camouflage or documentation.

.PARAMETER ClearDescription
    Remove the description attribute from the group.

.PARAMETER ConvertToSecurity
    Convert a Distribution group to a Security group.
    Security groups can be used for permissions assignment.

.PARAMETER ConvertToDistribution
    Convert a Security group to a Distribution group.
    Distribution groups cannot be used for permissions (effectively "disarms" the group).

.PARAMETER Owner
    New owner for the group object (DOMAIN\user or DN format).

.PARAMETER GrantRights
    Rights to grant to a principal. Values: GenericAll, GenericWrite, WriteMembers, WriteDacl, WriteOwner.

.PARAMETER Principal
    Principal to grant rights to (used with -GrantRights).

.PARAMETER Force
    Required for -ClearMembers to confirm removal of all members.

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
    Set-DomainGroup -Identity "Domain Admins" -AddMember "eviluser"
    Adds user to Domain Admins group.

.EXAMPLE
    Set-DomainGroup -Identity "Domain Admins" -RemoveMember "eviluser"
    Removes user from Domain Admins group.

.EXAMPLE
    Set-DomainGroup -Identity "Backup Operators" -AddMember @("user1","user2","computer1$")
    Adds multiple members to group.

.EXAMPLE
    Set-DomainGroup -Identity "IT-Support" -ClearMembers -Force
    Removes ALL members from the IT-Support group.

.EXAMPLE
    Set-DomainGroup -Identity "IT-Support" -SetDescription "Legitimate IT Support Group"
    Sets a description for camouflage purposes.

.EXAMPLE
    Set-DomainGroup -Identity "IT-Support" -ClearDescription
    Removes the description from the group.

.EXAMPLE
    Set-DomainGroup -Identity "MailGroup" -ConvertToSecurity
    Converts a Distribution group to Security group (can now assign permissions).

.EXAMPLE
    Set-DomainGroup -Identity "Domain Admins" -ConvertToDistribution
    Converts Security group to Distribution group (disarms the group for permissions).

.EXAMPLE
    Set-DomainGroup -Identity "Domain Admins" -Owner "DOMAIN\attacker"
    Takes ownership of Domain Admins group.

.EXAMPLE
    Set-DomainGroup -Identity "Domain Admins" -GrantRights WriteMembers -Principal "DOMAIN\attacker"
    Grants WriteMembers rights to attacker on Domain Admins group.

.OUTPUTS
    PSCustomObject with operation result

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding(DefaultParameterSetName='AddMember')]
    param(
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='AddMember')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='RemoveMember')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ClearMembers')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='SetDescription')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ClearDescription')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ConvertToSecurity')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ConvertToDistribution')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='SetOwner')]
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='GrantRights')]
        [Alias('samAccountName', 'Name', 'Group')]
        [string]$Identity,

        # Member operations
        [Parameter(ParameterSetName='AddMember', Mandatory=$true)]
        [string[]]$AddMember,

        [Parameter(ParameterSetName='RemoveMember', Mandatory=$true)]
        [string[]]$RemoveMember,

        [Parameter(ParameterSetName='ClearMembers', Mandatory=$true)]
        [switch]$ClearMembers,

        # Description operations
        [Parameter(ParameterSetName='SetDescription', Mandatory=$true)]
        [string]$SetDescription,

        [Parameter(ParameterSetName='ClearDescription', Mandatory=$true)]
        [switch]$ClearDescription,

        # Group Type conversion
        [Parameter(ParameterSetName='ConvertToSecurity', Mandatory=$true)]
        [switch]$ConvertToSecurity,

        [Parameter(ParameterSetName='ConvertToDistribution', Mandatory=$true)]
        [switch]$ConvertToDistribution,

        # Owner modification
        [Parameter(ParameterSetName='SetOwner', Mandatory=$true)]
        [string]$Owner,

        # ACL modification
        [Parameter(ParameterSetName='GrantRights', Mandatory=$true)]
        [ValidateSet('GenericAll','GenericWrite','WriteMembers','WriteDacl','WriteOwner')]
        [string]$GrantRights,

        [Parameter(ParameterSetName='GrantRights', Mandatory=$true)]
        [string]$Principal,

        # Force flag for destructive operations
        [Parameter(ParameterSetName='ClearMembers', Mandatory=$false)]
        [switch]$Force,

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
        Write-Log "[Set-DomainGroup] Starting group modification: $Identity"
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
                    Group = $Identity
                    Success = $false
                    Message = "No LDAP connection available"
                }
            }
            return
        }

        try {
            # Find the target group
            Write-Log "[Set-DomainGroup] Searching for group: $Identity"
            $TargetGroup = @(Get-DomainGroup -Identity $Identity @ConnectionParams)[0]

            if (-not $TargetGroup) {
                throw "Group '$Identity' not Found"
            }

            $GroupDN = $TargetGroup.distinguishedName
            Write-Log "[Set-DomainGroup] Found group: $GroupDN"

            # Build case-insensitive lookup for existing members (DN comparison must be case-insensitive)
            $ExistingMembersLower = @()
            if ($TargetGroup.member) {
                $ExistingMembersLower = @($TargetGroup.member | ForEach-Object { $_.ToLower() })
            }

            # Perform operation based on ParameterSet
            switch ($PSCmdlet.ParameterSetName) {
                'AddMember' {
                    Write-Log "[Set-DomainGroup] Adding member(s) to: $($TargetGroup.sAMAccountName)"

                    $AddedMembers = @()
                    $AddedMemberDNs = @()
                    $SkippedMembers = @()
                    $FailedMembers = @()

                    foreach ($MemberIdentity in $AddMember) {
                        try {
                            # Resolve member to DN (works for user, computer, or group)
                            # Get-DomainObject now supports cross-domain queries (DOMAIN\username)
                            $MemberObject = @(Get-DomainObject -Identity $MemberIdentity @ConnectionParams)[0]
                            if (-not $MemberObject) {
                                throw "Member '$MemberIdentity' not found"
                            }
                            $MemberDN = $MemberObject.distinguishedName

                            # Check if already member (case-insensitive DN comparison)
                            if ($ExistingMembersLower -contains $MemberDN.ToLower()) {
                                Write-Log "[Set-DomainGroup] $MemberIdentity is already a member - skipping"
                                $SkippedMembers += $MemberIdentity
                                continue
                            }

                            # Add member to list
                            $AddedMembers += $MemberIdentity
                            $AddedMemberDNs += $MemberDN
                            Write-Log "[Set-DomainGroup] Queued member for add: $MemberIdentity"

                        } catch {
                            Write-Warning "[Set-DomainGroup] Failed to resolve member '$MemberIdentity': $_"
                            $FailedMembers += $MemberIdentity
                        }
                    }

                    # Commit all changes at once via ModifyRequest (only if we actually have members to add)
                    if ($AddedMembers.Count -gt 0) {
                        try {
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $GroupDN

                            foreach ($dn in $AddedMemberDNs) {
                                $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                                $Modification.Name = "member"
                                $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Add
                                $Modification.Add($dn) | Out-Null
                                $ModifyRequest.Modifications.Add($Modification) | Out-Null
                            }

                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }

                            if (-not $PassThru) {
                                $msg = "Successfully added $($AddedMembers.Count) member(s) to: $($TargetGroup.sAMAccountName)"
                                if ($SkippedMembers.Count -gt 0) {
                                    $msg += " ($($SkippedMembers.Count) already existed)"
                                }
                                Show-Line $msg -Class Hint
                            }
                        } catch {
                            throw "Failed to commit changes: $_"
                        }
                    } elseif ($SkippedMembers.Count -gt 0 -and $FailedMembers.Count -eq 0) {
                        # All members already existed
                        if (-not $PassThru) {
                            Show-Line "All $($SkippedMembers.Count) member(s) already exist in: $($TargetGroup.sAMAccountName)" -Class Note
                        }
                    }

                    if ($PassThru) {
                        return [PSCustomObject]@{
                            Operation = "AddMember"
                            Group = $TargetGroup.sAMAccountName
                            DistinguishedName = $GroupDN
                            AddedMembers = $AddedMembers
                            SkippedMembers = $SkippedMembers
                            FailedMembers = $FailedMembers
                            Success = ($FailedMembers.Count -eq 0)
                            Message = "Added $($AddedMembers.Count), skipped $($SkippedMembers.Count) (already existed), $($FailedMembers.Count) failed"
                        }
                    }
                }

                'RemoveMember' {
                    Write-Log "[Set-DomainGroup] Removing member(s) from: $($TargetGroup.sAMAccountName)"

                    $RemovedMembers = @()
                    $RemovedMemberDNs = @()
                    $SkippedMembers = @()
                    $FailedMembers = @()

                    foreach ($MemberIdentity in $RemoveMember) {
                        try {
                            # Resolve member to DN (works for user, computer, or group)
                            # Get-DomainObject now supports cross-domain queries (DOMAIN\username)
                            $MemberObject = @(Get-DomainObject -Identity $MemberIdentity @ConnectionParams)[0]
                            if (-not $MemberObject) {
                                throw "Member '$MemberIdentity' not found"
                            }
                            $MemberDN = $MemberObject.distinguishedName

                            # Check if actually a member (case-insensitive DN comparison)
                            if ($ExistingMembersLower -notcontains $MemberDN.ToLower()) {
                                Write-Log "[Set-DomainGroup] $MemberIdentity is not a member - skipping"
                                $SkippedMembers += $MemberIdentity
                                continue
                            }

                            # Add member to removal list
                            $RemovedMembers += $MemberIdentity
                            $RemovedMemberDNs += $MemberDN
                            Write-Log "[Set-DomainGroup] Queued member for removal: $MemberIdentity"

                        } catch {
                            Write-Warning "[Set-DomainGroup] Failed to resolve member '$MemberIdentity': $_"
                            $FailedMembers += $MemberIdentity
                        }
                    }

                    # Commit all changes at once via ModifyRequest (only if we actually have members to remove)
                    if ($RemovedMembers.Count -gt 0) {
                        try {
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $GroupDN

                            foreach ($dn in $RemovedMemberDNs) {
                                $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                                $Modification.Name = "member"
                                $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete
                                $Modification.Add($dn) | Out-Null
                                $ModifyRequest.Modifications.Add($Modification) | Out-Null
                            }

                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }

                            if (-not $PassThru) {
                                $msg = "Successfully removed $($RemovedMembers.Count) member(s) from: $($TargetGroup.sAMAccountName)"
                                if ($SkippedMembers.Count -gt 0) {
                                    $msg += " ($($SkippedMembers.Count) were not members)"
                                }
                                Show-Line $msg -Class Hint
                            }
                        } catch {
                            throw "Failed to commit changes: $_"
                        }
                    } elseif ($SkippedMembers.Count -gt 0 -and $FailedMembers.Count -eq 0) {
                        # None of the specified members were in the group
                        if (-not $PassThru) {
                            Show-Line "None of the $($SkippedMembers.Count) specified member(s) were in: $($TargetGroup.sAMAccountName)" -Class Note
                        }
                    }

                    if ($PassThru) {
                        return [PSCustomObject]@{
                            Operation = "RemoveMember"
                            Group = $TargetGroup.sAMAccountName
                            DistinguishedName = $GroupDN
                            RemovedMembers = $RemovedMembers
                            SkippedMembers = $SkippedMembers
                            FailedMembers = $FailedMembers
                            Success = ($FailedMembers.Count -eq 0)
                            Message = "Removed $($RemovedMembers.Count), skipped $($SkippedMembers.Count) (not members), $($FailedMembers.Count) failed"
                        }
                    }
                }

                # ===== Clear All Members =====
                'ClearMembers' {
                    Write-Log "[Set-DomainGroup] Clearing all members from: $($TargetGroup.sAMAccountName)"

                    # Get current member count
                    $CurrentMembers = @()
                    if ($TargetGroup.member) {
                        if ($TargetGroup.member -is [System.Array]) {
                            $CurrentMembers = @($TargetGroup.member)
                        }
                        else {
                            $CurrentMembers = @($TargetGroup.member)
                        }
                    }

                    if ($CurrentMembers.Count -eq 0) {
                        if ($PassThru) {
                            return [PSCustomObject]@{
                                Operation = "ClearMembers"
                                Group = $TargetGroup.sAMAccountName
                                DistinguishedName = $GroupDN
                                Success = $true
                                Message = "Group has no members (no change)"
                            }
                        } else {
                            Show-Line "Group has no members: $($TargetGroup.sAMAccountName)" -Class Note
                        }
                    }
                    elseif (-not $Force) {
                        if ($PassThru) {
                            return [PSCustomObject]@{
                                Operation = "ClearMembers"
                                Group = $TargetGroup.sAMAccountName
                                DistinguishedName = $GroupDN
                                MemberCount = $CurrentMembers.Count
                                Success = $false
                                Message = "Group has $($CurrentMembers.Count) members. Use -Force to confirm removal of all members."
                            }
                        } else {
                            Show-Line "Group '$($TargetGroup.sAMAccountName)' has $($CurrentMembers.Count) members" -Class Note
                            Show-Line "Use -Force to confirm removal of all members" -Class Note
                        }
                    }
                    else {
                        try {
                            # Clear all members via ModifyRequest
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $GroupDN

                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "member"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete

                            $ModifyRequest.Modifications.Add($Modification) | Out-Null

                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }

                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearMembers"
                                    Group = $TargetGroup.sAMAccountName
                                    DistinguishedName = $GroupDN
                                    RemovedCount = $CurrentMembers.Count
                                    Success = $true
                                    Message = "Removed all $($CurrentMembers.Count) member(s)"
                                }
                            } else {
                                Show-Line "Successfully removed all $($CurrentMembers.Count) member(s) from: $($TargetGroup.sAMAccountName)" -Class Hint
                            }
                        } catch {
                            throw "Failed to clear members: $_"
                        }
                    }
                }

                # ===== Description Operations =====
                'SetDescription' {
                    Write-Log "[Set-DomainGroup] Setting description for: $($TargetGroup.sAMAccountName)"

                    try {
                        $CurrentDescription = $TargetGroup.description
                        Write-Log "[Set-DomainGroup] Current description: $CurrentDescription"

                        if ($CurrentDescription -eq $SetDescription) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetDescription"
                                    Group = $TargetGroup.sAMAccountName
                                    DistinguishedName = $GroupDN
                                    Success = $true
                                    Message = "Description already set to this value (no change)"
                                }
                            } else {
                                Show-Line "Description already set to this value: $($TargetGroup.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            # Set description via ModifyRequest
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $GroupDN

                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "description"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add($SetDescription) | Out-Null

                            $ModifyRequest.Modifications.Add($Modification) | Out-Null

                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }

                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "SetDescription"
                                    Group = $TargetGroup.sAMAccountName
                                    DistinguishedName = $GroupDN
                                    OldDescription = $CurrentDescription
                                    NewDescription = $SetDescription
                                    Success = $true
                                    Message = "Description updated"
                                }
                            } else {
                                Show-Line "Successfully set description for: $($TargetGroup.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to set description: $_"
                    }
                }

                'ClearDescription' {
                    Write-Log "[Set-DomainGroup] Clearing description for: $($TargetGroup.sAMAccountName)"

                    try {
                        $CurrentDescription = $TargetGroup.description

                        if (-not $CurrentDescription) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearDescription"
                                    Group = $TargetGroup.sAMAccountName
                                    DistinguishedName = $GroupDN
                                    Success = $true
                                    Message = "Description already empty (no change)"
                                }
                            } else {
                                Show-Line "Description already empty: $($TargetGroup.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            # Clear description via ModifyRequest
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $GroupDN

                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "description"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete

                            $ModifyRequest.Modifications.Add($Modification) | Out-Null

                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }

                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ClearDescription"
                                    Group = $TargetGroup.sAMAccountName
                                    DistinguishedName = $GroupDN
                                    OldDescription = $CurrentDescription
                                    Success = $true
                                    Message = "Description cleared"
                                }
                            } else {
                                Show-Line "Successfully cleared description for: $($TargetGroup.sAMAccountName)" -Class Hint
                            }
                        }
                    } catch {
                        throw "Failed to clear description: $_"
                    }
                }

                # ===== Group Type Conversion =====
                'ConvertToSecurity' {
                    Write-Log "[Set-DomainGroup] Converting to Security group: $($TargetGroup.sAMAccountName)"

                    try {
                        # Get current groupType
                        $CurrentGroupType = [int]$TargetGroup.groupType

                        Write-Log "[Set-DomainGroup] Current groupType: $CurrentGroupType (0x$($CurrentGroupType.ToString('X')))"

                        # groupType values:
                        # Global Security:       -2147483646 (0x80000002)
                        # DomainLocal Security:  -2147483644 (0x80000004)
                        # Universal Security:    -2147483640 (0x80000008)
                        # Global Distribution:    2 (0x2)
                        # DomainLocal Distribution: 4 (0x4)
                        # Universal Distribution:   8 (0x8)

                        # SECURITY_ENABLED = 0x80000000 (-2147483648)
                        $SECURITY_ENABLED = [int]0x80000000

                        # Check if already a security group
                        if (($CurrentGroupType -band $SECURITY_ENABLED) -ne 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ConvertToSecurity"
                                    Group = $TargetGroup.sAMAccountName
                                    DistinguishedName = $GroupDN
                                    Success = $true
                                    Message = "Group is already a Security group (no change)"
                                }
                            } else {
                                Show-Line "Group is already a Security group: $($TargetGroup.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            # Add SECURITY_ENABLED flag
                            $NewGroupType = $CurrentGroupType -bor $SECURITY_ENABLED
                            Write-Log "[Set-DomainGroup] New groupType: $NewGroupType (0x$($NewGroupType.ToString('X')))"

                            # Set groupType via ModifyRequest
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $GroupDN

                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "groupType"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add([string]$NewGroupType) | Out-Null

                            $ModifyRequest.Modifications.Add($Modification) | Out-Null

                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }

                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ConvertToSecurity"
                                    Group = $TargetGroup.sAMAccountName
                                    DistinguishedName = $GroupDN
                                    OldGroupType = $CurrentGroupType
                                    NewGroupType = $NewGroupType
                                    Success = $true
                                    Message = "Converted to Security group - can now be used for permissions"
                                }
                            } else {
                                Show-Line "Successfully converted to Security group: $($TargetGroup.sAMAccountName)" -Class Hint
                                Show-Line "Group can now be used for permission assignments!" -Class Finding
                            }
                        }
                    } catch {
                        throw "Failed to convert to Security group: $_"
                    }
                }

                'ConvertToDistribution' {
                    Write-Log "[Set-DomainGroup] Converting to Distribution group: $($TargetGroup.sAMAccountName)"

                    try {
                        # Get current groupType
                        $CurrentGroupType = [int]$TargetGroup.groupType

                        Write-Log "[Set-DomainGroup] Current groupType: $CurrentGroupType (0x$($CurrentGroupType.ToString('X')))"

                        # SECURITY_ENABLED = 0x80000000 (-2147483648)
                        $SECURITY_ENABLED = [int]0x80000000

                        # Check if already a distribution group
                        if (($CurrentGroupType -band $SECURITY_ENABLED) -eq 0) {
                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ConvertToDistribution"
                                    Group = $TargetGroup.sAMAccountName
                                    DistinguishedName = $GroupDN
                                    Success = $true
                                    Message = "Group is already a Distribution group (no change)"
                                }
                            } else {
                                Show-Line "Group is already a Distribution group: $($TargetGroup.sAMAccountName)" -Class Note
                            }
                        }
                        else {
                            # Remove SECURITY_ENABLED flag
                            $NewGroupType = $CurrentGroupType -band (-bnot $SECURITY_ENABLED)
                            Write-Log "[Set-DomainGroup] New groupType: $NewGroupType (0x$($NewGroupType.ToString('X')))"

                            # Set groupType via ModifyRequest
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $GroupDN

                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "groupType"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add([string]$NewGroupType) | Out-Null

                            $ModifyRequest.Modifications.Add($Modification) | Out-Null

                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }

                            if ($PassThru) {
                                return [PSCustomObject]@{
                                    Operation = "ConvertToDistribution"
                                    Group = $TargetGroup.sAMAccountName
                                    DistinguishedName = $GroupDN
                                    OldGroupType = $CurrentGroupType
                                    NewGroupType = $NewGroupType
                                    Success = $true
                                    Message = "Converted to Distribution group - can no longer be used for permissions"
                                }
                            } else {
                                Show-Line "Successfully converted to Distribution group: $($TargetGroup.sAMAccountName)" -Class Hint
                                Show-Line "Group can no longer be used for permissions (effectively disarmed)!" -Class Finding
                            }
                        }
                    } catch {
                        throw "Failed to convert to Distribution group: $_"
                    }
                }

                'SetOwner' {
                    Write-Log "[Set-DomainGroup] Setting owner for: $($TargetGroup.sAMAccountName)"

                    try {
                        $Result = Set-DomainObject -Identity $GroupDN -SetOwner -Principal $Owner @ConnectionParams

                        # Check for explicit failure or null result
                        if ($null -eq $Result) {
                            throw "Set-DomainObject returned no result - operation may have failed silently"
                        }
                        if ($Result -is [PSCustomObject] -and $Result.PSObject.Properties['Success'] -and -not $Result.Success) {
                            throw "Set-DomainObject failed: $($Result.Message)"
                        }
                        if ($Result -eq $false) {
                            throw "Set-DomainObject returned false"
                        }

                        if ($PassThru) {
                            return [PSCustomObject]@{
                                Operation = "SetOwner"
                                Group = $TargetGroup.sAMAccountName
                                DistinguishedName = $GroupDN
                                NewOwner = $Owner
                                Success = $true
                                Message = "Owner successfully changed"
                            }
                        } else {
                            Show-Line "Successfully changed owner of $($TargetGroup.sAMAccountName) to: $Owner" -Class Hint
                        }
                    } catch {
                        throw "Failed to set owner: $_"
                    }
                }

                'GrantRights' {
                    Write-Log "[Set-DomainGroup] Granting $GrantRights rights to $Principal on: $($TargetGroup.sAMAccountName)"

                    try {
                        # Map GrantRights to either Rights or ExtendedRight and call Set-DomainObject
                        $Result = switch ($GrantRights) {
                            'GenericAll'   { Set-DomainObject -Identity $GroupDN -GrantACE -Principal $Principal -Rights GenericAll @ConnectionParams }
                            'GenericWrite' { Set-DomainObject -Identity $GroupDN -GrantACE -Principal $Principal -Rights GenericWrite @ConnectionParams }
                            'WriteDacl'    { Set-DomainObject -Identity $GroupDN -GrantACE -Principal $Principal -Rights WriteDacl @ConnectionParams }
                            'WriteOwner'   { Set-DomainObject -Identity $GroupDN -GrantACE -Principal $Principal -Rights WriteOwner @ConnectionParams }
                            'WriteMembers' { Set-DomainObject -Identity $GroupDN -GrantACE -Principal $Principal -ExtendedRight AddMember @ConnectionParams }
                        }

                        # Check for explicit failure or null result
                        if ($null -eq $Result) {
                            throw "Set-DomainObject returned no result - operation may have failed silently"
                        }
                        if ($Result -is [PSCustomObject] -and $Result.PSObject.Properties['Success'] -and -not $Result.Success) {
                            throw "Set-DomainObject failed: $($Result.Message)"
                        }
                        if ($Result -eq $false) {
                            throw "Set-DomainObject returned false"
                        }

                        if ($PassThru) {
                            return [PSCustomObject]@{
                                Operation = "GrantRights"
                                Group = $TargetGroup.sAMAccountName
                                DistinguishedName = $GroupDN
                                Principal = $Principal
                                Rights = $GrantRights
                                Success = $true
                                Message = "Rights successfully granted"
                            }
                        } else {
                            Show-Line "Successfully granted $GrantRights to $Principal on: $($TargetGroup.sAMAccountName)" -Class Hint
                        }
                    } catch {
                        throw "Failed to grant rights: $_"
                    }
                }
            }

        } catch {
            Write-Log "[Set-DomainGroup] Error: $_"

            if ($PassThru) {
                return [PSCustomObject]@{
                    Operation = $PSCmdlet.ParameterSetName
                    Group = $Identity
                    Success = $false
                    Message = $_.Exception.Message
                }
            } else {
                Write-Error "[Set-DomainGroup] $($_.Exception.Message)"
            }
        } finally {
            # No cleanup needed - ModifyRequest does not create persistent objects
        }
    }

    end {
        Write-Log "[Set-DomainGroup] Group modification completed"
    }
}
