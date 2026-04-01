function Set-DomainObject {
<#
.SYNOPSIS
    Universal function for modifying ANY Active Directory object (attributes and ACLs).

.DESCRIPTION
    Set-DomainObject is a flexible helper function that can modify ANY AD object attribute AND Access Control Lists (ACLs) without needing to know the object
    class beforehand. It supports:

    ATTRIBUTE OPERATIONS:
    - Set/Replace/Append/Remove/Clear attribute operations
    - Multiple attributes in single operation

    ACL OPERATIONS:
    - Grant ACE (Allow permissions)
    - Revoke ACE (Remove permissions)
    - Deny ACE (Explicit deny)
    - Set Owner (Change object ownership)
    - Clear ACE (Remove all ACEs for a principal)

.PARAMETER Identity
    sAMAccountName, DistinguishedName, SID, ObjectGUID, or DOMAIN\name format.
    Identifies the object to modify.

.PARAMETER Set
    Hashtable of attributes to SET (replace existing values).
    Example: @{ description = "New description"; info = "Additional info" }

.PARAMETER Append
    Hashtable of attributes to APPEND (add to existing multi-valued attributes).
    Example: @{ servicePrincipalName = "HTTP/server.contoso.com" }

.PARAMETER Remove
    Hashtable of attributes to REMOVE (remove specific values).
    Example: @{ memberOf = "CN=OldGroup,DC=contoso,DC=com" }

.PARAMETER Clear
    Array of attribute names to CLEAR (remove all values).
    Example: @("description", "info")

.PARAMETER GrantACE
    Switch to grant (Allow) permissions on the object.
    Requires -Principal and either -Rights or -ExtendedRight.

.PARAMETER RevokeACE
    Switch to revoke (remove) permissions from the object.
    Requires -Principal and either -Rights or -ExtendedRight.

.PARAMETER DenyACE
    Switch to add explicit Deny permissions on the object.
    Requires -Principal and either -Rights or -ExtendedRight.

.PARAMETER SetOwner
    Switch to change the object's owner.
    Requires -Principal parameter.

.PARAMETER ClearACE
    Switch to remove ALL ACEs for a specific principal.
    Requires -Principal parameter.

.PARAMETER Principal
    Security principal (user/group) for ACE operations.
    Format: "DOMAIN\name", "name@domain.com", or DN.

.PARAMETER Rights
    ActiveDirectory rights to grant/revoke/deny.
    Valid values: GenericAll, GenericRead, GenericWrite, WriteDacl, WriteOwner,
                  CreateChild, DeleteChild, ReadProperty, WriteProperty, etc.

.PARAMETER ExtendedRight
    Extended right to grant/revoke/deny (user-friendly aliases supported).

    Common aliases:
    - DCSync              : All 3 DCSync rights (Get-Changes, Get-Changes-All, Get-Changes-In-Filtered-Set)
    - ForceChangePassword : Reset user password
    - AddMember           : Add members to group
    - SendAs              : Send email as another user
    - ReceiveAs           : Receive email as another user
    - ReadLAPSPassword    : Read LAPS password
    - AutoEnroll          : Certificate auto-enrollment

.PARAMETER Domain
    Target domain (FQDN). If not specified, uses current session or user's domain.

.PARAMETER Server
    Specific Domain Controller to connect to. If not specified, auto-discovery.

.PARAMETER Credential
    PSCredential object for authentication.

.PARAMETER PassThru
    Returns a result object instead of only console output.
    Useful for scripting and automation.

.EXAMPLE
    Set-DomainObject -Identity "CN=Brad Pitt,OU=Users,DC=contoso,DC=com" -Set @{ description = "Actor" }
    Sets the description attribute on the user object.

.EXAMPLE
    Set-DomainObject -Identity "DC=contoso,DC=com" -GrantACE -Principal "CONTOSO\BackupAdmin" -ExtendedRight "DCSync"
    Grants DCSync rights (all 3 required permissions) to BackupAdmin on the domain root.

.EXAMPLE
    Set-DomainObject -Identity "CN=TargetUser,OU=Users,DC=contoso,DC=com" -GrantACE -Principal "CONTOSO\HelpDesk" -ExtendedRight "ForceChangePassword"
    Allows HelpDesk group to reset TargetUser's password.

.EXAMPLE
    Set-DomainObject -Identity "CN=Domain Admins,CN=Users,DC=contoso,DC=com" -GrantACE -Principal "CONTOSO\attacker" -Rights "WriteDacl"
    Grants WriteDacl permission (allows modifying ACL of Domain Admins group).

.EXAMPLE
    Set-DomainObject -Identity "OU=Servers,DC=contoso,DC=com" -SetOwner -Principal "CONTOSO\IT-Admins"
    Changes the owner of the Servers OU to IT-Admins group.

.EXAMPLE
    Set-DomainObject -Identity "CN=krbtgt,CN=Users,DC=contoso,DC=com" -DenyACE -Principal "NT AUTHORITY\Authenticated Users" -Rights "WriteProperty"
    Adds explicit Deny for WriteProperty on krbtgt account.

.EXAMPLE
    Set-DomainObject -Identity "CN=CEO,OU=VIP,DC=contoso,DC=com" -GrantACE -Principal "CONTOSO\attacker" -ExtendedRight "SendAs"
    Allows attacker to send emails as the CEO.

.OUTPUTS
    Boolean - $true if successful, $false if failed.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding(DefaultParameterSetName='SetAttributes')]
    param(
        # === Object Identity ===
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('distinguishedName', 'Name', 'sAMAccountName')]
        [string]$Identity,

        # === Attribute Modification Parameters (SetAttributes ParameterSet) ===
        [Parameter(Mandatory=$false, ParameterSetName='SetAttributes')]
        [hashtable]$Set,

        [Parameter(Mandatory=$false, ParameterSetName='SetAttributes')]
        [hashtable]$Append,

        [Parameter(Mandatory=$false, ParameterSetName='SetAttributes')]
        [hashtable]$Remove,

        [Parameter(Mandatory=$false, ParameterSetName='SetAttributes')]
        [string[]]$Clear,

        # === ACE Operation Switches (mutually exclusive) ===
        [Parameter(Mandatory=$true, ParameterSetName='GrantACE')]
        [switch]$GrantACE,

        [Parameter(Mandatory=$true, ParameterSetName='RevokeACE')]
        [switch]$RevokeACE,

        [Parameter(Mandatory=$true, ParameterSetName='DenyACE')]
        [switch]$DenyACE,

        [Parameter(Mandatory=$true, ParameterSetName='ClearACE')]
        [switch]$ClearACE,

        [Parameter(Mandatory=$true, ParameterSetName='SetOwner')]
        [switch]$SetOwner,

        # === ACE Parameters ===
        [Parameter(Mandatory=$true, ParameterSetName='GrantACE')]
        [Parameter(Mandatory=$true, ParameterSetName='RevokeACE')]
        [Parameter(Mandatory=$true, ParameterSetName='DenyACE')]
        [Parameter(Mandatory=$true, ParameterSetName='ClearACE')]
        [Parameter(Mandatory=$true, ParameterSetName='SetOwner')]
        [string]$Principal,

        # Rights (for GrantACE/RevokeACE/DenyACE)
        [Parameter(Mandatory=$false, ParameterSetName='GrantACE')]
        [Parameter(Mandatory=$false, ParameterSetName='RevokeACE')]
        [Parameter(Mandatory=$false, ParameterSetName='DenyACE')]
        [ValidateSet(
            'GenericAll', 'GenericRead', 'GenericWrite', 'GenericExecute',
            'Delete', 'ReadControl', 'WriteDacl', 'WriteOwner',
            'CreateChild', 'DeleteChild', 'ListChildren', 'Self',
            'ReadProperty', 'WriteProperty', 'DeleteTree', 'ListObject',
            'ExtendedRight', 'ControlAccess'
        )]
        [string]$Rights,

        # ExtendedRight (alternative to Rights - user-friendly aliases)
        [Parameter(Mandatory=$false, ParameterSetName='GrantACE')]
        [Parameter(Mandatory=$false, ParameterSetName='RevokeACE')]
        [Parameter(Mandatory=$false, ParameterSetName='DenyACE')]
        [ValidateSet(
            # Critical Red Team Rights
            'DCSync', 'ForceChangePassword', 'ResetPassword', 'AddMember',
            # Exchange
            'SendAs', 'ReceiveAs',
            # LAPS
            'ReadLAPSPassword',
            # Certificates
            'AutoEnroll', 'CertEnroll',
            # Kerberos
            'AllowedToAuthenticate',
            # Replication
            'ReplicateDirectory', 'InstallReplica', 'CloneDC',
            # SID History
            'MigrateSIDHistory',
            # GPO
            'ApplyGroupPolicy', 'CreateGPOLink',
            # RSoP
            'GenerateRSoPLogging', 'GenerateRSoPPlanning',
            # Tombstone
            'ReanimateTombstones',
            # Self Membership
            'SelfMembership',
            # Dangerous
            'AllExtendedRights'
        )]
        [string]$ExtendedRight,

        # === Connection Parameters ===
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$PassThru,

        [Parameter(Mandatory=$false)]
        [string]$SearchBase
    )

    begin {
        Write-Log "[Set-DomainObject] Starting object modification (ParameterSet: $($PSCmdlet.ParameterSetName))"

        if ($PSCmdlet.ParameterSetName -in @('GrantACE', 'RevokeACE', 'DenyACE')) {
            if (-not $Rights -and -not $ExtendedRight) {
                throw "[Set-DomainObject] $($PSCmdlet.ParameterSetName) requires either -Rights or -ExtendedRight parameter"
            }
        }
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
                    Object = $Identity
                    Success = $false
                    Message = "No LDAP connection available"
                }
            }
            return $false
        }

        try {
            $Filter = "(objectClass=*)"
            $crossDomainQuery = $false
            $targetDomainDN = $null
            $targetDomainFQDN = $null

            if ($Identity) {
                # Detect DOMAIN\name format and handle cross-domain queries
                if ($Identity -match '^([^\\]+)\\(.+)$') {
                    Write-Log "[Set-DomainObject] Detecting cross-domain format: $Identity"

                    # Use centralized cross-domain resolution
                    $crossDomainInfo = Resolve-CrossDomainIdentity -Identity $Identity
                    $crossDomainQuery = $crossDomainInfo.IsCrossDomain
                    $targetDomainDN = $crossDomainInfo.TargetDomainDN
                    $targetDomainFQDN = $crossDomainInfo.TargetDomainFQDN

                    # Use the extracted identity (without domain prefix)
                    $Identity = $crossDomainInfo.Identity

                    if ($crossDomainQuery) {
                        Write-Log "[Set-DomainObject] Cross-domain query detected: Target domain = $targetDomainFQDN"
                    }
                }

                # Check if SID, DN, GUID, or sAMAccountName
                if ($Identity -match '^S-1-5-.*') {
                    # SID Format - convert to hex for LDAP
                    $SIDObj = New-Object System.Security.Principal.SecurityIdentifier($Identity)
                    $SIDBytes = New-Object byte[] $SIDObj.BinaryLength
                    $SIDObj.GetBinaryForm($SIDBytes, 0)
                    $SIDHex = ($SIDBytes | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter = "(objectSid=$SIDHex)"
                } elseif ($Identity -match '^CN=.*|^OU=.*|^DC=.*') {
                    # Distinguished Name
                    $IdentityFilter = "(distinguishedName=$Identity)"
                } elseif ($Identity -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
                    # GUID Format
                    $GUIDObj = [System.Guid]::Parse($Identity)
                    $GUIDBytes = $GUIDObj.ToByteArray()
                    $GUIDHex = ($GUIDBytes | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter = "(objectGUID=$GUIDHex)"
                } else {
                    # sAMAccountName (with wildcard support)
                    $IdentityFilter = "(|(sAMAccountName=$Identity)(cn=$Identity)(name=$Identity))"
                }

                $Filter = "(&$Filter$IdentityFilter)"
            }

            Write-Log "[Set-DomainObject] Using filter: $Filter"

            # ACL MODIFICATION LOGIC - use Raw query directly to avoid double query
            if ($PSCmdlet.ParameterSetName -ne 'SetAttributes') {
                Write-Log "[Set-DomainObject] Processing ACL modification: $($PSCmdlet.ParameterSetName)"

                # Single LDAP query with Raw for ACL operations
                $SearchParams = @{
                    Filter = $Filter
                    Properties = @('distinguishedName', 'nTSecurityDescriptor')
                    SizeLimit = 10  # Increased for cross-domain (may return multiple before filtering)
                    Raw = $true
                }

                # For cross-domain queries, use Global Catalog
                if ($crossDomainQuery) {
                    $gcConn = Get-GCConnection
                    if ($gcConn) {
                        Write-Log "[Set-DomainObject] Using GC connection for cross-domain query"
                        $SearchParams['LdapConnection'] = $gcConn
                        $SearchParams['SearchBase'] = $targetDomainDN
                    } else {
                        Write-Log "[Set-DomainObject] GC connection unavailable - cross-domain query may fail" -Level Warning
                    }
                } elseif ($SearchBase) {
                    $SearchParams['SearchBase'] = $SearchBase
                    Write-Log "[Set-DomainObject] Using custom SearchBase: $SearchBase"
                }

                $SearchResult = Invoke-LDAPSearch @SearchParams

                # Post-filter for cross-domain queries (exclude child domains)
                if ($crossDomainQuery -and $targetDomainFQDN -and $SearchResult) {
                    $ResultArray = @($SearchResult)
                    $FilteredResults = @()

                    foreach ($res in $ResultArray) {
                        if ($res.distinguishedName) {
                            if (Test-DomainMatch -DistinguishedName $res.distinguishedName -TargetDomainFQDN $targetDomainFQDN) {
                                $FilteredResults += $res
                            }
                        }
                    }

                    $SearchResult = $FilteredResults
                    Write-Log "[Set-DomainObject] After cross-domain filter: $($SearchResult.Count) result(s)"
                }

                # Ensure single result
                $SearchResult = @($SearchResult)[0]

                if (-not $SearchResult) {
                    Write-Error "[Set-DomainObject] Object not found: $Identity"
                    return $false
                }

                $ResultArray = @($SearchResult)
                $ObjectDN = $ResultArray[0].distinguishedName
                Write-Log "[Set-DomainObject] Found object: $ObjectDN"

                # Resolve Principal to SecurityIdentifier
                $PrincipalSID = $null
                $ResolvedSIDString = ConvertTo-SID -Identity $Principal

                if ($ResolvedSIDString) {
                    $PrincipalSID = New-Object System.Security.Principal.SecurityIdentifier($ResolvedSIDString)
                    Write-Log "[Set-DomainObject] Resolved principal '$Principal' to SID: $ResolvedSIDString"
                } else {
                    Write-Error "[Set-DomainObject] Failed to resolve principal '$Principal' - ensure the identity exists in AD"
                    return $false
                }

                # Get Security Descriptor from raw result
                if (-not $ResultArray[0].nTSecurityDescriptor) {
                    Write-Error "[Set-DomainObject] Failed to retrieve Security Descriptor for: $ObjectDN"
                    return $false
                }

                # Create ActiveDirectorySecurity object from binary SD
                $ACL = New-Object System.DirectoryServices.ActiveDirectorySecurity
                $ACL.SetSecurityDescriptorBinaryForm($ResultArray[0].nTSecurityDescriptor)
                Write-Log "[Set-DomainObject] Retrieved current ACL from object via nTSecurityDescriptor"

                # Track ACE operations for feedback
                $ACEsAdded = 0
                $ACEsRemoved = 0

                # Process based on operation type
                switch ($PSCmdlet.ParameterSetName) {
                    'GrantACE' {
                        Write-Log "[Set-DomainObject] Processing GrantACE operation"
                        $ACEsAdded = Add-ACEToACL -ACL $ACL -PrincipalSID $PrincipalSID -Rights $Rights -ExtendedRight $ExtendedRight -AccessType 'Allow' -Operation 'Add'
                    }

                    'RevokeACE' {
                        Write-Log "[Set-DomainObject] Processing RevokeACE operation"
                        $ACEsRemoved = Add-ACEToACL -ACL $ACL -PrincipalSID $PrincipalSID -Rights $Rights -ExtendedRight $ExtendedRight -AccessType 'Allow' -Operation 'Remove'
                    }

                    'DenyACE' {
                        Write-Log "[Set-DomainObject] Processing DenyACE operation"
                        $ACEsAdded = Add-ACEToACL -ACL $ACL -PrincipalSID $PrincipalSID -Rights $Rights -ExtendedRight $ExtendedRight -AccessType 'Deny' -Operation 'Add'
                    }

                    'ClearACE' {
                        Write-Log "[Set-DomainObject] Processing ClearACE operation (removing all ACEs for principal)"

                        # Get all ACEs for this principal
                        $ACEs = $ACL.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

                        foreach ($ACE in $ACEs) {
                            if ($ACE.IdentityReference -eq $PrincipalSID) {
                                $removed = $ACL.RemoveAccessRule($ACE)
                                if ($removed) {
                                    $ACEsRemoved++
                                }
                            }
                        }

                        Write-Log "[Set-DomainObject] Removed $ACEsRemoved ACE(s) for principal $Principal"
                    }

                    'SetOwner' {
                        Write-Log "[Set-DomainObject] Processing SetOwner operation"

                        $ACL.SetOwner($PrincipalSID)
                        Write-Log "[Set-DomainObject] Set owner to: $Principal ($($PrincipalSID.Value))"
                    }
                }

                # Commit ACL changes via ModifyRequest (unified LdapConnection architecture)
                try {
                    # Convert modified ACL back to binary Security Descriptor
                    $SDBytes = $ACL.GetSecurityDescriptorBinaryForm()

                    # Create ModifyRequest for nTSecurityDescriptor
                    $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                    $ModifyRequest.DistinguishedName = $ObjectDN

                    # Create attribute modification for nTSecurityDescriptor
                    $SDModification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                    $SDModification.Name = "nTSecurityDescriptor"
                    $SDModification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                    $SDModification.Add($SDBytes) | Out-Null

                    $ModifyRequest.Modifications.Add($SDModification) | Out-Null

                    # Send the request via LdapConnection
                    $Response = $Script:LdapConnection.SendRequest($ModifyRequest)

                    if ($Response.ResultCode -eq [System.DirectoryServices.Protocols.ResultCode]::Success) {
                        Write-Log "[Set-DomainObject] Successfully committed ACL changes to AD via ModifyRequest"

                        # Build appropriate message based on operation
                        $OperationMsg = switch ($PSCmdlet.ParameterSetName) {
                            'GrantACE'  { "Granted $ACEsAdded ACE(s) on object: $ObjectDN" }
                            'RevokeACE' { "Revoked $ACEsRemoved ACE(s) from object: $ObjectDN" }
                            'DenyACE'   { "Added $ACEsAdded Deny ACE(s) on object: $ObjectDN" }
                            'ClearACE'  { "Removed $ACEsRemoved ACE(s) for principal '$Principal' on object: $ObjectDN" }
                            'SetOwner'  { "Changed owner to '$Principal' on object: $ObjectDN" }
                        }

                        if ($PassThru) {
                            return [PSCustomObject]@{
                                Operation = $PSCmdlet.ParameterSetName
                                Object = $ObjectDN
                                Principal = $Principal
                                ACEsAdded = $ACEsAdded
                                ACEsRemoved = $ACEsRemoved
                                Success = $true
                                Message = $OperationMsg
                            }
                        } else {
                            Show-Line $OperationMsg -Class Hint
                        }
                        return $true
                    } else {
                        Write-Log "[Set-DomainObject] ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                        if ($PassThru) {
                            return [PSCustomObject]@{
                                Operation = $PSCmdlet.ParameterSetName
                                Object = $ObjectDN
                                Success = $false
                                Message = "ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }
                        }
                        return $false
                    }
                } catch {
                    Write-Log "[Set-DomainObject] Failed to commit ACL changes: $_"
                    if ($PassThru) {
                        return [PSCustomObject]@{
                            Operation = $PSCmdlet.ParameterSetName
                            Object = $ObjectDN
                            Success = $false
                            Message = $_.Exception.Message
                        }
                    }
                    return $false
                }
            }

            # ATTRIBUTE MODIFICATION LOGIC - find object first
            $SearchParams = @{
                Filter = $Filter
                Properties = @('distinguishedName')
                SizeLimit = 10  # Increased for cross-domain (may return multiple before filtering)
            }

            # For cross-domain queries, use Global Catalog
            if ($crossDomainQuery) {
                $gcConn = Get-GCConnection
                if ($gcConn) {
                    Write-Log "[Set-DomainObject] Using GC connection for cross-domain query"
                    $SearchParams['LdapConnection'] = $gcConn
                    $SearchParams['SearchBase'] = $targetDomainDN
                } else {
                    Write-Log "[Set-DomainObject] GC connection unavailable - cross-domain query may fail" -Level Warning
                }
            } elseif ($SearchBase) {
                $SearchParams['SearchBase'] = $SearchBase
                Write-Log "[Set-DomainObject] Using custom SearchBase: $SearchBase"
            }

            $SearchResult = Invoke-LDAPSearch @SearchParams

            # Post-filter for cross-domain queries (exclude child domains)
            if ($crossDomainQuery -and $targetDomainFQDN -and $SearchResult) {
                $ResultArray = @($SearchResult)
                $FilteredResults = @()

                foreach ($res in $ResultArray) {
                    if ($res.distinguishedName) {
                        if (Test-DomainMatch -DistinguishedName $res.distinguishedName -TargetDomainFQDN $targetDomainFQDN) {
                            $FilteredResults += $res
                        }
                    }
                }

                $SearchResult = $FilteredResults
                Write-Log "[Set-DomainObject] After cross-domain filter: $($SearchResult.Count) result(s)"
            }

            # Ensure single result
            $SearchResult = @($SearchResult)[0]

            if (-not $SearchResult) {
                Write-Error "[Set-DomainObject] Object not found: $Identity"
                return $false
            }

            # Ensure we have a single result
            $ResultArray = @($SearchResult)
            $ObjectDN = $ResultArray[0].distinguishedName
            Write-Log "[Set-DomainObject] Found object: $ObjectDN"

            # Build ModifyRequest with all attribute modifications
            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
            $ModifyRequest.DistinguishedName = $ObjectDN
            $ModificationsAdded = $false

            # === SET Operation (Replace values) ===
            if ($Set -and $Set.Count -gt 0) {
                Write-Log "[Set-DomainObject] Processing SET operation on $($Set.Count) attribute(s)"

                foreach ($AttrName in $Set.Keys) {
                    $AttrValue = $Set[$AttrName]

                    try {
                        $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                        $Modification.Name = $AttrName
                        $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace

                        # Add value(s) to modification
                        if ($AttrValue -is [array]) {
                            foreach ($item in $AttrValue) {
                                $Modification.Add($item) | Out-Null
                            }
                            Write-Log "[Set-DomainObject] Set $AttrName = $AttrValue (array with $($AttrValue.Count) items)"
                        } else {
                            $Modification.Add($AttrValue) | Out-Null
                            Write-Log "[Set-DomainObject] Set $AttrName = $AttrValue"
                        }

                        $ModifyRequest.Modifications.Add($Modification) | Out-Null
                        $ModificationsAdded = $true
                    } catch {
                        Write-Warning "[Set-DomainObject] Failed to prepare SET for ${AttrName}: $_"
                    }
                }
            }

            # === APPEND Operation (Add to multi-valued attributes) ===
            if ($Append -and $Append.Count -gt 0) {
                Write-Log "[Set-DomainObject] Processing APPEND operation on $($Append.Count) attribute(s)"

                foreach ($AttrName in $Append.Keys) {
                    $AttrValue = $Append[$AttrName]

                    try {
                        $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                        $Modification.Name = $AttrName
                        $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Add

                        if ($AttrValue -is [array]) {
                            foreach ($item in $AttrValue) {
                                $Modification.Add($item) | Out-Null
                            }
                            Write-Log "[Set-DomainObject] Appended $AttrName += $AttrValue (array with $($AttrValue.Count) items)"
                        } else {
                            $Modification.Add($AttrValue) | Out-Null
                            Write-Log "[Set-DomainObject] Appended $AttrName += $AttrValue"
                        }

                        $ModifyRequest.Modifications.Add($Modification) | Out-Null
                        $ModificationsAdded = $true
                    } catch {
                        Write-Warning "[Set-DomainObject] Failed to prepare APPEND for ${AttrName}: $_"
                    }
                }
            }

            # === REMOVE Operation (Remove specific values from multi-valued attributes) ===
            if ($Remove -and $Remove.Count -gt 0) {
                Write-Log "[Set-DomainObject] Processing REMOVE operation on $($Remove.Count) attribute(s)"

                foreach ($AttrName in $Remove.Keys) {
                    $AttrValue = $Remove[$AttrName]

                    try {
                        $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                        $Modification.Name = $AttrName
                        $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete

                        if ($AttrValue -is [array]) {
                            foreach ($item in $AttrValue) {
                                $Modification.Add($item) | Out-Null
                            }
                            Write-Log "[Set-DomainObject] Removed $AttrName -= $AttrValue (array with $($AttrValue.Count) items)"
                        } else {
                            $Modification.Add($AttrValue) | Out-Null
                            Write-Log "[Set-DomainObject] Removed $AttrName -= $AttrValue"
                        }

                        $ModifyRequest.Modifications.Add($Modification) | Out-Null
                        $ModificationsAdded = $true
                    } catch {
                        Write-Warning "[Set-DomainObject] Failed to prepare REMOVE for ${AttrName}: $_"
                    }
                }
            }

            # === CLEAR Operation (Remove all values) ===
            if ($Clear -and $Clear.Count -gt 0) {
                Write-Log "[Set-DomainObject] Processing CLEAR operation on $($Clear.Count) attribute(s)"

                foreach ($AttrName in $Clear) {
                    try {
                        $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                        $Modification.Name = $AttrName
                        # Delete without values = clear all values
                        $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete

                        $ModifyRequest.Modifications.Add($Modification) | Out-Null
                        Write-Log "[Set-DomainObject] Cleared $AttrName"
                        $ModificationsAdded = $true
                    } catch {
                        Write-Warning "[Set-DomainObject] Failed to prepare CLEAR for ${AttrName}: $_"
                    }
                }
            }

            # Send ModifyRequest if any modifications were added
            if ($ModificationsAdded) {
                try {
                    $Response = $Script:LdapConnection.SendRequest($ModifyRequest)

                    if ($Response.ResultCode -eq [System.DirectoryServices.Protocols.ResultCode]::Success) {
                        Write-Log "[Set-DomainObject] Successfully committed attribute changes to AD via ModifyRequest"
                        if ($PassThru) {
                            return [PSCustomObject]@{
                                Operation = "SetAttributes"
                                Object = $ObjectDN
                                Success = $true
                                Message = "Attributes successfully modified"
                            }
                        }
                        return $true
                    } else {
                        Write-Error "[Set-DomainObject] ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                        if ($PassThru) {
                            return [PSCustomObject]@{
                                Operation = "SetAttributes"
                                Object = $ObjectDN
                                Success = $false
                                Message = "ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }
                        }
                        return $false
                    }
                } catch {
                    Write-Error "[Set-DomainObject] Failed to commit changes: $_"
                    if ($PassThru) {
                        return [PSCustomObject]@{
                            Operation = "SetAttributes"
                            Object = $ObjectDN
                            Success = $false
                            Message = $_.Exception.Message
                        }
                    }
                    return $false
                }
            } else {
                # No modifications requested - this is a no-op, not a success
                Write-Log "[Set-DomainObject] No attribute modifications specified"
                if ($PassThru) {
                    return [PSCustomObject]@{
                        Operation = "SetAttributes"
                        Object = $ObjectDN
                        Success = $true
                        NoOp = $true
                        Message = "No modifications specified"
                    }
                }
                Show-Line "No modifications specified for object: $ObjectDN" -Class Note
                return $true
            }

        } catch {
            Write-Error "[Set-DomainObject] Error: $_"
            if ($PassThru) {
                return [PSCustomObject]@{
                    Operation = $PSCmdlet.ParameterSetName
                    Object = $Identity
                    Success = $false
                    Message = $_.Exception.Message
                }
            }
            return $false
        }
    }

    end {
        Write-Log "[Set-DomainObject] Object modification completed"
    }
}

<#
.SYNOPSIS
    Internal helper function to add/remove ACE to/from an ACL.

.DESCRIPTION
    Consolidates the duplicated ACE creation logic from GrantACE, RevokeACE, and DenyACE operations.
    Handles ReadProperty aliases, WriteProperty aliases, ExtendedRights, and standard Rights.

.PARAMETER ACL
    The ActiveDirectorySecurity object to modify.

.PARAMETER PrincipalSID
    The SecurityIdentifier of the principal.

.PARAMETER Rights
    Standard AD rights (GenericAll, WriteDacl, etc.).

.PARAMETER ExtendedRight
    ExtendedRight alias (DCSync, ForceChangePassword, etc.).

.PARAMETER AccessType
    'Allow' or 'Deny' for the ACE type.

.PARAMETER Operation
    'Add' to add ACE, 'Remove' to remove ACE.

.OUTPUTS
    Int - Number of ACEs added or removed.
#>
function Add-ACEToACL {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.DirectoryServices.ActiveDirectorySecurity]$ACL,

        [Parameter(Mandatory=$true)]
        [System.Security.Principal.SecurityIdentifier]$PrincipalSID,

        [Parameter(Mandatory=$false)]
        [string]$Rights,

        [Parameter(Mandatory=$false)]
        [string]$ExtendedRight,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Allow', 'Deny')]
        [string]$AccessType,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Add', 'Remove')]
        [string]$Operation
    )

    $ACECount = 0
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::$AccessType

    if ($ExtendedRight) {
        # Check if this is a ReadProperty alias (e.g., ReadLAPSPassword)
        $ReadPropertyGUID = $Script:ReadPropertyAliases[$ExtendedRight]

        if ($ReadPropertyGUID) {
            Write-Log "[Add-ACEToACL] '$ExtendedRight' is a ReadProperty alias (attribute GUID: $ReadPropertyGUID)"

            $ObjectType = New-Object Guid($ReadPropertyGUID)
            $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $PrincipalSID,
                [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,
                $AccessControlType,
                $ObjectType,
                [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
            )

            if ($Operation -eq 'Add') {
                $ACL.AddAccessRule($ACE)
                $ACECount++
                Write-Log "[Add-ACEToACL] Added $AccessType ACE for ReadProperty '$ExtendedRight'"
            } else {
                $removed = $ACL.RemoveAccessRule($ACE)
                if ($removed) {
                    $ACECount++
                    Write-Log "[Add-ACEToACL] Removed ACE for ReadProperty '$ExtendedRight'"
                } else {
                    Write-Log "[Add-ACEToACL] ACE for ReadProperty '$ExtendedRight' was not found - nothing removed"
                }
            }
        }
        # Check if this is a WriteProperty alias (e.g., AddMember, WriteMembers)
        elseif (($WritePropertyGUID = $Script:WritePropertyAliases[$ExtendedRight])) {
            Write-Log "[Add-ACEToACL] '$ExtendedRight' is a WriteProperty alias (attribute GUID: $WritePropertyGUID)"

            $ObjectType = New-Object Guid($WritePropertyGUID)
            $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $PrincipalSID,
                [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                $AccessControlType,
                $ObjectType,
                [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
            )

            if ($Operation -eq 'Add') {
                $ACL.AddAccessRule($ACE)
                $ACECount++
                Write-Log "[Add-ACEToACL] Added $AccessType ACE for WriteProperty '$ExtendedRight'"
            } else {
                $removed = $ACL.RemoveAccessRule($ACE)
                if ($removed) {
                    $ACECount++
                    Write-Log "[Add-ACEToACL] Removed ACE for WriteProperty '$ExtendedRight'"
                } else {
                    Write-Log "[Add-ACEToACL] ACE for WriteProperty '$ExtendedRight' was not found - nothing removed"
                }
            }
        } else {
            # Handle ExtendedRight with alias mapping
            $GUIDs = $Script:ExtendedRightsAliases[$ExtendedRight]

            if (-not $GUIDs) {
                Write-Error "[Add-ACEToACL] Unknown ExtendedRight alias: $ExtendedRight"
                return 0
            }

            # DCSync is special - it's an array of 3 GUIDs
            $GUIDList = if ($GUIDs -is [array]) { $GUIDs } else { @($GUIDs) }

            foreach ($GUID in $GUIDList) {
                $ObjectType = New-Object Guid($GUID)
                $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $PrincipalSID,
                    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                    $AccessControlType,
                    $ObjectType,
                    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
                )

                if ($Operation -eq 'Add') {
                    $ACL.AddAccessRule($ACE)
                    $ACECount++
                    Write-Log "[Add-ACEToACL] Added $AccessType ACE for ExtendedRight GUID: $GUID"
                } else {
                    $removed = $ACL.RemoveAccessRule($ACE)
                    if ($removed) {
                        $ACECount++
                        Write-Log "[Add-ACEToACL] Removed ACE for ExtendedRight GUID: $GUID"
                    } else {
                        Write-Log "[Add-ACEToACL] ACE for ExtendedRight GUID $GUID was not found - nothing removed"
                    }
                }
            }
        }
    } elseif ($Rights) {
        # Standard rights
        $ADRights = [System.DirectoryServices.ActiveDirectoryRights]::$Rights
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $PrincipalSID,
            $ADRights,
            $AccessControlType
        )

        if ($Operation -eq 'Add') {
            $ACL.AddAccessRule($ACE)
            $ACECount++
            Write-Log "[Add-ACEToACL] Added $AccessType ACE for Rights: $Rights"
        } else {
            $removed = $ACL.RemoveAccessRule($ACE)
            if ($removed) {
                $ACECount++
                Write-Log "[Add-ACEToACL] Removed ACE for Rights: $Rights"
            } else {
                Write-Log "[Add-ACEToACL] ACE for Rights '$Rights' was not found - nothing removed"
            }
        }
    }

    return $ACECount
}
