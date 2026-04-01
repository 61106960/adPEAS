<#
.SYNOPSIS
    Converts nTSecurityDescriptor byte array to formatted ACE objects.

.DESCRIPTION
    ConvertTo-FormattedACE is a central helper function for parsing and formatting Active Directory nTSecurityDescriptor attributes.
    It converts raw byte arrays into human-readable ACE (Access Control Entry) objects with SID-to-Name resolution.

    This function is used by multiple modules (Get-DomainUser, Get-DomainComputer, Get-DomainGroup, Get-DomainGPO) to provide consistent -ShowACE output.

    SID Resolution:
    Uses ConvertFrom-SID helper for LDAP-based SID-to-Name translation with caching.
    This ensures consistent resolution across all modules and supports remote credentials via session management.

.PARAMETER SecurityDescriptor
    The nTSecurityDescriptor attribute value (byte array) from LDAP query.

.PARAMETER NoResolveSIDs
    If set, skips SID-to-Name resolution and displays raw SIDs instead.
    By default, SIDs are resolved to friendly names (e.g., "CONTOSO\Domain Admins") using ConvertFrom-SID helper with LDAP-based resolution.

.EXAMPLE
    $user = Get-DomainUser -Identity "Administrator" -Properties nTSecurityDescriptor
    ConvertTo-FormattedACE -SecurityDescriptor $user.nTSecurityDescriptor
    Parses the security descriptor and returns formatted ACE objects.

.EXAMPLE
    Get-DomainGPO -ShowACE | ForEach-Object { ConvertTo-FormattedACE $_.nTSecurityDescriptor }
    Processes multiple GPO security descriptors.

.OUTPUTS
    PSCustomObject with properties:
    - Owner: String (resolved name or SID)
    - OwnerSID: String (SID)
    - ACEs: Array of ACE objects with properties:
        - AccessControlType: Allow/Deny
        - Trustee: String (resolved name or SID)
        - TrusteeSID: String (SID)
        - Rights: String (formatted access rights)
        - RightsRaw: Array of ActiveDirectoryRights enum values
        - ObjectType: GUID of property/extended right (if applicable)
        - ObjectTypeName: Resolved extended right name (if available)
        - InheritedObjectType: GUID for inheritance filter
        - IsInherited: Boolean indicating if ACE is inherited
        - InheritanceFlags: Inheritance flag details
        - PropagationFlags: Propagation flag details

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function ConvertTo-FormattedACE {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]
        [byte[]]$SecurityDescriptor,

        [Parameter(Mandatory=$false)]
        [switch]$NoResolveSIDs
    )

    process {
        try {
            # Convert byte array to ActiveDirectorySecurity object
            $RawSD = New-Object System.DirectoryServices.ActiveDirectorySecurity
            $RawSD.SetSecurityDescriptorBinaryForm($SecurityDescriptor)

            # Extract Owner SID
            $OwnerSID = $RawSD.GetOwner([System.Security.Principal.SecurityIdentifier]).Value

            # Resolve Owner SID to Name using centralized ConvertFrom-SID (default: resolve)
            $OwnerName = if (-not $NoResolveSIDs) {
                ConvertFrom-SID -SID $OwnerSID
            } else {
                $OwnerSID
            }

            Write-Log "[ConvertTo-FormattedACE] Owner: $OwnerName ($OwnerSID)"

            # Get DACL (Discretionary Access Control List)
            $DACL = $RawSD.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

            # Parse ACEs
            $ACEList = @()

            foreach ($ACE in $DACL) {
                $TrusteeSID = $ACE.IdentityReference.Value

                # Resolve Trustee SID to Name using centralized ConvertFrom-SID (default: resolve)
                $TrusteeName = if (-not $NoResolveSIDs) {
                    ConvertFrom-SID -SID $TrusteeSID
                } else {
                    $TrusteeSID
                }

                # Parse Active Directory Rights (bitfield)
                $RightsArray = @()
                $ADRights = $ACE.ActiveDirectoryRights

                # Use central AllActiveDirectoryRights from adPEAS-GUIDs.ps1
                foreach ($Right in $Script:AllActiveDirectoryRights) {
                    # Check if ALL bits of the right are set, not just ANY overlap using ($ADRights -band $Right) -eq $Right to prevent false positives
                    if (($ADRights -band $Right) -eq $Right) {
                        $RightsArray += $Right.ToString()
                    }
                }

                # Extract ObjectType GUID (for extended rights/property access)
                $ObjectTypeGuid = if ($ACE.ObjectType -and $ACE.ObjectType -ne [System.Guid]::Empty) {
                    $ACE.ObjectType.ToString()
                } else { $null }

                # Map well-known Extended Rights GUIDs to friendly names uses central GUID resolution from adPEAS-GUIDs.ps1
                $ObjectTypeName = if ($ObjectTypeGuid) {
                    Get-ExtendedRightName -GUID $ObjectTypeGuid
                } else { $null }

                # Replace ExtendedRight with specific name if resolved
                if ($ObjectTypeName -and ($RightsArray -contains "ExtendedRight")) {
                    $RightsArray = $RightsArray | Where-Object { $_ -ne "ExtendedRight" }
                    $RightsArray += $ObjectTypeName
                }

                # Extract InheritedObjectType GUID
                $InheritedObjectTypeGuid = if ($ACE.InheritedObjectType -and $ACE.InheritedObjectType -ne [System.Guid]::Empty) {
                    $ACE.InheritedObjectType.ToString()
                } else { $null }

                # Format rights as comma-separated string
                $RightsFormatted = $RightsArray -join ', '

                # Build ACE object with extended properties
                $ACEObj = [PSCustomObject]@{
                    AccessControlType   = $ACE.AccessControlType.ToString()
                    Trustee             = $TrusteeName
                    TrusteeSID          = $TrusteeSID
                    Rights              = $RightsFormatted
                    RightsRaw           = $RightsArray
                    ObjectType          = $ObjectTypeGuid
                    ObjectTypeName      = $ObjectTypeName
                    InheritedObjectType = $InheritedObjectTypeGuid
                    IsInherited         = $ACE.IsInherited
                    InheritanceFlags    = $ACE.InheritanceFlags.ToString()
                    PropagationFlags    = $ACE.PropagationFlags.ToString()
                }

                $ACEList += $ACEObj

                Write-Log "[ConvertTo-FormattedACE] ACE: $($ACE.AccessControlType) - $TrusteeName - $RightsFormatted (Inherited: $($ACE.IsInherited))"
            }

            # Return structured object
            return [PSCustomObject]@{
                Owner     = $OwnerName
                OwnerSID  = $OwnerSID
                ACEs      = $ACEList
            }

        } catch {
            Write-Error "[ConvertTo-FormattedACE] Error parsing security descriptor: $_"
            return $null
        }
    }
}