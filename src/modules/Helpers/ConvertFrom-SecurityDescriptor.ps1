<#
.SYNOPSIS
    Converts Security Descriptor byte array to structured object format.

.DESCRIPTION
    Converts a Security Descriptor (DACL) into a single structured object with:
    - Owner: Object with SID, Name, and DisplayText properties
    - ACEs: Array of structured ACE objects with SID, Name, Type, Rights, RightsDisplay, ObjectType, DisplayText

.PARAMETER SecurityDescriptorBytes
    Byte array of the Security Descriptor (nTSecurityDescriptor attribute).

.EXAMPLE
    $sd = Get-DomainUser -Identity "admin" -Properties nTSecurityDescriptor
    ConvertFrom-SecurityDescriptor -SecurityDescriptorBytes $sd.nTSecurityDescriptor

    # Access owner info:
    $sd.nTSecurityDescriptor.Owner.SID       # S-1-5-21-...-512
    $sd.nTSecurityDescriptor.Owner.Name      # CONTOSO\Domain Admins
    $sd.nTSecurityDescriptor.Owner.DisplayText # Owner: CONTOSO\Domain Admins

    # Access ACEs:
    $sd.nTSecurityDescriptor.ACEs | Where-Object { $_.Type -eq 'Allow' }

.OUTPUTS
    PSCustomObject with:
    - Owner: PSCustomObject with SID, Name, DisplayText
    - ACEs: Array of PSCustomObjects with SID, Name, Type, Rights, RightsDisplay, ObjectType, DisplayText

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
function ConvertFrom-SecurityDescriptor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$SecurityDescriptorBytes
    )

    try {
        $SD = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $SD.SetSecurityDescriptorBinaryForm($SecurityDescriptorBytes)

        # Get Owner - create structured object
        $OwnerSID = $SD.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        $OwnerName = ConvertFrom-SID -SID $OwnerSID

        $OwnerObject = [PSCustomObject]@{
            SID = $OwnerSID
            Name = $OwnerName
            DisplayText = "Owner: $OwnerName"
        }

        # Process each ACE into structured objects
        $ACEList = @()

        foreach ($ACE in $SD.Access) {
            # Get both SID and Name for each principal
            $PrincipalSID = $null
            $PrincipalName = $null

            # Try to translate IdentityReference to SID directly (works for any language)
            try {
                $sidObj = $ACE.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                $PrincipalSID = $sidObj.Value
            } catch {
                # Translate failed - IdentityReference might already be a SID string
                $Principal = $ACE.IdentityReference.Value
                if ($Principal -match '^S-1-') {
                    $PrincipalSID = $Principal
                }
            }

            # Get the display name
            $Principal = $ACE.IdentityReference.Value
            if ($Principal -match '^S-1-') {
                # Principal is a SID - resolve to name for display
                $PrincipalName = ConvertFrom-SID -SID $Principal
            } else {
                # Principal is already a name
                $PrincipalName = $Principal
                # If we didn't get SID via Translate, try ConvertTo-SID as fallback
                if (-not $PrincipalSID) {
                    $PrincipalSID = ConvertTo-SID -Identity $Principal
                }
            }

            $ACEType = $ACE.AccessControlType
            $Rights = $ACE.ActiveDirectoryRights -replace '\s', ''
            $RightsDisplay = $Rights

            if ($Rights -match 'ExtendedRight' -and $ACE.ObjectType -ne [System.Guid]::Empty) {
                $ObjectTypeGUID = $ACE.ObjectType.ToString()
                $ExtendedRightName = Get-ExtendedRightName -GUID $ObjectTypeGUID

                if ($ExtendedRightName) {
                    # Known Extended Right - show friendly name
                    $RightsDisplay = $Rights -replace 'ExtendedRight', "ExtendedRight ($ExtendedRightName)"
                } else {
                    # Unknown GUID - show GUID for reference
                    $RightsDisplay = $Rights -replace 'ExtendedRight', "ExtendedRight ({$ObjectTypeGUID})"
                }
            }

            # Build display text for this ACE (for backward-compatible string output)
            $DisplayText = "$ACEType - $PrincipalName - $RightsDisplay"

            # Structured ACE object with all info
            $ACEList += [PSCustomObject]@{
                SID = $PrincipalSID
                Name = $PrincipalName
                Type = $ACEType.ToString()
                Rights = $Rights
                RightsDisplay = $RightsDisplay
                ObjectType = if ($ACE.ObjectType -ne [System.Guid]::Empty) { $ACE.ObjectType.ToString() } else { $null }
                DisplayText = $DisplayText
            }
        }

        # Return unified structure - single source of truth
        return [PSCustomObject]@{
            Owner = $OwnerObject
            ACEs = $ACEList
        }
    } catch {
        throw
    }
}
