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

        # GetAccessRules with SecurityIdentifier, not the .Access property. .Access asks
        # for the rules as NTAccount, which makes the local machine resolve every SID to
        # a name - and it silently drops the ACEs it cannot resolve. Against a domain the
        # scanning host is not joined to, which is the normal case for this tool, that is
        # every domain principal in the descriptor: the DACL came back with the built-in
        # identities only, or empty, and no error anywhere. Asking for SecurityIdentifier
        # needs no name resolution at all, so nothing can be dropped, and it is also what
        # CLAUDE.md requires - identity decisions are made on the SID, and the display
        # name comes from ConvertFrom-SID rather than from the host's own account
        # database, which would hand back a localized name on a non-English host.
        $AccessRules = $SD.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

        foreach ($ACE in $AccessRules) {
            $PrincipalSID = $ACE.IdentityReference.Value
            $PrincipalName = ConvertFrom-SID -SID $PrincipalSID

            $ACEType = $ACE.AccessControlType
            $Rights = $ACE.ActiveDirectoryRights -replace '\s', ''
            $RightsDisplay = $Rights

            if ($Rights -match 'ExtendedRight') {
                if ($ACE.ObjectType -ne [System.Guid]::Empty) {
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
                else {
                    # An empty ObjectType means ALL extended rights, which includes
                    # Certificate-Enrollment. This case used to be left as the bare word
                    # "ExtendedRight", so a consumer looking for the name never saw it -
                    # Get-ADCSTemplate missed a template enrollable through an
                    # All-Extended-Rights ACE. The word "ExtendedRight" stays in the string,
                    # so anything matching on that keeps working.
                    $RightsDisplay = $Rights -replace 'ExtendedRight', "ExtendedRight (All-Extended-Rights)"
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
