<#
.SYNOPSIS
    Tests whether an ACE grants its rights on the object that carries it.

.DESCRIPTION
    An ACE marked INHERIT_ONLY_ACE is not part of the effective permissions of the object
    whose DACL holds it. It exists only to be inherited downwards, so a right it grants
    says nothing about what may be done to that object.

    The delegation wizard produces such an ACE for "only the following objects in this
    object" and for "all descendant objects", and only the first of those carries an
    InheritedObjectType. An ACE created for "all descendant objects" therefore looks
    exactly like one that applies to the object itself unless PropagationFlags is read.

    Measured on the three forms the wizard writes - ContainerInherit+InheritOnly,
    ObjectInherit+InheritOnly and both+InheritOnly - every one arrives with an empty
    InheritedObjectType and PropagationFlags 'InheritOnly'. NoPropagateInherit, which is
    "this object and its immediate children", does not set InheritOnly and must keep its
    finding.

    Takes the ACE shape Get-ObjectACL and ConvertTo-FormattedACE return, where
    PropagationFlags is the string form of the flags enum. For a raw
    ActiveDirectoryAccessRule the same test reads the enum directly - see
    Get-OUPermissions, which needs the companion question (does it reach the children?)
    as well and computes both from the rule itself.

.PARAMETER ACE
    An ACE object carrying a PropagationFlags property.

.OUTPUTS
    [bool] True if the ACE applies to the object that carries it.

.EXAMPLE
    foreach ($ace in $aclResult.ACEs) {
        if (-not (Test-ACEAppliesToSelf -ACE $ace)) { continue }
    }

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
function Test-ACEAppliesToSelf {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $ACE
    )

    if ($null -eq $ACE) { return $false }

    # A missing property is not an InheritOnly ACE. Returning $false here would drop every
    # ACE from a caller that supplies a different shape, which is the silent-clean failure
    # this check exists to prevent.
    if (-not $ACE.PSObject.Properties['PropagationFlags']) { return $true }

    return -not (([string]$ACE.PropagationFlags) -match 'InheritOnly')
}
