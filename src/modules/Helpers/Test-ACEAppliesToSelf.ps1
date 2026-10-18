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

function Get-TemplateEnrollmentRight {
    <#
    .SYNOPSIS
    Says which of the two enrollment rights an ACE of a certificate template covers.

    .DESCRIPTION
    The CA asks the template's DACL for Certificate-Enrollment (a manual request) or
    Certificate-AutoEnrollment. An ACE covers one of them when it applies to the template
    itself and grants the extended right named, all extended rights, or full control.

    Full control is read by its scope. An object ACE grants its mask on the node of the
    object type list its GUID names and nowhere else (MS-DTYP 2.5.3.2), so GenericAll
    scoped to an attribute or to a child class grants no extended right on the template -
    the check used to take every GenericAll for one, and a Deny of it for a Deny of
    enrollment. An inherit-only ACE exists only to be passed down and does not apply to
    the template at all.

    Kept here, beside Test-ACEAppliesToSelf, rather than in Get-ADCSTemplate: the Core
    function Get-CertificateTemplate asks the same question for -EnrollmentAllowed, and a
    Core module does not reach into a check.

    .PARAMETER ACE
    An ACE as ConvertFrom-SecurityDescriptor returns it (Rights, ObjectType,
    PropagationFlags).

    .OUTPUTS
    [string[]] - 'Certificate-Enrollment' and/or 'Certificate-AutoEnrollment'; empty when
    the ACE covers neither.

    .EXAMPLE
    Get-TemplateEnrollmentRight -ACE $sd.ACEs[0]
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory=$true)]
        [AllowNull()]
        $ACE
    )

    if ($null -eq $ACE) { return @() }
    if (-not (Test-ACEAppliesToSelf -ACE $ACE)) { return @() }
    if ([string]$ACE.Rights -notmatch 'GenericAll|ExtendedRight') { return @() }

    $objectType = ([string]$ACE.ObjectType).Trim('{}').ToLower()
    if (-not $objectType -or $objectType -eq [Guid]::Empty.ToString()) {
        return @('Certificate-Enrollment', 'Certificate-AutoEnrollment')
    }
    if ($objectType -eq $Script:ExtendedRightsAliases['CertificateEnrollment']) {
        return @('Certificate-Enrollment')
    }
    if ($objectType -eq $Script:ExtendedRightsAliases['CertificateAutoEnrollment']) {
        return @('Certificate-AutoEnrollment')
    }
    return @()
}
