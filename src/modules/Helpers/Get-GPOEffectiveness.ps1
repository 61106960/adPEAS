<#
.SYNOPSIS
    Says whether a setting found in a Group Policy Object currently applies to anything.

.DESCRIPTION
    A GPO carries two switches that decide whether what is written inside it reaches a
    machine at all, and the checks that read those settings consulted neither.

    The flags attribute disables half the policy or all of it: 1 turns off the user
    configuration, 2 the computer configuration, 3 both. Get-DomainGPO decodes it into
    GPOStatus already - nothing read the result. A dangerous startup script in a GPO whose
    computer configuration is switched off was reported exactly like one that runs on every
    boot.

    The other is linkage. A GPO linked nowhere applies nowhere.

    Neither makes a finding go away, and this does not suppress one. A disabled half is one
    click from being enabled again, an unlinked GPO one drag from being linked, and the
    dangerous setting inside is a cleanup candidate either way - often a forgotten one,
    which is exactly why it is still dangerous. What the reader needs is to be able to tell
    the two apart, and that is what this provides.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

<#
.SYNOPSIS
    Indexes the GPO list by GUID so a finding can look up its policy's state.

.PARAMETER GPO
    The objects Get-DomainGPO returned.

.OUTPUTS
    Hashtable keyed by the GPO GUID in braces and upper case, the form a SYSVOL path
    yields, holding Status, ComputerDisabled and UserDisabled.
#>
function Get-GPOStatusMap {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        $GPO
    )

    $map = @{}

    foreach ($policy in @($GPO)) {
        if (-not $policy) { continue }

        # The findings carry the GUID as it appears in the SYSVOL path: braces, upper case.
        $guid = "$($policy.Name)".ToUpper()
        if (-not $guid) { continue }

        # GPOStatus is the decoded form; flags is the raw attribute behind it. Reading the
        # decoded string keeps the mapping in one place, in Get-DomainGPO.
        $status = "$($policy.GPOStatus)"

        $map[$guid] = @{
            Status           = if ($status) { $status } else { 'Unknown' }
            ComputerDisabled = ($status -eq 'Computer portion disabled' -or $status -eq 'All settings disabled')
            UserDisabled     = ($status -eq 'User portion disabled' -or $status -eq 'All settings disabled')
        }
    }

    return $map
}

<#
.SYNOPSIS
    Returns why a finding does not currently apply, or nothing when it does.

.PARAMETER StatusEntry
    The entry Get-GPOStatusMap holds for this GPO, or $null when the policy was not found.

.PARAMETER Scope
    Which half of the policy the setting lives in: Machine, User, or Any for a setting
    that is not tied to one - the GPO's own permissions, for instance.

.PARAMETER LinkedOUCount
    How many places the GPO is linked to. Zero means it applies nowhere.

.OUTPUTS
    String - a sentence naming the reason, or $null when the setting does apply.
#>
function Get-GPOIneffectiveReason {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        $StatusEntry,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Machine', 'User', 'Any')]
        [string]$Scope = 'Any',

        [Parameter(Mandatory=$false)]
        [int]$LinkedOUCount = -1
    )

    $reasons = @()

    if ($StatusEntry) {
        if ($StatusEntry.ComputerDisabled -and $StatusEntry.UserDisabled) {
            $reasons += 'all settings in this GPO are disabled'
        }
        elseif ($Scope -eq 'Machine' -and $StatusEntry.ComputerDisabled) {
            $reasons += 'the computer configuration of this GPO is disabled'
        }
        elseif ($Scope -eq 'User' -and $StatusEntry.UserDisabled) {
            $reasons += 'the user configuration of this GPO is disabled'
        }
    }

    # -1 means the caller did not resolve the linkage, which is not the same as having
    # resolved it to none. Saying "applies nowhere" on a failed lookup would be a claim.
    if ($LinkedOUCount -eq 0) {
        $reasons += 'the GPO is not linked to any OU, site or domain'
    }

    if ($reasons.Count -eq 0) { return $null }

    return ('Does not currently apply: ' + ($reasons -join ', ') +
            '. Re-enabling or re-linking the GPO makes it effective again.')
}
