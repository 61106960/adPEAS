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
            ComputerDisabled = ($status -eq 'Computer configuration disabled' -or $status -eq 'All settings disabled')
            UserDisabled     = ($status -eq 'User configuration disabled' -or $status -eq 'All settings disabled')
        }
    }

    return $map
}

<#
.SYNOPSIS
    Returns the state of a GPO when something stops it taking effect, and nothing when
    nothing does.

.DESCRIPTION
    The value every GPO check reports as its GPOStatus attribute, in the vocabulary
    Get-DomainGPO decodes the flags attribute into.

    It deliberately says nothing about linkage to no OU at all. Where a GPO applies is the
    LinkedOUs attribute's subject, and it states an unlinked policy in one word; saying it
    a second time here is how the same fact came to stand twice in one block, in two
    wordings. What belongs here is what LinkedOUs cannot show: a half of the policy that is
    switched off, and a set of links that exists but is disabled to the last one - the case
    where a reader sees OUs listed and would otherwise conclude the settings reach them.

.PARAMETER StatusEntry
    The entry Get-GPOStatusMap holds for this GPO, or $null when the policy was not found.

.PARAMETER Scope
    Which half of the policy the setting lives in: Machine, User, or Any for a setting
    that is not tied to one - the GPO's own permissions, for instance.

.PARAMETER Link
    The GPO's links, as Get-GPOLinkage returns them. $null means the caller did not resolve
    the linkage, which is not the same as having resolved it to none.

.OUTPUTS
    String - the state, or $null when nothing stops the GPO taking effect.
#>
function Get-GPOEffectiveStatus {
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
        [AllowNull()]
        $Link
    )

    $reasons = @()

    if ($StatusEntry) {
        if ($StatusEntry.ComputerDisabled -and $StatusEntry.UserDisabled) {
            $reasons += 'all settings disabled'
        }
        elseif ($Scope -eq 'Machine' -and $StatusEntry.ComputerDisabled) {
            $reasons += 'computer configuration disabled'
        }
        elseif ($Scope -eq 'User' -and $StatusEntry.UserDisabled) {
            $reasons += 'user configuration disabled'
        }
    }

    # Links that exist but are all switched off. LinkedOUs shows each one with its state,
    # and on a policy with five links that means five suffixes to read before the reader
    # knows none of them counts. A GPO with no links at all is not mentioned here at all -
    # LinkedOUs says that in one word, and saying it twice is what this rewrite removed.
    #
    # A link record with no LinkStatus counts as enabled: that is the conservative
    # direction, and a cross-domain or hand-built entry has none.
    $links = @($Link)
    if ($null -ne $Link -and $links.Count -gt 0) {
        $activeLinks = @($links | Where-Object { $_.LinkStatus -ne 'Disabled' })
        if ($activeLinks.Count -eq 0) {
            $reasons += 'every link is disabled'
        }
    }

    if ($reasons.Count -eq 0) { return $null }

    $text = $reasons -join ', '
    return ($text.Substring(0, 1).ToUpper() + $text.Substring(1))
}
