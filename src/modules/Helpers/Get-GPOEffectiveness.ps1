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

<#
.SYNOPSIS
    Puts the effective-setting verdict of a GPO into words.

.DESCRIPTION
    Several checks report more than one GPO configuring the same thing and have to say
    which of them actually decides the value. That used to be a boolean, IsEffectiveSetting,
    and a boolean cannot carry the answer: False meant either "a higher-priority policy
    overrides this one" or "this policy reaches no machine at all", which are different
    facts with different remediations. One of them is a precedence problem, the other is a
    policy nobody linked.

    So the verdict is a sentence, in the same spirit as Get-GPOEffectiveStatus above, and
    the wording lives here rather than in each check so that three reports do not describe
    the same situation three ways.

    The scopes mirror the precedence model the callers build:

      DomainControllers - linked at or below the Domain Controllers OU
      Domain            - linked at the domain root
      OtherOU           - actively linked, but to some ordinary OU
      NotLinked         - linked nowhere, or every link disabled

    The OtherOU wording stops short of claiming precedence. Two policies linked to the same
    workstation OU with opposite values are both reported as applying there, because none of
    these checks compares link order below the domain level - and a row that claimed a
    precedence it never evaluated would be worse than one that says so.

.PARAMETER Scope
    The precedence scope the caller determined.

.PARAMETER IsEffective
    Whether this GPO won its scope's precedence contest. Only consulted for the two scopes
    that hold a contest, DomainControllers and Domain.

.PARAMETER WinnerName
    Display name of the GPO that won, for the overridden case. Omitted when unknown.

.PARAMETER WinnerLinkOrder
    Link order of the winner, appended when known - it is what decided the contest.

.PARAMETER HasAnyLink
    Whether the policy has link records at all. Separates "linked nowhere" from "every link
    is disabled", which reach the same set of machines by different routes.

.OUTPUTS
    [string] A sentence beginning with Yes or No.

.EXAMPLE
    Get-GPOEffectiveSettingText -Scope 'DomainControllers' -IsEffective $true
    Yes - wins precedence on the Domain Controllers OU

.EXAMPLE
    Get-GPOEffectiveSettingText -Scope 'Domain' -IsEffective $false -WinnerName 'DC LDAP Hardening' -WinnerLinkOrder 1
    No - overridden by 'DC LDAP Hardening' (link order 1)

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
function Get-GPOEffectiveSettingText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Scope,

        [Parameter(Mandatory=$false)]
        [bool]$IsEffective,

        [Parameter(Mandatory=$false)]
        [string]$WinnerName,

        [Parameter(Mandatory=$false)]
        $WinnerLinkOrder,

        [Parameter(Mandatory=$false)]
        [bool]$HasAnyLink
    )

    switch ($Scope) {
        'DomainControllers' {
            if ($IsEffective) { return 'Yes - wins precedence on the Domain Controllers OU' }
            return (Get-GPOOverriddenText -WinnerName $WinnerName -WinnerLinkOrder $WinnerLinkOrder)
        }
        'Domain' {
            if ($IsEffective) { return 'Yes - wins precedence at the domain root' }
            return (Get-GPOOverriddenText -WinnerName $WinnerName -WinnerLinkOrder $WinnerLinkOrder)
        }
        'OtherOU' {
            return 'Yes - applies on its linked OUs; no precedence comparison there'
        }
        default {
            if ($HasAnyLink) { return 'No - every link is disabled' }
            return 'No - the policy is linked nowhere'
        }
    }
}

<#
.SYNOPSIS
    Wording for a GPO that lost its precedence contest.
.DESCRIPTION
    Split out so the two scopes that hold a contest cannot drift apart in how they phrase
    the loss. The winner's name is what a reader needs in order to go and look at it; the
    link order is what decided the contest and is appended when it is known.
.OUTPUTS
    [string]
#>
function Get-GPOOverriddenText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$WinnerName,

        [Parameter(Mandatory=$false)]
        $WinnerLinkOrder
    )

    if ([string]::IsNullOrWhiteSpace($WinnerName)) {
        return 'No - overridden by a higher-priority GPO'
    }

    # 999 is the placeholder the callers use for "no link order recorded", so it says
    # nothing worth printing.
    $order = $null
    if ($null -ne $WinnerLinkOrder -and "$WinnerLinkOrder" -ne '' -and "$WinnerLinkOrder" -ne '999') {
        $order = "$WinnerLinkOrder"
    }

    if ($order) { return "No - overridden by '$WinnerName' (link order $order)" }
    return "No - overridden by '$WinnerName'"
}

<#
.SYNOPSIS
    Answers whether a Group Policy reaches a machine at all.

.DESCRIPTION
    The one question eleven checks need and each used to answer for itself, which is how
    they drifted apart: the same unlinked policy was a finding in one section, a note in
    another and the effective setting in a third.

    What it reads is the directory: whether an enabled link exists, and whether the
    relevant half of the policy is switched on.

    WHAT IT DOES NOT DO, and the reason it is not called Test-GPOApplies. A policy that
    passes this can still apply to nothing:

      - A WMI filter that matches no machine.
      - Security filtering. Remove Authenticated Users from the Apply Group Policy right
        and grant it to nobody and the policy reaches nothing, while every link stays
        enabled. This one is computable from the GPO's own DACL and Get-GPOPermissions
        already parses it, so it is the obvious refinement - it is simply not read here.
      - Block inheritance and Enforced, which together need real RSoP.

    So a $true means "nothing in the directory stops this from applying", not "this
    applies". A name that claimed the latter would invite the next reader to trust it as
    an RSoP answer, which it is not.

    Reaches is deliberately three-valued. $null is unknown, and a caller must not dampen a
    finding on it: a linkage that could not be resolved is missing information, and
    demoting a real finding for missing information is the worse direction to be wrong in.
    Same discipline as the Resolved flag on Get-CertificateTrustAnchor.

.PARAMETER StatusEntry
    The policy's entry from Get-GPOStatusMap, or $null when it has none.

.PARAMETER Scope
    Which half of the policy the caller cares about. A check that reads MACHINE settings
    passes 'Machine', and a disabled user configuration then does not count against it.

.PARAMETER Link
    The policy's link records. Follows the convention the GPO checks already use, and the
    distinction carries the whole three-valued answer:

      $null  linkage could not be resolved -> Reaches is $null
      @()    resolved, and the policy is linked nowhere -> Reaches is $false

    Wrapped defensively, because @($null) is an array of count one holding $null, and a
    caller that built its list from a missing hashtable key hands over exactly that.

.OUTPUTS
    [PSCustomObject] with
      Reaches - $true, $false, or $null for unknown
      Reason  - $null when it reaches, otherwise a sentence naming what stops it

.EXAMPLE
    $reach = Get-GPOReach -StatusEntry $statusMap[$guid] -Scope 'Machine' -Link $links
    if ($reach.Reaches -eq $false) { "inactive: $($reach.Reason)" }

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
function Get-GPOReach {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
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

    if ($null -eq $Link) {
        return [PSCustomObject]@{
            Reaches = $null
            Reason  = 'Unknown - the linkage could not be resolved'
        }
    }

    $reasons = @()

    # Real link records only. A slot holding $null is not a link, and counting it as one
    # would report a policy linked nowhere as linked.
    $links = @(@($Link) | Where-Object { $_ })

    if ($links.Count -eq 0) {
        $reasons += 'the policy is linked nowhere'
    } else {
        # A record with no LinkStatus counts as enabled, which is the conservative
        # direction - a cross-domain or hand-built entry carries none.
        $activeLinks = @($links | Where-Object { $_.LinkStatus -ne 'Disabled' })
        if ($activeLinks.Count -eq 0) { $reasons += 'every link is disabled' }
    }

    # The configuration half, worded once in Get-GPOEffectiveStatus. Called with no Link so
    # it reports only the status reasons; the link state is decided above.
    $statusReason = Get-GPOEffectiveStatus -StatusEntry $StatusEntry -Scope $Scope -Link $null
    if ($statusReason) { $reasons += $statusReason.ToLower() }

    if ($reasons.Count -eq 0) {
        return [PSCustomObject]@{ Reaches = $true; Reason = $null }
    }

    $text = $reasons -join ', '
    return [PSCustomObject]@{
        Reaches = $false
        Reason  = ($text.Substring(0, 1).ToUpper() + $text.Substring(1))
    }
}
