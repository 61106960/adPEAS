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
    The precedence scope the caller determined: DomainControllers, Domain, OtherOU,
    NotLinked, or Unknown when the linkage could not be resolved. Anything else is treated
    as Unknown rather than as NotLinked - see the default branch.

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
    [string] A sentence beginning with Yes, No, or Unknown.

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
        'NotLinked' {
            if ($HasAnyLink) { return 'No - every link is disabled' }
            return 'No - the policy is linked nowhere'
        }
        'Unknown' {
            return 'Unknown - the linkage could not be resolved'
        }
        default {
            # NotLinked used to live here, which made this the fall-through for every scope
            # the function does not recognise - including the unresolved one, which was then
            # reported as the definite "linked nowhere" while the LinkedOUs row on the same
            # object correctly said Unknown. The two contradicted each other in one block.
            #
            # Failing to "unknown" is the right direction for an unexpected value: a wrong
            # claim about where a policy applies sends a reader to the wrong GPO, an admission
            # of ignorance only sends them to check by hand.
            return 'Unknown - the policy scope could not be determined'
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

<#
.SYNOPSIS
    Splits GPO findings into the ones whose policy reaches a machine and the ones whose
    does not.

.DESCRIPTION
    The partition every settings-level GPO check needs. A finding that says "this policy
    grants SeDebugPrivilege to Helpdesk" asserts that something is configured and takes
    effect; if the policy reaches nothing, the second half of that is false. A service
    provider who ships a library of policies and links a handful of them turns the rest
    into pages of findings about configuration that applies nowhere.

    What it does NOT do is drop them. "Nothing found" and "found but not shown" are
    different statements, and an unlinked policy is one gPLink write away from being live -
    a pre-staged policy with dangerous settings is a finding a tester wants, not noise. The
    caller decides what to print; this only sorts.

    Deliberately NOT applied to the checks that report a disclosure rather than a setting.
    A cpassword in Groups.xml is readable by Authenticated Users whether the policy is
    linked or not, so linkage has no bearing on it. Nor to the delegation checks: who may
    edit an unlinked policy still matters, because editing it and linking it is a two-step
    path.

.PARAMETER Finding
    The finding objects. Each must carry the policy's GUID under GuidProperty.

.PARAMETER GPOStatusMap
    From Get-GPOStatusMap, or $null when it could not be built.

.PARAMETER GPOLinkage
    From Get-GPOLinkage. $null means the linkage could not be resolved, and every finding
    then counts as active - see below.

.PARAMETER Scope
    Which half of the policy the check reads, when that is the same for every finding.

.PARAMETER ScopeProperty
    For a check whose findings do not share one half. The registry check derives it per
    finding from the hive - a value under Machine\Registry.pol writes HKLM, the one under
    User writes HKCU - and a policy with only its computer configuration switched off
    stops the first and not the second. Passing one scope for all of them would lose that
    and leave such a finding at full severity.

    Names a property holding 'Machine', 'User' or 'Any'. Where it is absent or holds
    something else, Scope applies.

.PARAMETER GuidProperty
    Where the GUID sits on the finding. GPOGUID for the checks that build their own
    objects; the checks that enrich a native GPO object pass 'Name', because that is what
    a GPO's GUID is called in the directory.

.OUTPUTS
    [PSCustomObject] with Active and Inactive, both arrays, and the two counts that say
    which of the two reasons applied: Unlinked and Disabled. There is no third reason - a
    policy either has no enabled link, or its relevant configuration half is switched off -
    and the summary line names them rather than saying "reaches no machine", which would
    claim a check on the target machines that nothing here performs. A policy linked to an
    OU holding no computer at all reaches nothing and still counts as active here.

    A finding whose reach is unknown counts as ACTIVE. Unknown is not inactive: demoting or
    hiding a real finding because the linkage could not be read would lose it, and that is
    the worse direction to be wrong in. This is why the test below is -eq $false rather
    than a falsiness check - $null is falsy too.

.EXAMPLE
    $split = Split-GPOFindingByReach -Finding $findings -GPOStatusMap $map -GPOLinkage $linkage -Scope 'Machine'
    $split.Active.Count
    $split.Inactive.Count

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
function Split-GPOFindingByReach {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        $Finding,

        [Parameter(Mandatory=$false)]
        [AllowNull()]
        $GPOStatusMap,

        [Parameter(Mandatory=$false)]
        [AllowNull()]
        $GPOLinkage,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Machine', 'User', 'Any')]
        [string]$Scope = 'Any',

        [Parameter(Mandatory=$false)]
        [string]$ScopeProperty,

        [Parameter(Mandatory=$false)]
        [string]$GuidProperty = 'GPOGUID'
    )

    $active   = New-Object System.Collections.Generic.List[object]
    $inactive = New-Object System.Collections.Generic.List[object]
    $unlinked = 0
    $disabled = 0

    # One entry per dormant POLICY, not per dormant finding, so that ten registry values in
    # one unlinked GPO name it once. Keyed by GUID; the first category wins, which is the
    # same precedence the counters use.
    $dormantByGuid = [ordered]@{}

    foreach ($item in @(@($Finding) | Where-Object { $_ })) {
        $guid = "$($item.$GuidProperty)".ToUpper()

        # Tested against $null, not for truth. An empty map is a real answer - the query
        # ran and nothing in the domain carries a gPLink - and it has to stay
        # distinguishable from a linkage that could not be read at all. Truthiness cannot
        # carry that: @{} happens to be truthy in PowerShell, so it would read as resolved,
        # but a caller that wrote `if ($GPOLinkage)` would be relying on an accident rather
        # than on the contract.
        $links = $null
        if ($null -ne $GPOLinkage) {
            $links = @()
            if ($GPOLinkage.ContainsKey($guid)) { $links = @($GPOLinkage[$guid]) }
        }

        $statusEntry = $null
        if ($GPOStatusMap -and $GPOStatusMap.ContainsKey($guid)) { $statusEntry = $GPOStatusMap[$guid] }

        # Per-finding scope where the check supplies one. Anything other than the three
        # Get-GPOReach accepts falls back rather than throwing on a ValidateSet: a finding
        # with a missing or malformed scope should be judged, not lose the whole run.
        $itemScope = $Scope
        if ($ScopeProperty) {
            $candidate = "$($item.$ScopeProperty)"
            if ($candidate -in @('Machine', 'User', 'Any')) { $itemScope = $candidate }
        }

        $reach = Get-GPOReach -StatusEntry $statusEntry -Scope $itemScope -Link $links

        # -eq $false, not -not: $null is falsy, and an unresolved linkage must not be read
        # as inactive. See the OUTPUTS note above.
        if ($reach.Reaches -eq $false) {
            $inactive.Add($item)

            # Which of the two reasons, for the summary line. "Linked nowhere" is checked
            # first because it is the one a reader acts on differently: an unlinked policy
            # is a cleanup candidate, a disabled one is a deliberate switch somebody threw.
            # A policy that is both counts as unlinked, since linking it would still not
            # make it apply.
            $category = if ($reach.Reason -like '*linked nowhere*') { 'unlinked' } else { 'disabled' }
            if ($category -eq 'unlinked') { $unlinked++ } else { $disabled++ }

            if (-not $dormantByGuid.Contains($guid)) {
                # The display name off the finding. Checks name it GPOName; the two that work
                # on native GPO objects carry displayName, and Name there is the GUID - so
                # falling back to Name would print the GUID twice on one line.
                $name = $null
                foreach ($candidate in @('GPOName', 'displayName')) {
                    if ($item.PSObject.Properties[$candidate] -and
                        -not [string]::IsNullOrWhiteSpace("$($item.$candidate)")) {
                        $name = "$($item.$candidate)"
                        break
                    }
                }

                $dormantByGuid[$guid] = [PSCustomObject]@{
                    GPOGUID  = "$($item.$GuidProperty)"
                    GPOName  = $name
                    Category = $category
                }
            }
        } else {
            $active.Add($item)
        }
    }

    # ToArray(), not @($active). Casting a hashtable to PSCustomObject throws
    # "Argument types do not match" when a value is @() wrapped around a
    # List[object] - @($list) and $list.ToArray() are not interchangeable here, and the
    # failure is a terminating error inside the function, which the calling check turns
    # into "Error during check" with no hint of where it came from.
    # @(...Values) rather than .Values: an OrderedDictionary's value collection is not an
    # array, and a single entry would reach the caller as a bare object whose .Count is empty.
    return [PSCustomObject]@{
        Active   = $active.ToArray()
        Inactive = $inactive.ToArray()
        Unlinked = $unlinked
        Disabled = $disabled
        Dormant  = @($dormantByGuid.Values)
    }
}

<#
.SYNOPSIS
    The one line that stands in for the GPO findings whose policy reaches nothing.

.DESCRIPTION
    Worded here so that eight checks say it the same way, and so that the count is never
    silently absent. Without this line a reader cannot tell a domain with nothing to report
    from one whose findings were all filtered out - the distinction a blind SYSVOL scan
    once got wrong by reporting a failed read as a clean result.

    Short on purpose. Ten GPO checks print this during a full scan, and a sentence of
    advice repeated ten times is the kind of noise the dampening exists to remove.

    It names the reason rather than the consequence. An earlier wording said the policy
    "reaches no machine", which claimed more than adPEAS establishes: a policy linked to an
    OU that holds no computer reaches nothing and is not what this counts. There are only
    two reasons here, and they are the two a reader acts on differently - an unlinked
    policy is a cleanup candidate, a disabled one is a switch somebody threw on purpose.

    The -IncludeInactive hint appears only when the check was called directly, because that
    is the only context in which it is true: the switch belongs to the individual check and
    is deliberately not plumbed through Invoke-adPEAS, so telling a reader of a full scan
    to pass it would send them to a parameter that is not there. The check knows which
    context it is in - Invoke-adPEAS sets the check context before each check and clears it
    after, so an absent context means a direct call.

.PARAMETER Unlinked
    How many findings sit on a policy that is linked nowhere.

.PARAMETER Disabled
    How many sit on a policy whose links or whose relevant configuration half are switched
    off. Both are "not active" from a reader's point of view, so they share a word.

.PARAMETER Listed
    Whether those findings are being printed as well. Changes the line from an account of
    what is missing into an explanation of what is there.

.PARAMETER Dormant
    One entry per dormant POLICY - GPOGUID, GPOName, Category ('unlinked' or 'disabled') -
    as Split-GPOFindingByReach returns it in its Dormant field. Each is named on its own
    line below the summary.

    Naming them is the point: a count alone tells a reader that something was held back but
    not whether they care, and a GPO nobody can identify cannot be cleaned up either. Both
    the name and the GUID, because the name is what a reader recognises and the GUID is the
    folder under \\<domain>\SYSVOL\<domain>\Policies\ they need in order to go and look.

    Laid out as every other adPEAS row is: display name left, GUID on column 45. When both
    reasons occur the rows are grouped under a header naming the reason and its count, and
    the summary above drops the reason rather than stating it twice; one reason needs no
    header, so the summary keeps the sentence and the rows follow it directly.

    Policies, not findings: ten registry values in one unlinked GPO are one line. The
    summary above still counts findings, which is why the two numbers can differ.

    Not truncated. The list is bounded by the number of policies in the domain, and cutting
    it off would leave a reader with only -IncludeInactive to learn the missing names - which
    prints every held-back finding, far more output than the lines a cap saves.

.OUTPUTS
    None. Writes one Note line plus one per dormant policy, and nothing at all when both
    counts are zero.

.EXAMPLE
    Show-GPOInactiveSummary -Unlinked 2 -Disabled 1 -Dormant $split.Dormant

    [*] 3 finding(s) hidden:

    Group:       Dormant policies - not linked
    Count:       2 policies
    Policies:    Example Policy A    {11111111-1111-1111-1111-111111111111}
                 Example Policy B    {22222222-2222-2222-2222-222222222222}
#>
function Show-GPOInactiveSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [int]$Unlinked = 0,

        [Parameter(Mandatory=$false)]
        [int]$Disabled = 0,

        [Parameter(Mandatory=$false)]
        [switch]$Listed,

        [Parameter(Mandatory=$false)]
        [AllowNull()]
        $Dormant
    )

    $Count = $Unlinked + $Disabled
    if ($Count -le 0) { return }

    # One reason or both. Naming only the reason that applies keeps the common case short.
    $reason = if ($Unlinked -gt 0 -and $Disabled -gt 0) {
        "$Unlinked on unlinked policies, $Disabled on disabled ones"
    } elseif ($Unlinked -gt 0) {
        'the policy is not linked'
    } else {
        'the policy is disabled'
    }

    if ($Listed) {
        Show-Line "$Count of the findings below sit on a policy that is not linked or not enabled" -Class Note
        return
    }

    # Unlinked before disabled, matching the order the summary names them, and by name
    # within each so that two runs against the same domain print the same thing. A policy
    # with no name sorts under its GUID rather than to the front.
    $rows = @(@($Dormant) | Where-Object { $_ } | Sort-Object `
        @{Expression = { if ($_.Category -eq 'unlinked') { 0 } else { 1 } }}, `
        @{Expression = { if ([string]::IsNullOrWhiteSpace("$($_.GPOName)")) { "$($_.GPOGUID)" } else { "$($_.GPOName)" } }})

    # With the policies listed below, the reason belongs to the group that carries it rather
    # than to the summary - naming both counts up here and then again in the headers says the
    # same thing twice. One reason present means no group header is needed at all, so the
    # summary keeps the sentence and the rows follow directly.
    $grouped = ($rows.Count -gt 0 -and $Unlinked -gt 0 -and $Disabled -gt 0)
    $text = if ($grouped) { "$Count finding(s) hidden" } else { "$Count finding(s) hidden - $reason" }

    # The two numbers count different things - findings up here, policies in the group headers
    # and in the rows - so when they differ the headline has to name the unit. Thirty-four
    # findings over four policies otherwise reads as "(2)" meaning two findings. GPO(s) rather
    # than "policies" because that is the word the rest of the output uses.
    if ($rows.Count -gt 0 -and $rows.Count -ne $Count) {
        $text += " on $($rows.Count) GPO(s)"
    }

    # Invoke-adPEAS sets the context for the duration of each check, so no context means
    # the check was called on its own and the switch is reachable.
    if ($null -eq $Script:adPEAS_CurrentCheckContext) {
        $text += ' (-IncludeInactive to list)'
    }

    if ($rows.Count -eq 0) {
        Show-Line $text -Class Note
        return
    }

    # The headline is the entry point and stays a plain line; the policies follow as one card
    # per reason. A card each rather than one for both, because an unlinked policy and a disabled
    # one call for different work - cleanup versus a switch somebody threw - and the HTML report
    # then carries two titles a reader can scan rather than one mixed list.
    Show-Line "${text}:" -Class Note

    # Not capped. It was, at ten, and the first real domain it met had twelve dormant policies:
    # the cap saved two lines and cost the list its completeness, leaving -IncludeInactive - which
    # prints every held-back finding - as the only way to recover two names. The length is bounded
    # by what somebody has to administer, and one line per policy is already the compression.
    foreach ($category in @('unlinked', 'disabled')) {
        $inCategory = @($rows | Where-Object { $_.Category -eq $category })
        if ($inCategory.Count -eq 0) { continue }

        $label = if ($category -eq 'unlinked') { 'Dormant policies - not linked' } else { 'Dormant policies - disabled' }
        $why = if ($category -eq 'unlinked') {
            'Linked nowhere, so the settings reach no machine until the policy is linked.'
        } else {
            'Linked, but the link or the relevant configuration half is switched off.'
        }

        $policyWord = if ($inCategory.Count -eq 1) { 'policy' } else { 'policies' }
        Show-GPOSuppressedGroup -Group $label -Reason $why `
            -CountText "$($inCategory.Count) $policyWord" -Policy $inCategory
    }
}

<#
.SYNOPSIS
    Emits one object card for a group of policies a check held back.

.DESCRIPTION
    Hands a group of held-back policies to Show-Object as a single GPOSuppressedGroup object, so
    the group renders as a titled block in the console and as a collapsible card - grey, sorted to
    the end, folded by default - in the HTML report, the same machinery a finding uses.

    One card per group, never per policy: these are the things a check deliberately did not report
    in full, so a card each would put back the noise the grouping removed.

    The policies are deduplicated and sorted by Get-GPOPolicySummary and laid into one newline-
    joined attribute, rendered the way domainControllers is - name left, GUID on column 45.

.PARAMETER Group
    The heading: "Dormant policies - not linked", "Assignments that only remove default holders".

.PARAMETER Reason
    One sentence on why the group was held back.

.PARAMETER CountText
    What the title and the Count row say - "5 policies", or "10 assignment(s) on 3 GPO(s)" where
    the finding count and the policy count differ. The caller owns it, because only the caller
    knows what it is counting.

.PARAMETER Policy
    The findings or policy objects, carrying GPOName and GPOGUID.

.OUTPUTS
    None. Emits one Show-Object of type GPOSuppressedGroup, or nothing when no policy resolves.
#>
function Show-GPOSuppressedGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Group,

        [Parameter(Mandatory=$true)]
        [string]$Reason,

        [Parameter(Mandatory=$true)]
        [string]$CountText,

        [Parameter(Mandatory=$false)]
        [AllowNull()]
        $Policy
    )

    $rows = @(Get-GPOPolicySummary -Finding $Policy)
    if ($rows.Count -eq 0) { return }

    # Name left, GUID on column 45 - the same grid the dormant list used, built here so the
    # policies travel as one attribute value rather than one Show-Line each. The object renderer
    # adds the "[*] " prefix and the indent on top, so the field width is 45 minus those six.
    $nameWidth = 45 - 4 - 2
    $lines = foreach ($row in $rows) {
        $guid = "$($row.GPOGUID)"; if ([string]::IsNullOrWhiteSpace($guid)) { $guid = '(GUID unknown)' }
        $name = "$($row.GPOName)"; if ([string]::IsNullOrWhiteSpace($name)) { $name = '(name unavailable)' }
        $name.PadRight($nameWidth) + $guid
    }

    $card = [PSCustomObject]@{
        Group    = $Group
        Reason   = $Reason
        Count    = $CountText
        Policies = (@($lines) -join "`n")
    }
    $card | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPOSuppressedGroup' -Force

    # Note, not a finding: held-back, low-priority material. The HTML pipeline colours it grey,
    # sorts it behind the real findings and folds it shut on this class alone.
    Show-Object $card -Class Note
}

<#
.SYNOPSIS
    Reduces findings to the distinct policies they sit on.

.DESCRIPTION
    Split out because the caller needs the count before the list is printed - Show-GPOSuppressedGroup
    needs the policies, and the check headlines need their number - so the dedup happens once here:
    a headline reads "35 finding(s) hidden on 13 GPO(s)", and the two numbers count different
    things. Asking the printer for them afterwards would mean deduplicating twice and would put
    the headline after the rows it introduces.

    Keyed on the GUID, uppercased, since that is the only identifier guaranteed unique - two
    policies may share a display name. The name of the first occurrence wins; they agree in
    practice, and a disagreement would mean the directory has two names for one GUID.

.PARAMETER Finding
    Objects carrying GPOName and GPOGUID.

.OUTPUTS
    [PSCustomObject[]] with GPOName and GPOGUID, sorted by name, one per distinct GUID.
#>
function Get-GPOPolicySummary {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        $Finding
    )

    $byGuid = [ordered]@{}
    foreach ($item in @(@($Finding) | Where-Object { $_ })) {
        $guid = "$($item.GPOGUID)"
        if ([string]::IsNullOrWhiteSpace($guid)) { continue }

        $key = $guid.ToUpperInvariant()
        if ($byGuid.Contains($key)) { continue }

        $byGuid[$key] = [PSCustomObject]@{
            GPOName = "$($item.GPOName)"
            GPOGUID = $guid
        }
    }

    # @(...Values), not .Values: an OrderedDictionary's value collection is not an array, and a
    # single entry would reach the caller as a bare object whose .Count is empty.
    $rows = @($byGuid.Values)
    if ($rows.Count -eq 0) { return @() }

    # A policy with no name sorts under its GUID rather than to the front.
    #
    # Returned bare, to be wrapped in @() by the caller. A leading comma was tried and is wrong
    # here: it nests the whole list inside a one-element array, which the caller's @() then
    # unrolls back to the inner array - fine for one policy, but it collapses several into one.
    # Every caller wraps, so the one-element unroll is handled where it has to be anyway.
    return $rows | Sort-Object @{Expression = {
        if ([string]::IsNullOrWhiteSpace($_.GPOName)) { $_.GPOGUID } else { $_.GPOName }
    }}
}
