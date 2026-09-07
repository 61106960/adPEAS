function Get-GPOUserRightsAssignment {
    <#
    .SYNOPSIS
    Reports where a GPO departs from the Windows defaults for a sensitive user right.

    .DESCRIPTION
    Parses the [Privilege Rights] section of GptTmpl.inf in every GPO and compares the
    holders it assigns against the set Windows ships, from the table in adPEAS-UserRights.

    Why a comparison rather than a list: the [Privilege Rights] section is absolute, not
    additive. The principals a GPO lists for a right become the complete set of holders on
    every machine the policy reaches. The GPO's list and the default list are therefore two
    descriptions of the same thing, and the difference between them is what an auditor
    needs - in both directions.

      Added   - holders beyond the Windows default. The escalation risk, and the finding.
      Removed - default holders the GPO drops. Usually deliberate hardening, occasionally
                an operational foot-gun; reported as a note, never as a finding.

    This replaces a filter on the identity of the holder, which asked the wrong question
    and failed both ways round. Backup Operators holding SeDebugPrivilege is not a Windows
    default and is a clean path to SYSTEM - and it was suppressed, because the group looked
    privileged. Meanwhile which principals hold a right by default depends on the right,
    not on how privileged the holder looks, and no identity list can express that.

    Member servers and domain controllers have different defaults, so the comparison uses
    the ones for the machines the GPO actually reaches: the Default Domain Controllers
    Policy and anything linked to the Domain Controllers OU are measured against the domain
    controller set, everything else against the member set, and a policy reaching both is
    measured against the union.

    Severity comes from the right's own tier, raised to a finding when a deviating holder
    is a broad group - Everyone, Authenticated Users, Domain Users - because a right that
    everybody holds is not a delegation, it is a configuration accident.

    A right with no documented default in the table is not guessed at. The check falls back
    to the identity filter for that one right and says so on the finding, so the gap is
    visible rather than silently decided. SeServiceLogonRight is the case that matters:
    what holds it depends on which products are installed.

    Also reported: whether the GPO currently applies at all. A deviation in a policy whose
    computer configuration is switched off, or that is linked nowhere, is real and worth
    cleaning up but is not reaching a machine today - and it used to read exactly like one
    that is.

    Requires SMB access to \\domain\SYSVOL.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .PARAMETER IncludeDefaults
    Also report the assignments that match the Windows default. Off by default: they are
    the majority of what a domain contains and none of them is a deviation.

    .PARAMETER IncludePrivileged
    Kept as an alias of -IncludeDefaults, so an existing invocation keeps working. Under
    the old identity filter it meant "also show privileged holders"; the closest thing in
    a baseline model is "also show what matches the baseline".

    .EXAMPLE
    Get-GPOUserRightsAssignment

    .EXAMPLE
    Get-GPOUserRightsAssignment -IncludeDefaults

    .NOTES
    Category: Rights
    Author: Alexander Sturz (@_61106960_)
    Reference: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [Alias('IncludePrivileged')]
        [switch]$IncludeDefaults
    )

    begin {
        Write-Log "[Get-GPOUserRightsAssignment] Starting check"
    }

    process {
        try {
            # Connection parameters only - IncludeDefaults is ours.
            $CredParams = @{}
            if ($Domain) { $CredParams['Domain'] = $Domain }
            if ($Server) { $CredParams['Server'] = $Server }
            if ($Credential) { $CredParams['Credential'] = $Credential }

            if (-not (Ensure-LDAPConnection @CredParams)) {
                return
            }

            Show-SubHeader "Comparing GPO user rights against the Windows defaults..." -ObjectType "GPOUserRights"

            $gpos = @(Get-DomainGPO @CredParams)
            if ($gpos.Count -eq 0) {
                Show-Line "No GPOs found" -Class "Note"
                return
            }

            $gpoLinkage = Get-GPOLinkage
            $gpoStatusMap = Get-GPOStatusMap -GPO $gpos
            $domainFQDN = $Script:LDAPContext.Domain
            $dcServer = $Script:LDAPContext.Server
            $domainDN = $Script:LDAPContext.DomainDN

            # Closure-visible state
            $showDefaults = [bool]$IncludeDefaults
            $linkage = $gpoLinkage
            $statusMap = $gpoStatusMap
            $dcOU = if ($domainDN) { "OU=Domain Controllers,$domainDN" } else { $null }
            $Script:gpoUserRightsFindings = @()

            # Records whether the Policies path was actually read. Without it an empty
            # result cannot be told apart from a scan that never ran, and the check
            # reported a failed SMB access as a clean domain. Cleared inline below.
            $Script:gpoUserRightsSysvolScanned = $false

            Invoke-SMBAccess -Description "Scanning GPO user rights assignments" -ScriptBlock {
                $sysvolPath = "\\$dcServer\SYSVOL\$domainFQDN\Policies"
                if (-not (Test-Path $sysvolPath)) {
                    Write-Log "[Get-GPOUserRightsAssignment] SYSVOL path not accessible: $sysvolPath"
                    return
                }

                $Script:gpoUserRightsSysvolScanned = $true

                # Iterate the cached SYSVOL listing instead of probing a constructed path per
                # GPO: most GPOs have no GptTmpl.inf, so per-GPO probing costs one SMB round
                # trip each for a file that usually does not exist.
                $gptTmplFiles = @(Get-CachedSYSVOLFiles -Filter "GptTmpl.inf")

                $gpoByGuid = @{}
                foreach ($g in $gpos) {
                    if ($g.Name) { $gpoByGuid[([string]$g.Name).ToUpper()] = $g }
                }

                $totalGPOs = $gptTmplFiles.Count
                $currentGPOIndex = 0
                foreach ($file in $gptTmplFiles) {
                    if ($file.FullName -notmatch '\\Policies\\(\{[^}]+\})\\') { continue }
                    $gpoGUIDKey = $Matches[1].ToUpper()
                    $gpo = $gpoByGuid[$gpoGUIDKey]
                    if (-not $gpo) { continue }

                    # [Privilege Rights] is a Computer Configuration section, and its file
                    # is {GUID}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf. A GPO can
                    # carry a second GptTmpl.inf under USER\, and this loop took any file
                    # sitting below the GUID folder: user-scope content was then read as a
                    # privilege assignment on every machine the policy reaches, and where
                    # both files named the same right the GPO was reported twice for it -
                    # two rows a reader has no way to tell apart. Get-GPORegistrySettings
                    # makes the same distinction for Registry.pol.
                    if ($file.FullName -notmatch '(?i)\\Policies\\\{[^}]+\}\\MACHINE\\') { continue }

                    $currentGPOIndex++
                    if ($totalGPOs -gt $Script:ProgressThreshold) {
                        Show-Progress -Activity "Scanning GPO user rights assignments" -Current $currentGPOIndex -Total $totalGPOs -ObjectName $gpo.displayName
                    }

                    $content = Get-CachedSYSVOLContent -Path $file.FullName
                    if (-not $content) { continue }
                    if ($content -notmatch '(?is)\[Privilege Rights\](.*?)(\[|$)') { continue }
                    $section = $Matches[1]

                    # ----- Where this policy applies -----
                    #
                    # The full link records go to the display, disabled ones included: the
                    # LinkedOUs transformer marks those with "(link disabled)", and dropping
                    # them here meant a policy whose only link is switched off looked exactly
                    # like one that was never linked at all. The active subset still decides
                    # which baseline applies, because a disabled link reaches no machine.
                    # $null only when the linkage was never resolved. A GUID that is simply
                    # absent from a resolved map means no links, which is @() - and
                    # @($linkage[$missingKey]) would be an array holding one $null.
                    $links = $null
                    if ($linkage) {
                        $links = @()
                        if ($linkage.ContainsKey($gpoGUIDKey)) { $links = @($linkage[$gpoGUIDKey]) }
                    }
                    $activeLinks = @()
                    if ($links) {
                        $activeLinks = @($links | Where-Object { $_.LinkStatus -ne "Disabled" })
                    }
                    $linkedOUs = @($activeLinks | ForEach-Object { $_.DistinguishedName })
                    $isDomainWide = ($null -ne ($activeLinks | Where-Object { $_.Scope -eq "Domain" }))

                    # ----- Which default set to measure against -----
                    #
                    # The Default Domain Controllers Policy carries a well-known GUID, and
                    # any policy linked at or below the Domain Controllers OU reaches a DC
                    # as well. A domain-wide link reaches both kinds of machine, so both
                    # baselines count and the union is what is expected.
                    $reachesDC = ($gpoGUIDKey -eq '{6AC1786C-016F-11D2-945F-00C04FB984F9}') -or $isDomainWide
                    $reachesMember = $isDomainWide -or ($linkedOUs.Count -eq 0)
                    foreach ($linkDN in $linkedOUs) {
                        if ($dcOU -and "$linkDN".EndsWith($dcOU, [System.StringComparison]::OrdinalIgnoreCase)) {
                            $reachesDC = $true
                        } else {
                            $reachesMember = $true
                        }
                    }
                    # An unlinked policy is measured against the member set, the stricter of
                    # the two - it is the assumption that reports more, and reporting more
                    # about a policy that reaches nothing today costs nothing.
                    if (-not $reachesDC -and -not $reachesMember) { $reachesMember = $true }

                    $scopes = @()
                    if ($reachesMember) { $scopes += 'Member' }
                    if ($reachesDC)     { $scopes += 'DC' }

                    $machineScope = if ($reachesDC -and $reachesMember) {
                        'Domain Controllers and member computers'
                    } elseif ($reachesDC) {
                        'Domain Controllers'
                    } else {
                        'Member computers'
                    }

                    # ----- Compare every right the table knows -----
                    foreach ($right in $Script:UserRightsBaseline.Keys) {
                        # [ \t] around the '=', not \s: \s matches a newline. A right that is
                        # present but assigned to nobody - "SeCreateTokenPrivilege =" - let
                        # \s* swallow the line break, and (.+) then captured the whole next
                        # line as the principal list.
                        #
                        # [^\r\n]* rather than (.+): the value ends at the line, and an
                        # emptied right captures nothing - which is a real statement, because
                        # an emptied right removes every default holder.
                        $pattern = '(?im)^[ \t]*' + [regex]::Escape($right) + '[ \t]*=[ \t]*([^\r\n]*)'
                        $m = [regex]::Match($section, $pattern)
                        if (-not $m.Success) { continue }

                        # Resolve every token to a SID. GptTmpl.inf almost always writes *SID,
                        # but a hand-edited file can carry a name, and the comparison below is
                        # SID based - a name reaching it unresolved would count as a deviation
                        # against a baseline written in SIDs.
                        $holderSIDs = @()
                        $unresolved = @()
                        foreach ($token in ($m.Groups[1].Value -split ',')) {
                            $raw = $token.Trim().TrimStart('*')
                            if ([string]::IsNullOrWhiteSpace($raw)) { continue }

                            if ($raw -match '^S-1-') {
                                $holderSIDs += $raw
                                continue
                            }

                            $resolved = $null
                            try { $resolved = ConvertTo-SID -Identity $raw } catch { }
                            if ($resolved) { $holderSIDs += $resolved } else { $unresolved += $raw }
                        }

                        $comparison = Compare-UserRightAssignment -Right $right -HolderSID $holderSIDs -Scope $scopes
                        if (-not $comparison) { continue }

                        # A right with no documented default falls back to the identity
                        # filter rather than calling every holder a deviation.
                        $added = @($comparison.Added)
                        if (-not $comparison.HasBaseline) {
                            $added = @($added | Where-Object {
                                -not ((Test-IsPrivilegedSID -SID $_) -or
                                      [bool](Test-IsPrivilegedRID -SID $_) -or
                                      ($Script:OperatorSIDs -contains $_) -or
                                      (Test-IsWellKnownServiceSID -SID $_))
                            })
                        }

                        $removed = @($comparison.Removed)

                        # An unresolvable name cannot be compared, so it is reported rather
                        # than dropped - silently discarding a holder is the one outcome a
                        # rights check must not produce.
                        $hasDeviation = ($added.Count -gt 0) -or ($removed.Count -gt 0) -or ($unresolved.Count -gt 0)
                        if (-not $hasDeviation -and -not $showDefaults) { continue }

                        $addedNames = @($added | ForEach-Object { ConvertFrom-SID -SID $_ })
                        if ($unresolved.Count -gt 0) {
                            $addedNames += @($unresolved | ForEach-Object { "$_ [unresolved]" })
                        }
                        $removedNames = @($removed | ForEach-Object { ConvertFrom-SID -SID $_ })

                        # A broad group holding a sensitive right is not a delegation, it is
                        # a configuration accident, and it outranks the right's own tier.
                        $anyBroad = $false
                        foreach ($sid in $added) {
                            if ((Test-IsBroadGroupSID -SID $sid) -or [bool](Test-IsBroadGroupRID -SID $sid)) {
                                $anyBroad = $true
                                break
                            }
                        }

                        $severity = if ($added.Count -eq 0 -and $unresolved.Count -eq 0) {
                            # Only default holders removed. Hardening more often than not,
                            # and never something to raise as an exposure.
                            'Note'
                        } elseif ($anyBroad) {
                            'Finding'
                        } else {
                            $comparison.Tier
                        }

                        $finding = [PSCustomObject]@{
                            gpoName          = $gpo.displayName
                            gpoGuid          = $gpo.Name
                            userRight        = $right
                            userRightName    = $comparison.Name
                            whyItMatters     = $comparison.Why
                            appliesTo        = $machineScope
                            grantedBeyondDefault = $addedNames
                            removedFromDefault   = $removedNames
                            LinkedOUs        = $(if ($null -eq $links) { 'Unknown - linkage could not be resolved' } else { $links })
                            _severity        = $severity
                        }

                        if (-not $comparison.HasBaseline) {
                            $finding | Add-Member -NotePropertyName 'baselineUnknown' `
                                -NotePropertyValue 'Windows publishes no fixed default set for this right, so the holders above were filtered by identity instead of compared. Judge them against what this domain actually runs.' -Force
                        }

                        $gpoStatus = Get-GPOEffectiveStatus -StatusEntry $statusMap[$gpoGUIDKey] `
                            -Scope 'Machine' -Link $(if ($null -eq $linkage) { $null } else { $links })
                        if ($gpoStatus) {
                            $finding | Add-Member -NotePropertyName 'GPOStatus' -NotePropertyValue $gpoStatus -Force
                        }

                        $Script:gpoUserRightsFindings += $finding
                    }
                }

                if ($totalGPOs -gt $Script:ProgressThreshold) {
                    Show-Progress -Activity "Scanning GPO user rights assignments" -Completed
                }
            }

            $findings = @($Script:gpoUserRightsFindings)
            $Script:gpoUserRightsFindings = $null
            $sysvolScanned = [bool]$Script:gpoUserRightsSysvolScanned
            $Script:gpoUserRightsSysvolScanned = $null

            if ($findings.Count -gt 0) {
                $deviations = @($findings | Where-Object { $_._severity -ne 'Note' })
                $hasFinding = @($findings | Where-Object { $_._severity -eq 'Finding' }).Count -gt 0
                $headerClass = if ($hasFinding) { "Finding" } else { "Hint" }

                if ($deviations.Count -gt 0) {
                    Show-Line "Found $($deviations.Count) user right assignment(s) that depart from the Windows default:" -Class $headerClass
                } else {
                    Show-Line "No user right is granted beyond the Windows default" -Class "Secure"
                }

                $removalsOnly = @($findings | Where-Object { $_._severity -eq 'Note' })
                if ($removalsOnly.Count -gt 0) {
                    Show-Line "$($removalsOnly.Count) assignment(s) only remove default holders - hardening, or a service about to break" -Class "Note"
                }

                # Findings first, then hints, then the removals
                $ordered = @($findings | Sort-Object @{Expression={
                    switch ($_._severity) { 'Finding' { 0 } 'Hint' { 1 } default { 2 } }
                }}, gpoName, userRight)
                foreach ($finding in $ordered) {
                    $finding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPOUserRights' -Force
                    Show-Object $finding -Class $finding._severity
                }
            } elseif ((Test-SysvolAccessible) -eq $false) {
                # SYSVOL could not be read - report honestly instead of implying a clean result
                Show-Line "SYSVOL is not accessible - GPO user rights could not be evaluated" -Class "Note"
            } elseif (-not $sysvolScanned) {
                # SYSVOL answers in general, but this scan never got to read the Policies
                # path. Without this branch the check fell through to the Secure message
                # below and reported a blind scan as a clean domain.
                Show-Line "SYSVOL access failed - GPO user rights could not be evaluated - SMB access failed (authentication/network issue)" -Class "Finding"
            } else {
                Show-Line "Every user right assigned via GPO matches the Windows default" -Class "Secure"
            }

        } catch {
            Write-Log "[Get-GPOUserRightsAssignment] Error: $_" -Level Error
            Show-Line "Error during check: $_" -Class "Finding"
        } finally {
            $Script:gpoUserRightsFindings = $null
        }
    }

    end {
        Write-Log "[Get-GPOUserRightsAssignment] Check completed"
    }
}
