function Get-ProtectedUsersStatus {
    <#
    .SYNOPSIS
    Analyzes Protected Users coverage for Tier-0 accounts.

    .DESCRIPTION
    Evaluates how many true Tier-0 accounts are protected by the "Protected Users" security group.

    Tier-0 Definition (accounts that SHOULD be protected):
    - Domain Admins members
    - Enterprise Admins members (forest root)
    - Schema Admins members (forest root)
    - BUILTIN\Administrators members on DCs

    Excluded from protection metric (cannot use Protected Users):
    - krbtgt (service account)
    - DC$ computer accounts
    - gMSA accounts

    Additionally reports Operator group status (informational):
    - Account Operators
    - Backup Operators
    - Server Operators
    - Print Operators

    Severity based on protection coverage:
    - >80% protected = Secure
    - 20-80% protected = Hint
    - <20% protected = Finding

    Protected Users Security Features:
    - No NTLM, Digest, or CredSSP authentication
    - No DES/RC4 encryption for Kerberos (AES only), which also means an AS-REP for a
      member with DONT_REQ_PREAUTH comes back AES-encrypted: far slower to crack, not
      impossible. Enforcing pre-authentication is NOT among the documented effects, and
      claiming it here read as immunity from AS-REP roasting
    - Kerberos TGT lifetime limited to 4 hours (instead of 10)
    - No delegation possible (Unconstrained/Constrained/RBCD)
    - Credential caching disabled

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-ProtectedUsersStatus

    .EXAMPLE
    Get-ProtectedUsersStatus -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Accounts
    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    begin {
        Write-Log "[Get-ProtectedUsersStatus] Starting check"
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            Show-SubHeader "Analyzing Protected Users coverage for Tier-0 accounts..." -ObjectType "Tier0Account"

            $domainDN = $Script:LDAPContext.DomainDN
            $domainSID = $Script:LDAPContext.DomainSID

            # Get Domain Functional Level
            $domainObj = @(Get-DomainObject -Identity $domainDN @PSBoundParameters)[0]

            $functionalLevelValue = if ($domainObj.'msDS-Behavior-Version') { [int]$domainObj.'msDS-Behavior-Version' } else { 0 }

            # Protected Users requires Windows Server 2012 R2 (Level 6) or higher
            if ($functionalLevelValue -lt 6) {
                Show-Line "Protected Users feature not available (requires Domain Functional Level 2012 R2+)" -Class Note
                return
            }

            # ===== Step 1: Get Protected Users group members =====
            $protectedUsersSID = "$domainSID-525"
            Write-Log "[Get-ProtectedUsersStatus] Looking for Protected Users group with SID: $protectedUsersSID"
            $protectedUsersGroup = @(Get-DomainGroup -Identity $protectedUsersSID @PSBoundParameters)[0]

            if (-not $protectedUsersGroup) {
                Show-Line "Protected Users group not found (should exist at this functional level)" -Class Hint
                return
            }

            # Who is protected, asked the way the Tier-0 side below asks: recursively, and
            # over every object class.
            #
            # Protected Users takes effect through the token, so a nested group protects its
            # members exactly as a direct membership does - and filling the group from a role
            # group is the usual arrangement in a larger environment. Read directly, as this
            # used to be, such a domain measured 0 of N protected, and the check printed
            # "Found N unprotected Tier-0 account(s) (0 of N in Protected Users, 0%)" as a
            # red finding while every one of those accounts was in fact protected. A
            # percentage is exactly the number a customer quotes.
            #
            # Get-DomainObject rather than Get-DomainUser for the same reason: a nested group
            # is not a user, so the per-member lookup returned nothing and dropped it without
            # a word.
            $protectedMemberSIDs = @{}
            $protectedUsersDN = [string]$protectedUsersGroup.distinguishedName
            if ($protectedUsersDN) {
                # Escape-LDAPFilterDN, not a local -replace chain: a group renamed to
                # something holding a parenthesis or an escaped comma otherwise produces a
                # filter the server rejects, and the whole measurement with it.
                $escapedProtectedDN = Escape-LDAPFilterDN -DistinguishedName $protectedUsersDN
                foreach ($protectedObj in @(Get-DomainObject -LDAPFilter "(memberOf:1.2.840.113556.1.4.1941:=$escapedProtectedDN)" -Properties 'objectSid', 'sAMAccountName', 'distinguishedName' @PSBoundParameters)) {
                    if (-not $protectedObj.objectSid) { continue }
                    $protectedName = [string]$protectedObj.sAMAccountName
                    if (-not $protectedName) { $protectedName = [string]$protectedObj.distinguishedName }
                    $protectedMemberSIDs[$protectedObj.objectSid] = $protectedName
                }
            }

            # The direct members as well. The recursive filter returns them too, so this
            # normally adds nothing; what it covers is the member object that filter cannot
            # return, and the case where the group DN could not be read above.
            if ($protectedUsersGroup.member) {
                foreach ($memberDN in @($protectedUsersGroup.member)) {
                    $memberObj = @(Get-DomainObject -Identity $memberDN -Properties 'objectSid', 'sAMAccountName' @PSBoundParameters)[0]
                    if (-not $memberObj -or -not $memberObj.objectSid) { continue }
                    if ($protectedMemberSIDs.ContainsKey($memberObj.objectSid)) { continue }
                    $directName = [string]$memberObj.sAMAccountName
                    if (-not $directName) { $directName = [string]$memberDN }
                    $protectedMemberSIDs[$memberObj.objectSid] = $directName
                }
            }

            # And the path neither of the two sees. primaryGroupID is a membership that
            # leaves no trace in member or memberOf, so LDAP_MATCHING_RULE_IN_CHAIN cannot
            # find it - the same gap Get-PrivilegedGroupMembers and
            # Get-PrivilegedAccountFilter already close for the privileged groups. Unusual
            # for Protected Users, and it costs one query.
            foreach ($primaryObj in @(Get-DomainObject -LDAPFilter '(primaryGroupID=525)' -Properties 'objectSid', 'sAMAccountName', 'distinguishedName' @PSBoundParameters)) {
                if (-not $primaryObj.objectSid) { continue }
                if ($protectedMemberSIDs.ContainsKey($primaryObj.objectSid)) { continue }
                $primaryName = [string]$primaryObj.sAMAccountName
                if (-not $primaryName) { $primaryName = [string]$primaryObj.distinguishedName }
                $protectedMemberSIDs[$primaryObj.objectSid] = $primaryName
            }

            Write-Log "[Get-ProtectedUsersStatus] Found $($protectedMemberSIDs.Count) members in Protected Users group"

            # ===== Step 2: Collect all Tier-0 account members =====
            # Get Tier-0 group SIDs from central definition
            $tier0GroupSIDs = Get-Tier0GroupSIDs -DomainSID $domainSID

            $tier0Accounts = @{}  # SID -> Account object (deduplicated)
            $tier0AccountGroups = @{}  # SID -> Array of group names (for display)

            foreach ($groupSID in $tier0GroupSIDs) {
                $groupObj = @(Get-DomainGroup -Identity $groupSID @PSBoundParameters)[0]

                if (-not $groupObj) {
                    # One entry of the Tier-0 list is an account: RID 500, the built-in
                    # Administrator. Asked for as a group it was never found - measured,
                    # "Group not found: <domain SID>-500" in every scan - so the account
                    # counted as Tier-0 only through a group it belongs to, and not at all
                    # once it belongs to none.
                    $builtinAdmin = $null
                    if ($groupSID -like "$domainSID-500") {
                        $builtinAdmin = @(Get-DomainUser -Identity $groupSID @PSBoundParameters)[0]
                    }
                    if ($builtinAdmin -and $builtinAdmin.objectSid) {
                        $adminSID = $builtinAdmin.objectSid
                        if (-not $tier0Accounts.ContainsKey($adminSID)) {
                            $tier0Accounts[$adminSID] = $builtinAdmin
                            $tier0AccountGroups[$adminSID] = @()
                        }
                        if ('Built-in Administrator (RID 500)' -notin $tier0AccountGroups[$adminSID]) {
                            $tier0AccountGroups[$adminSID] += 'Built-in Administrator (RID 500)'
                        }
                        continue
                    }
                    Write-Log "[Get-ProtectedUsersStatus] Group not found: $groupSID"
                    continue
                }

                $groupName = $groupObj.sAMAccountName
                Write-Log "[Get-ProtectedUsersStatus] Processing Tier-0 group: $groupName ($groupSID)"

                # Get recursive members using LDAP_MATCHING_RULE_IN_CHAIN
                $groupDN = $groupObj.distinguishedName
                # The central escaper rather than a local -replace chain: the two are meant
                # to do the same thing, and only one of them is tested.
                $escapedDN = Escape-LDAPFilterDN -DistinguishedName $groupDN

                # Query all users who are (recursively) members of this group
                $members = @(Get-DomainUser -LDAPFilter "(memberOf:1.2.840.113556.1.4.1941:=$escapedDN)" @PSBoundParameters)

                # And the members that filter cannot see. primaryGroupID puts the group's
                # RID in the account's token without appearing in member or memberOf, so a
                # Domain Admin held that way was not Tier-0 to this check and could never
                # show up as unprotected. Only for a group in this domain: a primaryGroupID
                # is a RID relative to the account's own domain, so a BUILTIN SID cannot be
                # one.
                if ($groupSID -like "$domainSID-*") {
                    $groupRID = $groupSID.Substring($domainSID.Length + 1)
                    if ($groupRID -match '^\d+$') {
                        $members += @(Get-DomainObject -LDAPFilter "(primaryGroupID=$groupRID)" @PSBoundParameters)
                    }
                }

                foreach ($member in $members) {
                    if (-not $member.objectSid) { continue }

                    $memberSID = $member.objectSid

                    # Add to deduplicated list
                    if (-not $tier0Accounts.ContainsKey($memberSID)) {
                        $tier0Accounts[$memberSID] = $member
                        $tier0AccountGroups[$memberSID] = @()
                    }

                    # Track which groups this account belongs to. The primaryGroupID query
                    # above can return an account the recursive filter already returned, so
                    # the group name must not be appended twice.
                    if ($groupName -notin $tier0AccountGroups[$memberSID]) {
                        $tier0AccountGroups[$memberSID] += $groupName
                    }
                }

                # Also add direct group members (Get-DomainGroup returns member DNs).
                #
                # The query above uses LDAP_MATCHING_RULE_IN_CHAIN, which returns every user
                # whose membership chain includes this group - direct members among them. So
                # a DN already accounted for needs no lookup of its own, and in a normal
                # domain that is all of them: this loop used to spend one LDAP round trip
                # per member of every Tier-0 group to re-read accounts it already had.
                # What is left is the case the recursive filter misses, such as a member
                # object that is not a user.
                if ($groupObj.member) {
                    $knownDNs = @{}
                    foreach ($knownAccount in $tier0Accounts.Values) {
                        if ($knownAccount.distinguishedName) {
                            $knownDNs[[string]$knownAccount.distinguishedName] = $true
                        }
                    }

                    foreach ($memberDN in @($groupObj.member)) {
                        if ($knownDNs.ContainsKey([string]$memberDN)) {
                            # Already collected by the recursive query; make sure the group
                            # is recorded against it and move on without asking again.
                            $knownAccount = $tier0Accounts.Values | Where-Object { $_.distinguishedName -eq $memberDN } | Select-Object -First 1
                            if ($knownAccount -and $knownAccount.objectSid -and
                                $groupName -notin $tier0AccountGroups[$knownAccount.objectSid]) {
                                $tier0AccountGroups[$knownAccount.objectSid] += $groupName
                            }
                            continue
                        }

                        $memberObj = @(Get-DomainUser -Identity $memberDN @PSBoundParameters)[0]
                        if ($memberObj -and $memberObj.objectSid) {
                            $memberSID = $memberObj.objectSid
                            if (-not $tier0Accounts.ContainsKey($memberSID)) {
                                $tier0Accounts[$memberSID] = $memberObj
                                $tier0AccountGroups[$memberSID] = @()
                            }
                            if ($groupName -notin $tier0AccountGroups[$memberSID]) {
                                $tier0AccountGroups[$memberSID] += $groupName
                            }
                        }
                    }
                }
            }

            Write-Log "[Get-ProtectedUsersStatus] Found $($tier0Accounts.Count) unique Tier-0 accounts"

            # ===== Step 3: Filter out excluded accounts (krbtgt, DCs, gMSAs) =====
            $eligibleAccounts = @{}
            $excludedAccounts = @{}
            $totalTier0 = @($tier0Accounts.Keys).Count
            $currentIndex = 0

            foreach ($sid in $tier0Accounts.Keys) {
                $currentIndex++
                if ($totalTier0 -gt $Script:ProgressThreshold) {
                    Show-Progress -Activity "Analyzing Tier0 account protection" -Current $currentIndex -Total $totalTier0 -ObjectName $tier0Accounts[$sid].sAMAccountName
                }
                $account = $tier0Accounts[$sid]
                $exclusionCheck = Test-IsExcludedFromProtectedUsers -Account $account

                if ($exclusionCheck.IsExcluded) {
                    $excludedAccounts[$sid] = @{
                        Account = $account
                        Reason = $exclusionCheck.Reason
                    }
                    Write-Log "[Get-ProtectedUsersStatus] Excluded: $($account.sAMAccountName) - $($exclusionCheck.Reason)"
                } else {
                    $eligibleAccounts[$sid] = $account
                }
            }
            if ($totalTier0 -gt $Script:ProgressThreshold) {
                Show-Progress -Activity "Analyzing Tier0 account protection" -Completed
            }

            Write-Log "[Get-ProtectedUsersStatus] Eligible for protection: $($eligibleAccounts.Count), Excluded: $($excludedAccounts.Count)"

            # ===== Step 4: Categorize eligible accounts =====
            $protectedTier0 = @()
            $unprotectedTier0 = @()

            foreach ($sid in $eligibleAccounts.Keys) {
                $account = $eligibleAccounts[$sid]
                $groups = $tier0AccountGroups[$sid] -join ', '

                if ($protectedMemberSIDs.ContainsKey($sid)) {
                    $protectedTier0 += [PSCustomObject]@{
                        Account = $account
                        Groups = $groups
                        IsProtected = $true
                    }
                } else {
                    $unprotectedTier0 += [PSCustomObject]@{
                        Account = $account
                        Groups = $groups
                        IsProtected = $false
                    }
                }
            }

            # ===== Step 4b: Authentication policy silos of the Tier-0 accounts =====
            # Protected Users and a silo are two halves of one protection: the group takes
            # NTLM, delegation and long-lived tickets away, the silo confines where the
            # account may sign on. Whether a silo applies cannot be read off the account -
            # the KDC needs the assignment, the membership and the silo's own enforcement -
            # so the rows say it. Nothing changes for an account without a link to a silo or
            # a policy, and without one the silos are not even read.
            $connectionParams = @{}
            foreach ($connectionKey in @('Domain', 'Server', 'Credential')) {
                if ($PSBoundParameters.ContainsKey($connectionKey)) { $connectionParams[$connectionKey] = $PSBoundParameters[$connectionKey] }
            }
            $authNRows = Get-Tier0AuthNPolicyRows -Account @($tier0Accounts.Values) -ConnectionParams $connectionParams

            # ===== Step 5: Calculate coverage and determine severity =====
            $totalEligible = $eligibleAccounts.Count
            $totalProtected = $protectedTier0.Count

            $coveragePercent = if ($totalEligible -gt 0) {
                [math]::Round(($totalProtected / $totalEligible) * 100, 1)
            } else { 0 }

            # Determine severity based on coverage
            $severity = if ($coveragePercent -gt 80) {
                'Secure'
            } elseif ($coveragePercent -ge 20) {
                'Hint'
            } else {
                'Finding'
            }

            # ===== Step 6: Display results =====
            # Show unprotected accounts (the main concern)
            if (@($unprotectedTier0).Count -gt 0) {
                # Combined summary with unprotected count - use "Found" wording for consistency
                $summaryText = "Found $($unprotectedTier0.Count) unprotected Tier-0 account(s) ($totalProtected of $totalEligible in Protected Users, $coveragePercent%):"
                Show-Line $summaryText -Class $severity

                foreach ($item in $unprotectedTier0) {
                    $account = $item.Account
                    # Add tier0Groups property for display
                    # No row saying NOT PROTECTED: the line above says it of every account it
                    # lists. The context carries the verdict, and the tier0Groups row - why the
                    # account is Tier-0 - carries the card (tier0_unprotected).
                    $account | Add-Member -NotePropertyName 'tier0Groups' -NotePropertyValue $item.Groups -Force
                    Add-Tier0AuthNPolicyRow -Account $account -Rows $authNRows
                    $account | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'Tier0Account' -Force
                    $account | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'Unprotected' -Force
                    # Finding, whatever the coverage line above says. That line rates the
                    # domain's posture and turns Secure above 80 percent; this object is one
                    # account outside Protected Users, and its tier0Groups row is red.
                    Show-Object $account -Class Finding
                }
            } else {
                # All accounts are protected (100% coverage)
                $summaryText = "Found $totalEligible Tier-0 account(s) - all in Protected Users ($coveragePercent%)"
                Show-Line $summaryText -Class $severity
            }

            # Show protected accounts (good)
            if (@($protectedTier0).Count -gt 0) {
                Show-Line "Protected Tier-0 accounts:" -Class Secure

                foreach ($item in $protectedTier0) {
                    $account = $item.Account
                    # Its tier0Groups row is green (tier0_protected) - see above.
                    $account | Add-Member -NotePropertyName 'tier0Groups' -NotePropertyValue $item.Groups -Force
                    Add-Tier0AuthNPolicyRow -Account $account -Rows $authNRows
                    $account | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'Tier0Account' -Force
                    $account | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'Protected' -Force
                    Show-Object $account -Class Secure
                }
            }

            # Show excluded accounts (informational)
            if (@($excludedAccounts.Keys).Count -gt 0) {
                Show-Line "$($excludedAccounts.Count) account(s) excluded from metric (not applicable for Protected Users):" -Class Note

                foreach ($sid in $excludedAccounts.Keys) {
                    $info = $excludedAccounts[$sid]
                    $account = $info.Account
                    $account | Add-Member -NotePropertyName 'excludedReason' -NotePropertyValue $info.Reason -Force
                    Add-Tier0AuthNPolicyRow -Account $account -Rows $authNRows
                    $account | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'Tier0Account' -Force
                    $account | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'Excluded' -Force
                    Show-Object $account -Class Note
                }
            }

            # ===== Step 7: Operator groups (informational) =====
            # Collect operator groups with members, display as PSCustomObjects
            $operatorFindings = @()

            foreach ($operatorSID in $Script:OperatorSIDs) {
                $operatorGroup = @(Get-DomainGroup -Identity $operatorSID @PSBoundParameters)[0]

                if (-not $operatorGroup) { continue }
                if (-not $operatorGroup.member) { continue }

                $memberCount = @($operatorGroup.member).Count
                if ($memberCount -eq 0) { continue }

                # Get member names and check protection status
                $memberNameList = @()
                $protectedCount = 0

                foreach ($memberDN in @($operatorGroup.member)) {
                    # Get-DomainObject, not Get-DomainUser: a nested group or a computer
                    # account in an operator group returned nothing here, so it was never
                    # counted as protected and the name fell back to the bare CN.
                    $memberObj = @(Get-DomainObject -Identity $memberDN -Properties 'objectSid' @PSBoundParameters)[0]
                    if ($memberObj -and $memberObj.objectSid) {
                        if ($protectedMemberSIDs.ContainsKey($memberObj.objectSid)) {
                            $protectedCount++
                        }
                        # Resolve SID to DOMAIN\sAMAccountName (handles cross-domain)
                        $resolvedName = ConvertFrom-SID -SID $memberObj.objectSid
                        $memberNameList += $resolvedName
                    } else {
                        # Fallback: extract CN from DN
                        if ($memberDN -match '^CN=([^,]+)') {
                            $memberNameList += $Matches[1]
                        } else {
                            $memberNameList += $memberDN
                        }
                    }
                }

                # Create PSCustomObject for display
                $operatorFindings += [PSCustomObject]@{
                    OperatorGroup = $operatorGroup.sAMAccountName
                    OperatorGroupDN = $operatorGroup.distinguishedName
                    MemberCount = $memberCount
                    ProtectedCount = $protectedCount
                    Members = $memberNameList -join "`n"
                }
            }

            # Only show if there are operator groups with members
            if (@($operatorFindings).Count -gt 0) {
                Show-Line "Operator groups with members (consider for Protected Users):" -Class Hint

                foreach ($finding in $operatorFindings) {
                    $finding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'OperatorGroup' -Force
                    Show-Object $finding -Class Hint
                }
            }

        } catch {
            Write-Log "[Get-ProtectedUsersStatus] Error: $_" -Level Error
            Show-Line "Error during check - the Protected Users coverage could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-ProtectedUsersStatus] Check completed"
    }
}

<#
.SYNOPSIS
    Whether an authentication policy silo or policy applies to each Tier-0 account.

.DESCRIPTION
    The KDC applies a silo to an account only when the silo is assigned to it
    (msDS-AssignedAuthNPolicySilo) and lists it among its members
    (msDS-AuthNPolicySiloMembers, seen from the account as msDS-AuthNPolicySiloMembersBL) -
    MS-KILE 3.3.5.4. For a silo member the silo's enforcement decides, and a policy
    assigned directly to the account applies only where no silo does (MS-KILE 3.3.5.5).
    Windows exempts the built-in Administrator from both.

    One row each, starting with its verdict so that each card's pattern stands alone:
    - authenticationPolicySilo: "Enforced: SILO", "Audit only: SILO", "No policy: SILO",
      "Not applied: SILO (assigned, not a member)", "Not applied: SILO (member, not
      assigned)", "Exempt: SILO (built-in Administrator)"
    - authenticationPolicy: "Enforced: POLICY", "Audit only: POLICY", "Superseded: POLICY
      (the silo's policy applies)", "Exempt: POLICY (built-in Administrator)"

    The silos and policies are read only when an account carries a link to one.

.PARAMETER Account
    The Tier-0 accounts.

.PARAMETER ConnectionParams
    Domain, Server and Credential of the calling check.

.OUTPUTS
    Hashtable: lowercased DN of an account -> hashtable of its rows. Accounts without a
    link are absent.
#>
function Get-Tier0AuthNPolicyRows {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [object[]]$Account = @(),

        [Parameter(Mandatory = $false)]
        [hashtable]$ConnectionParams = @{}
    )

    $rows = @{}
    $linked = @($Account | Where-Object {
        $_ -and ($_.'msDS-AssignedAuthNPolicySilo' -or $_.'msDS-AuthNPolicySiloMembersBL' -or $_.'msDS-AssignedAuthNPolicy')
    })
    if ($linked.Count -eq 0) { return $rows }

    $silos = @{}
    $policies = @{}
    $configNC = [string]$Script:LDAPContext.ConfigurationNamingContext
    if ($configNC) {
        $authNBase = "CN=AuthN Policy Configuration,CN=Services,$configNC"
        try {
            foreach ($silo in @(Get-DomainObject -LDAPFilter '(objectClass=msDS-AuthNPolicySilo)' -SearchBase $authNBase `
                    -Properties 'distinguishedName', 'name', 'msDS-AuthNPolicySiloEnforced', 'msDS-UserAuthNPolicy', 'msDS-ComputerAuthNPolicy', 'msDS-ServiceAuthNPolicy' @ConnectionParams)) {
                if ($silo.distinguishedName) { $silos[([string]$silo.distinguishedName).ToLowerInvariant()] = $silo }
            }
            foreach ($policy in @(Get-DomainObject -LDAPFilter '(objectClass=msDS-AuthNPolicy)' -SearchBase $authNBase `
                    -Properties 'distinguishedName', 'name', 'msDS-AuthNPolicyEnforced' @ConnectionParams)) {
                if ($policy.distinguishedName) { $policies[([string]$policy.distinguishedName).ToLowerInvariant()] = $policy }
            }
        } catch {
            Write-Log "[Get-ProtectedUsersStatus] The authentication policy silos could not be read: $_"
        }
    }

    foreach ($entry in $linked) {
        $isBuiltinAdmin = ([string]$entry.objectSid) -match '-500$'
        $assignedSilo = [string]@($entry.'msDS-AssignedAuthNPolicySilo')[0]
        $memberOf = @(@($entry.'msDS-AuthNPolicySiloMembersBL') | Where-Object { $_ } | ForEach-Object { [string]$_ })
        $entryRows = @{}

        $siloApplies = $false
        if ($assignedSilo) {
            $siloName = Get-Tier0AuthNName -DistinguishedName $assignedSilo -Known $silos
            $silo = $silos[$assignedSilo.ToLowerInvariant()]
            if ($isBuiltinAdmin) {
                $entryRows['authenticationPolicySilo'] = "Exempt: $siloName (built-in Administrator)"
            } elseif ($memberOf -notcontains $assignedSilo) {
                $entryRows['authenticationPolicySilo'] = "Not applied: $siloName (assigned, not a member)"
            } elseif (-not $silo) {
                $entryRows['authenticationPolicySilo'] = "Unknown: $siloName (the silo could not be read)"
            } elseif (([string]@($silo.'msDS-AuthNPolicySiloEnforced')[0]) -ne 'TRUE') {
                $entryRows['authenticationPolicySilo'] = "Audit only: $siloName"
            } elseif (-not ($silo.'msDS-UserAuthNPolicy' -or $silo.'msDS-ComputerAuthNPolicy' -or $silo.'msDS-ServiceAuthNPolicy')) {
                $entryRows['authenticationPolicySilo'] = "No policy: $siloName"
            } else {
                $entryRows['authenticationPolicySilo'] = "Enforced: $siloName"
                $siloApplies = $true
            }
        } elseif ($memberOf.Count -gt 0) {
            $names = @($memberOf | ForEach-Object { Get-Tier0AuthNName -DistinguishedName $_ -Known $silos }) -join ', '
            $entryRows['authenticationPolicySilo'] = "Not applied: $names (member, not assigned)"
        }

        $assignedPolicy = [string]@($entry.'msDS-AssignedAuthNPolicy')[0]
        if ($assignedPolicy) {
            $policyName = Get-Tier0AuthNName -DistinguishedName $assignedPolicy -Known $policies
            $policy = $policies[$assignedPolicy.ToLowerInvariant()]
            if ($isBuiltinAdmin) {
                $entryRows['authenticationPolicy'] = "Exempt: $policyName (built-in Administrator)"
            } elseif ($siloApplies) {
                $entryRows['authenticationPolicy'] = "Superseded: $policyName (the silo's policy applies)"
            } elseif ($policy -and ([string]@($policy.'msDS-AuthNPolicyEnforced')[0]) -eq 'TRUE') {
                $entryRows['authenticationPolicy'] = "Enforced: $policyName"
            } elseif ($policy) {
                $entryRows['authenticationPolicy'] = "Audit only: $policyName"
            } else {
                $entryRows['authenticationPolicy'] = "Unknown: $policyName (the policy could not be read)"
            }
        }

        if ($entryRows.Count -gt 0 -and $entry.distinguishedName) {
            $rows[([string]$entry.distinguishedName).ToLowerInvariant()] = $entryRows
        }
    }
    return $rows
}

<#
.SYNOPSIS
    The name of a silo or policy, from the object read or from its DN.
#>
function Get-Tier0AuthNName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName,

        [Parameter(Mandatory = $false)]
        [hashtable]$Known = @{}
    )

    $object = $Known[$DistinguishedName.ToLowerInvariant()]
    if ($object -and $object.name) { return [string]$object.name }
    if ($DistinguishedName -match '^CN=((?:\\.|[^,])+)') { return $Matches[1] }
    return $DistinguishedName
}

<#
.SYNOPSIS
    Puts the silo and policy rows Get-Tier0AuthNPolicyRows computed on an account.
#>
function Add-Tier0AuthNPolicyRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Account,

        [Parameter(Mandatory = $false)]
        [hashtable]$Rows = @{}
    )

    if (-not $Account -or -not $Account.distinguishedName) { return }
    $entryRows = $Rows[([string]$Account.distinguishedName).ToLowerInvariant()]
    if (-not $entryRows) { return }
    foreach ($rowName in @($entryRows.Keys)) {
        $Account | Add-Member -NotePropertyName $rowName -NotePropertyValue $entryRows[$rowName] -Force
    }
}
