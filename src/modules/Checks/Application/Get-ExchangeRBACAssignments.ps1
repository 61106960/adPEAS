function Get-ExchangeRBACAssignments {
    <#
    .SYNOPSIS
    Reports who holds the Exchange management roles that grant access to mailbox content
    or allow self-escalation inside Exchange.

    .DESCRIPTION
    Exchange stores its Role Based Access Control model in the Configuration partition,
    where every assignment is an msExchRoleAssignment object linking a role
    (msExchRoleLink) to a principal (msExchUserLink). Any domain user can read it.

    Checking the Organization Management group alone is not enough: a role can be assigned
    straight to a single user, and such an assignment appears in no group membership at
    all. This check reads the assignments themselves.

    Roles reported:
    - Mailbox Import Export       - export the contents of any mailbox to a file
    - ApplicationImpersonation    - act as any mailbox over EWS
    - Role Management             - grant oneself any other Exchange role
    - Unscoped Role Management    - publish a role that runs arbitrary code
    - Mailbox Search              - search the contents of every mailbox
    - Active Directory Permissions - change Active Directory ACLs through Exchange

    Assignments that match the role group Exchange ships them on are reported as expected;
    everything else is a finding.

    A delegating assignment does not give the assignee the role - it gives the right to
    assign the role to others. Exchange setup creates one for Organization Management on
    practically every role, and those are expected; a delegating assignment anywhere else
    is a finding on the role it hands out. Delegating is bit 49 of
    msExchRoleAssignmentFlags. Microsoft does not document the bit; it was measured against
    Get-ManagementRoleAssignment on an Exchange organization (set on all 87 delegating
    assignments, on none of the 122 regular ones).

    Known limitations:
    - Roles are matched by name, so a custom role derived from one of the parents above
      carries a different name and is not matched.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-ExchangeRBACAssignments
    Reports the high-value Exchange role assignments in the current forest.

    .EXAMPLE
    Get-ExchangeRBACAssignments -Domain "contoso.com" -Credential (Get-Credential)
    Reports the role assignments with explicit credentials.

    .NOTES
    Category: Application
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
        Write-Log "[Get-ExchangeRBACAssignments] Starting check"
    }

    process {
        try {
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            Show-SubHeader "Checking Exchange management role assignments..." -ObjectType "ExchangeRoleAssignment"

            $configDN = $Script:LDAPContext.ConfigurationNamingContext
            $exchangeBase = "CN=Microsoft Exchange,CN=Services,$configDN"

            # No organization means no RBAC container to read. Said out loud rather than
            # logged, so a check that produced no rows is not mistaken for a clean result.
            $exchangeOrgs = @()
            try {
                $exchangeOrgs = @(Get-DomainObject -LDAPFilter "(objectClass=msExchOrganizationContainer)" -SearchBase $exchangeBase @PSBoundParameters)
            }
            catch {
                Write-Log "[Get-ExchangeRBACAssignments] Exchange Organization not found: $_"
            }

            if (@($exchangeOrgs).Count -eq 0) {
                Show-Line "No Exchange Organization detected - no role assignments to analyze" -Class Note
                return
            }

            # The roles worth reporting, with the role group Exchange assigns them to out of
            # the box. An empty default list means Exchange ships the role unassigned, so
            # every assignment of it was made by someone. These are regular assignments;
            # the delegating ones Exchange ships all sit on Organization Management (below).
            #
            # ApplicationImpersonation ships on Hygiene Management, for the anti-spam
            # integration - measured, and listed in the built-in role groups.
            #
            # Verdict text: each entry starts with its own distinct word. The finding table
            # is an unordered hashtable, so when two triggers on one attribute can both
            # match a value, which one wins is undefined - the strings are kept mutually
            # exclusive to avoid that.
            $watchedRoles = @{
                'mailbox import export' = @{
                    Defaults = @()
                    Verdict  = 'Mailbox export - the assignee can export the contents of any mailbox to a file'
                }
                'applicationimpersonation' = @{
                    Defaults = @('Hygiene Management')
                    Verdict  = 'Mailbox impersonation - the assignee can act as any mailbox over EWS'
                }
                'role management' = @{
                    Defaults = @('Organization Management')
                    Verdict  = 'Role management - the assignee can grant itself any other Exchange role'
                }
                'unscoped role management' = @{
                    Defaults = @()
                    Verdict  = 'Unscoped role management - the assignee can publish a role that runs arbitrary code'
                }
                'mailbox search' = @{
                    Defaults = @('Discovery Management')
                    Verdict  = 'Mailbox search - the assignee can search the contents of every mailbox'
                }
                'active directory permissions' = @{
                    Defaults = @('Organization Management')
                    Verdict  = 'Directory permissions - the assignee can change Active Directory ACLs through Exchange'
                }
            }

            $roleAssignments = @()
            try {
                $roleAssignments = @(Get-DomainObject -LDAPFilter "(objectClass=msExchRoleAssignment)" -SearchBase $exchangeBase @PSBoundParameters)
            }
            catch {
                Write-Log "[Get-ExchangeRBACAssignments] Error querying role assignments: $_" -Level Error
                Show-Line "Exchange role assignments could not be read - result unknown, not empty" -Class Hint
                return
            }

            if (@($roleAssignments).Count -eq 0) {
                # Setup creates the role assignments with the organization, several hundred
                # of them, so none readable is a container this account may not see rather
                # than an empty one. Measured with a domain user against Exchange SE, where
                # the RBAC container is not readable.
                Show-Line "No Exchange role assignment is readable by this account - result unknown, not empty" -Class Hint
                return
            }

            Write-Log "[Get-ExchangeRBACAssignments] Read $(@($roleAssignments).Count) role assignment(s)"

            # Resolved assignees, keyed by DN. A role group holding several watched roles
            # would otherwise be read once per assignment.
            $assigneeCache = @{}
            $results = @()

            foreach ($assignment in $roleAssignments) {
                $roleDN = [string]$assignment.msExchRoleLink
                $userDN = [string]$assignment.msExchUserLink
                if (-not $roleDN -or -not $userDN) { continue }

                # Leaf RDN of the role DN. The escape-aware pattern matters because a DN
                # value may contain an escaped comma; role names do not, but parsing a DN
                # by splitting on commas is how that stops being true one day.
                if ($roleDN -notmatch '^CN=((?:[^,\\]|\\.)+),') { continue }
                $roleName = $Matches[1] -replace '\\(.)', '$1'

                $roleKey = $roleName.ToLower()
                if (-not $watchedRoles.ContainsKey($roleKey)) { continue }
                $roleInfo = $watchedRoles[$roleKey]

                # A role assignment policy is not a directory principal and does not resolve
                # in the domain partition - it lives under CN=Policies,CN=RBAC. It also
                # matters more than a group would: a policy applies to every mailbox that
                # carries it, so a watched role assigned through one reaches all of them.
                $assigneeName = $null
                $assigneeType = $null
                # Reset with the other two: only the principal branch below sets it, and a
                # policy assignment used to inherit the object of the assignment before it -
                # and that account's privilege verdict with it.
                $assigneeObject = $null

                if ($userDN -match ',CN=Policies,CN=RBAC,') {
                    if ($userDN -match '^CN=((?:[^,\\]|\\.)+),') {
                        $assigneeName = $Matches[1] -replace '\\(.)', '$1'
                    } else {
                        $assigneeName = $userDN
                    }
                    $assigneeType = 'Role assignment policy'
                }
                else {
                    if (-not $assigneeCache.ContainsKey($userDN)) {
                        $resolved = $null
                        try {
                            $resolved = @(Get-DomainObject -Identity $userDN @PSBoundParameters)[0]
                        }
                        catch {
                            Write-Log "[Get-ExchangeRBACAssignments] Could not resolve assignee ${userDN}: $_"
                        }
                        $assigneeCache[$userDN] = $resolved
                    }

                    $assigneeObject = $assigneeCache[$userDN]

                    if ($assigneeObject) {
                        $assigneeName = if ($assigneeObject.sAMAccountName) {
                            [string]$assigneeObject.sAMAccountName
                        } elseif ($assigneeObject.cn) {
                            [string]$assigneeObject.cn
                        } else {
                            $userDN
                        }

                        $objectClasses = @($assigneeObject.objectClass)
                        if ($objectClasses -icontains 'computer') {
                            $assigneeType = 'Computer'
                        }
                        elseif ($objectClasses -icontains 'group') {
                            # Test-IsExchangeServiceGroup answers this without matching on a
                            # group name: it decides by the OU Exchange setup creates.
                            $exchangeGroupCheck = Test-IsExchangeServiceGroup -Identity $userDN
                            $assigneeType = if ($exchangeGroupCheck.IsExchangeService) { 'Exchange role group' } else { 'Group' }
                        }
                        elseif ($objectClasses -icontains 'user') {
                            $assigneeType = 'User'
                        }
                        else {
                            $assigneeType = 'Unknown'
                        }
                    }
                    else {
                        # A principal from another domain in the forest, or one this account
                        # cannot read. Reported as unresolved rather than dropped.
                        $assigneeName = $userDN
                        $assigneeType = 'Unresolved'
                    }
                }

                # Is this the assignment Exchange shipped? The role group names are created
                # by Exchange setup and are English in every installation, which is the same
                # basis Test-IsExchangeServiceGroup already relies on for its OU name.
                $assigneeRDN = $assigneeName
                if ($userDN -match '^CN=((?:[^,\\]|\\.)+),') {
                    $assigneeRDN = $Matches[1] -replace '\\(.)', '$1'
                }

                # Delegating or regular. A delegating assignment does not give its holder the
                # role, only the right to assign it, and Exchange setup creates one for
                # Organization Management on practically every role. Read as role holders,
                # they made findings of every standard installation: ApplicationImpersonation,
                # Unscoped Role Management and Mailbox Import Export, each "assigned" to
                # Organization Management.
                #
                # Bit 49 of msExchRoleAssignmentFlags, measured against
                # Get-ManagementRoleAssignment: set on all 87 delegating assignments of an
                # organization and on none of its 122 regular ones. Bit 50 behaved the same;
                # nothing measured tells the two apart, so 49 is a choice, not a finding. The
                # "-Delegating" name suffix is no substitute - Exchange cuts the name at 64
                # characters, and four of the 87 had lost it. A value that cannot be read
                # counts as regular, which is what every assignment was taken for before.
                $isDelegating = $false
                $rawRoleFlags = $assignment.msExchRoleAssignmentFlags
                $parsedRoleFlags = [int64]0
                if ($null -ne $rawRoleFlags -and [int64]::TryParse([string]@($rawRoleFlags)[0], [ref]$parsedRoleFlags)) {
                    $isDelegating = ($parsedRoleFlags -band ([int64]1 -shl 49)) -ne 0
                }

                $isDefaultAssignment = if ($isDelegating) {
                    ($assigneeType -eq 'Exchange role group') -and ($assigneeRDN -eq 'Organization Management')
                } else {
                    ($assigneeType -eq 'Exchange role group') -and (@($roleInfo.Defaults) -contains $assigneeRDN)
                }

                # The verdict for a delegating assignment keeps the role's own first words,
                # so it opens the role's card: the capability at stake is the role's, one
                # assignment away.
                $roleVerdict = if ($isDelegating) {
                    "$(($roleInfo.Verdict -split ' - ', 2)[0]) by delegation - the assignee does not hold the role but can assign it to any principal, an account it controls included"
                } else {
                    $roleInfo.Verdict
                }

                # What the assignee already holds. A Domain Admin with Mailbox Import Export
                # gains nothing from the assignment - that account reaches every mailbox
                # anyway - while a help desk group with the same role is the finding. Both
                # were reported identically, and the output is sorted by role name, so the
                # one that matters sat wherever the alphabet put it.
                #
                # Asked by SID where the object was resolved, with -IncludeOperators for the
                # same reason the roasting checks use it: an Account Operator can reset the
                # password of the accounts that hold the role.
                $assigneePrivileged = $null
                if ($assigneeObject -and $assigneeObject.objectSid) {
                    try {
                        $assigneePrivileged = Test-IsPrivileged -Identity ([string]$assigneeObject.objectSid) -IncludeOperators
                    } catch {
                        Write-Log "[Get-ExchangeRBACAssignments] Privilege check failed for '$assigneeName': $_"
                    }
                }

                if ($isDefaultAssignment -and $isDelegating) {
                    $verdict = "Default assignment - Organization Management can assign $roleName to others as shipped by Exchange; the delegating assignment does not give it the role"
                    $consoleClass = 'Hint'
                } elseif ($isDefaultAssignment) {
                    $verdict = "Default assignment - $roleName is assigned to $assigneeRDN as shipped by Exchange"
                    $consoleClass = 'Hint'
                } elseif ($assigneePrivileged -and $assigneePrivileged.IsPrivileged -eq $true) {
                    $verdict = "$roleVerdict The assignee is already privileged ($($assigneePrivileged.Reason)), so the role grants it nothing it could not reach anyway - the assignment is worth removing as hygiene, not as an escalation path."
                    $consoleClass = 'Hint'
                } else {
                    $verdict = $roleVerdict
                    $consoleClass = 'Finding'
                }

                # Organization Management holds Role Management both ways, so the name says
                # which of the two rows this is.
                $resultObj = [PSCustomObject]@{
                    Name           = "$roleName -> $assigneeName$(if ($isDelegating) { ' (delegating)' })"
                    RoleName       = $roleName
                    Assignee       = $assigneeName
                    AssigneeType   = $assigneeType
                    AssignmentType = if ($isDelegating) { 'Delegating - may assign the role, does not hold it' } else { 'Regular' }
                    RiskVerdict    = $verdict
                }

                if ($assigneePrivileged -and $assigneePrivileged.IsPrivileged -eq $true) {
                    $resultObj | Add-Member -NotePropertyName 'assigneePrivilege' -NotePropertyValue (
                        "Already privileged: $($assigneePrivileged.Reason)") -Force
                }

                # Who holds a role assigned to a group: its members. For the role groups
                # Exchange ships these roles on - Discovery Management with Mailbox Search,
                # Hygiene Management with ApplicationImpersonation - the assignment is the
                # expected one, and only the membership says who reads every mailbox in
                # this organization. Direct members, by name; a nested group is named as one.
                if ($assigneeObject -and @($assigneeObject.objectClass) -icontains 'group' -and -not $isDelegating) {
                    $memberNames = @(@($assigneeObject.member) | Where-Object { $_ } | ForEach-Object {
                        if ("$_" -match '^CN=((?:[^,\\]|\\.)+),') { $Matches[1] -replace '\\(.)', '$1' } else { "$_" }
                    } | Sort-Object)
                    $membersText = if ($memberNames.Count -eq 0) {
                        'No direct members'
                    } else {
                        $shownMembers = @($memberNames | Select-Object -First 20) -join ', '
                        if ($memberNames.Count -gt 20) { $shownMembers = "$shownMembers, ... and $($memberNames.Count - 20) more" }
                        "$($memberNames.Count) direct member(s): $shownMembers"
                    }
                    $resultObj | Add-Member -NotePropertyName 'assigneeMembers' -NotePropertyValue $membersText -Force
                }

                # Scope is reported only from a scope object that actually exists. Exchange
                # also encodes implicit scopes in attributes whose values are not published,
                # so the absent case is stated as "no custom scope object", which is what
                # was observed, rather than as "organization-wide", which would be a guess.
                $recipientScope = [string]$assignment.msExchRecipientWriteScopeLink
                $configScope = [string]$assignment.msExchConfigWriteScopeLink
                $scopeNames = @()
                foreach ($scopeDN in @($recipientScope, $configScope)) {
                    if ($scopeDN -and $scopeDN -match '^CN=((?:[^,\\]|\\.)+),') {
                        $scopeNames += ($Matches[1] -replace '\\(.)', '$1')
                    }
                }
                $resultObj | Add-Member -NotePropertyName 'AssignmentScope' -NotePropertyValue $(
                    if (@($scopeNames).Count -gt 0) { $scopeNames -join ', ' }
                    else { 'No custom management scope attached' }
                ) -Force

                $resultObj | Add-Member -NotePropertyName 'AssigneeDN' -NotePropertyValue $userDN -Force
                $resultObj | Add-Member -NotePropertyName 'distinguishedName' -NotePropertyValue ([string]$assignment.distinguishedName) -Force
                $resultObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'ExchangeRoleAssignment' -Force
                $resultObj | Add-Member -NotePropertyName 'ConsoleClass' -NotePropertyValue $consoleClass -Force

                $results += $resultObj
            }

            if (@($results).Count -eq 0) {
                Show-Line "None of the high-value Exchange roles is assigned ($(@($roleAssignments).Count) role assignment(s) examined)" -Class Secure
                return
            }

            $unexpected = @($results | Where-Object { $_.ConsoleClass -eq 'Finding' })
            if (@($unexpected).Count -gt 0) {
                Show-Line "Found $(@($unexpected).Count) high-value Exchange role assignment(s) beyond the roles Exchange ships assigned" -Class Finding
            } else {
                Show-Line "The high-value Exchange roles are assigned only to the role groups Exchange ships them on" -Class Hint
            }

            # Findings first, then the shipped defaults, each group by role name so repeated
            # runs against the same organization produce the same order.
            $ordered = @($results | Sort-Object -Property `
                @{ Expression = { if ($_.ConsoleClass -eq 'Finding') { 0 } else { 1 } } }, `
                @{ Expression = { $_.RoleName } }, `
                @{ Expression = { $_.Assignee } })

            foreach ($result in $ordered) {
                Show-Object $result -Class $result.ConsoleClass
            }
        }
        catch {
            Write-Log "[Get-ExchangeRBACAssignments] Error: $_" -Level Error
            Show-Line "Error during Exchange role assignment check: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-ExchangeRBACAssignments] Check completed"
    }
}
