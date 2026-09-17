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

    Known limitations:
    - Roles are matched by name, so a custom role derived from one of the parents above
      carries a different name and is not matched.
    - Whether an assignment is delegating (the assignee may pass the role on) is held in
      msExchRoleAssignmentFlags, whose bit values Microsoft does not publish. It is not
      reported rather than reported wrongly.

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
            # every assignment of it was made by someone.
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
                    Defaults = @()
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
                Show-Line "No Exchange role assignments found in the Configuration partition" -Class Note
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

                $isDefaultAssignment = ($assigneeType -eq 'Exchange role group') -and
                                       (@($roleInfo.Defaults) -contains $assigneeRDN)

                if ($isDefaultAssignment) {
                    $verdict = "Default assignment - $roleName is assigned to $assigneeRDN as shipped by Exchange"
                    $consoleClass = 'Hint'
                } else {
                    $verdict = $roleInfo.Verdict
                    $consoleClass = 'Finding'
                }

                $resultObj = [PSCustomObject]@{
                    Name         = "$roleName -> $assigneeName"
                    RoleName     = $roleName
                    Assignee     = $assigneeName
                    AssigneeType = $assigneeType
                    RiskVerdict  = $verdict
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
