function Get-AddComputerRights {
    <#
    .SYNOPSIS
    Analyzes "Add Computer to Domain" permissions and quota settings.

    .DESCRIPTION
    Performs comprehensive analysis of computer account creation permissions:

    1. ms-DS-MachineAccountQuota (Domain attribute)
       - Default: 10 (any authenticated user can add 10 computers)
       - Secure: 0 (only explicit permissions)

    2. ACL on the computer container (CN=Computers by default, redirectable)
       - CreateChild for the computer class, or GenericAll, on the container

    3. GPO User Rights Assignment
       - "Add workstations to domain" (SeMachineAccountPrivilege)

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-AddComputerRights

    .EXAMPLE
    Get-AddComputerRights -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Rights
    Author: Alexander Sturz (@_61106960_)
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
        [switch]$IncludePrivileged,

        [switch]$IncludeInactive
    )

    begin {
        Write-Log "[Get-AddComputerRights] Starting check"
    }

    process {
        try {
            # Build connection parameters (exclude IncludePrivileged which is not a connection parameter)
            $connectionParams = @{}
            if ($Domain) { $connectionParams['Domain'] = $Domain }
            if ($Server) { $connectionParams['Server'] = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            $domainDN = $Script:LDAPContext.DomainDN
            $domainFQDN = $Script:LDAPContext.Domain

            Show-SubHeader "Analyzing Add Computer to Domain rights..." -ObjectType "AddComputerRight"

            $hasFindings = $false
            $quotaValue = 0

            # ===== Step 1: Check ms-DS-MachineAccountQuota =====
            # Escape DN for LDAP filter to prevent injection (RFC 4515)
            $escapedDomainDN = Escape-LDAPFilterDN -DistinguishedName $domainDN
            $domainResult = @(Get-DomainObject -LDAPFilter "(distinguishedName=$escapedDomainDN)" @connectionParams)[0]
            # $null -ne, not truthiness: a hardened quota of 0 is the whole point of this
            # check, and it only survived a truthiness test because LDAP hands attribute
            # values back as strings, where '0' happens to be true. Any normalization to
            # [int] upstream would have turned "nobody may join" into the assumed default
            # of 10, i.e. the exact opposite of the configuration.
            $machineQuota = if ($domainResult -and $null -ne $domainResult.'ms-DS-MachineAccountQuota') {
                $domainResult.'ms-DS-MachineAccountQuota'
            } else {
                $null
            }

            if ($null -ne $machineQuota) {
                $quotaValue = if ($machineQuota -is [array]) { [int]$machineQuota[0] } else { [int]$machineQuota }
            } else {
                # Not configured = defaults to 10
                $quotaValue = 10
            }

            # ===== Step 2: Check ACL on the default computer container =====
            #
            # Read from wellKnownObjects rather than assumed. redircmp points the default
            # location at an organizational unit, and after that CN=Computers is no longer
            # where a machine account created with the quota lands - so the container this
            # check reports on would not be the one that matters.
            $computersContainerDN = "CN=Computers,$domainDN"
            try {
                $domainObject = @(Get-DomainObject -Identity $domainDN -Properties 'wellKnownObjects' @connectionParams)[0]
                foreach ($entry in @($domainObject.wellKnownObjects)) {
                    # DN-With-Binary: B:32:<GUID>:<DN>. AA312825768811D1ADED00C04FD8D5CD is
                    # the computer container.
                    if ("$entry" -match '^B:32:AA312825768811D1ADED00C04FD8D5CD:(.+)$') {
                        $computersContainerDN = $Matches[1]
                        break
                    }
                }
            } catch {
                Write-Log "[Get-AddComputerRights] Could not read wellKnownObjects: $($_.Exception.Message)"
            }
            Write-Log "[Get-AddComputerRights] Default computer container: $computersContainerDN"

            $createComputerAccounts = @()

            # Use Get-ObjectACL for ACL analysis (handles credentials automatically)
            #
            # Inherited ACEs are read as well. A CreateChild grant inherited from the domain
            # root lets its holder create computer accounts exactly as an explicit one does,
            # and -ExplicitOnly dropped every such grant without a word.
            $computerClassGUID = 'bf967a86-0de6-11d0-a285-00aa003049e2'
            $aclResult = Get-ObjectACL -DistinguishedName $computersContainerDN -Rights 'GenericAll','CreateChild' -AllowOnly @connectionParams

            if ($aclResult -and $aclResult.ACEs) {
                $seenSIDs = @{}

                foreach ($ace in $aclResult.ACEs) {
                    $trusteeSID = $ace.TrusteeSID

                    # Skip ACEs with empty SID (can occur with orphaned/deleted principals)
                    if ([string]::IsNullOrEmpty($trusteeSID)) {
                        Write-Log "[Get-AddComputerRights] Skipping ACE with empty SID"
                        continue
                    }

                    if ($seenSIDs.ContainsKey($trusteeSID)) { continue }

                    # An InheritOnly ACE is not part of the effective permissions of the
                    # container that carries it, so it grants no right to create an object IN
                    # CN=Computers - only in a descendant container of it, of which there are
                    # normally none. Reported as "may add computers to the domain" it was a
                    # false positive, and the ACE carries an empty InheritedObjectType so
                    # nothing else here caught it.
                    #
                    # This is also the whole of the class question. An inheritance filter
                    # names the class of the children that may inherit the ACE (MS-DTYP,
                    # ACE); the access check reads the ObjectType alone and skips only
                    # INHERIT_ONLY_ACE. The wizard forms for "only the following objects"
                    # are inherit-only and stop here, an inherited copy for another class
                    # than the container's arrives inherit-only, and an ACE that names a
                    # class without being inherit-only grants its rights on the container
                    # whatever the class. Comparing the filter with the container's class
                    # used to drop that last one.
                    if (-not (Test-ACEAppliesToSelf -ACE $ace)) {
                        Write-Log "[Get-AddComputerRights] Skipping descendants-only ACE: $($ace.Trustee) ($trusteeSID), PropagationFlags=$($ace.PropagationFlags)"
                        continue
                    }

                    # Check if this ACE grants CreateChild for Computer objects: GenericAll or
                    # CreateChild, for all classes or for the computer class. GenericAll used to
                    # count whatever class it named - and an object ACE grants its rights on the
                    # class it names only (MS-DTYP 2.5.3.2). Exchange setup's GenericAll on the
                    # msExchDynamicDistributionList class, inherited by CN=Computers, made Exchange
                    # Trusted Subsystem and Organization Management computer creators.
                    # Get-ObjectACL hands an empty GUID over as $null.
                    $forComputers = (-not $ace.ObjectType) -or ($ace.ObjectType -eq $computerClassGUID)
                    $hasCreateChild = $forComputers -and
                        ((@($ace.RightsRaw) -contains 'GenericAll') -or (@($ace.RightsRaw) -contains 'CreateChild'))

                    if ($hasCreateChild) {
                        $seenSIDs[$trusteeSID] = $true

                        # CN=Computers is a Container - use context-specific filtering
                        # SELF, Creator Owner, Pre-Windows 2000 Compatible Access are NORMAL here
                        $expectedCheck = Test-IsExpectedACLIdentity -SID $trusteeSID -Context 'Container'
                        if ($expectedCheck.Skip) {
                            Write-Log "[Get-AddComputerRights] Skipping expected identity: $($ace.Trustee) ($trusteeSID) - $($expectedCheck.Reason)"
                            continue
                        }

                        # Skip Authenticated Users if quota > 0 (they already have implicit rights via quota)
                        if ($trusteeSID -eq 'S-1-5-11' -and $quotaValue -gt 0) {
                            Write-Log "[Get-AddComputerRights] Skipping Authenticated Users ACL (already covered by quota)"
                            continue
                        }

                        # Determine severity
                        $severity = 'Finding'

                        if (-not $IncludePrivileged) {
                            # Use scope-based check for CN=Computers container ACL rights
                            $scopeResult = Test-IsExpectedInScope -Identity $trusteeSID -Scope 'ComputerContainerACL' -ReturnDetails

                            if ($scopeResult.Severity -eq 'Expected') {
                                Write-Log "[Get-AddComputerRights] CreateChild (expected): $($ace.Trustee) - $($scopeResult.Reason)"
                                continue
                            }

                            if ($scopeResult.Severity -eq 'Attention') {
                                Write-Log "[Get-AddComputerRights] CreateChild (attention): $($ace.Trustee) - $($scopeResult.Reason) - skipped (use -IncludePrivileged to include)"
                                continue
                            }

                            $severity = $scopeResult.Severity
                        } else {
                            # -IncludePrivileged: Show ALL accounts, but mark privileged ones for yellow display
                            $scopeResult = Test-IsExpectedInScope -Identity $trusteeSID -Scope 'ComputerContainerACL' -ReturnDetails
                            $severity = $scopeResult.Severity
                            Write-Log "[Get-AddComputerRights] IncludePrivileged: Including $($ace.Trustee) ($trusteeSID) with severity $severity"
                        }

                        $createComputerAccounts += [PSCustomObject]@{
                            SID = $trusteeSID
                            Name = $ace.Trustee
                            Severity = $severity
                        }
                    }
                }
            }

            # ===== Step 3: Check GPO User Rights Assignment =====
            $gpoFindings = @(Check-GPOAddComputerRights -DomainFQDN $domainFQDN @connectionParams)

            # Which policy actually wins, and whether it hands the privilege to
            # ordinary users. Computed here rather than inside the GPO block below,
            # because the quota line needs the same answer and used to assert the
            # opposite: it said "any authenticated user can add computers" on the
            # strength of the quota value alone. In a domain whose effective policy
            # restricts SeMachineAccountPrivilege to Administrators, the GPO block was
            # skipped entirely and that sentence was the only thing the report said -
            # a false positive in exactly the environment that did the right thing.
            #
            # The quota is a ceiling on a privilege, not the privilege. The finding
            # definition has said so since it was written ("This alone does not grant
            # computer creation rights - it requires the SeMachineAccountPrivilege").
            $effectiveGPO = @($gpoFindings | Where-Object { $_._IsEffective -eq $true })[0]
            $effectiveIsDangerous = $effectiveGPO -and ($effectiveGPO._HasAuthenticatedUsers -or $effectiveGPO._HasEveryone)

            # ===== Step 4: Output findings as objects =====

            # Finding 1: MachineAccountQuota as object
            # Note: Quota > 0 is a Hint (not Finding) - it's a configuration worth noting but not critical
            if ($quotaValue -eq 0) {
                Show-Line "ms-DS-MachineAccountQuota is 0 - computer creation restricted to explicit permissions" -Class Secure
            } else {
                # Three different statements, because three different things are true.
                # Without a policy the documented default applies - Authenticated Users
                # hold SeMachineAccountPrivilege on domain controllers - so the
                # original sentence is right and now says what it rests on.
                #
                # In the object, beside the quota they qualify. The statement used to be
                # the line above the object, ending in a colon that announced a row with
                # the number alone, while the policy it named came two blocks later.
                if ($effectiveGPO -and -not $effectiveIsDangerous) {
                    # Accounts, not EffectiveSetting: the latter explains precedence
                    # ("this policy wins", "overridden by X"), which is not the list of
                    # principals the privilege went to.
                    $restrictedTo = if (@($effectiveGPO.Accounts).Count -gt 0) { @($effectiveGPO.Accounts) -join ', ' } else { "nobody" }
                    $whoCanAdd = "Only $restrictedTo - no other account can use the quota"
                    $grantedBy = "GPO '$($effectiveGPO.displayName)' restricts SeMachineAccountPrivilege to $restrictedTo"
                    $quotaClass = 'Note'
                } elseif ($effectiveGPO) {
                    $grantedTo = if (@($effectiveGPO.Accounts).Count -gt 0) { @($effectiveGPO.Accounts) -join ', ' } else { "Authenticated Users" }
                    $whoCanAdd = "Any authenticated user, up to the quota"
                    $grantedBy = "GPO '$($effectiveGPO.displayName)' grants SeMachineAccountPrivilege to $grantedTo"
                    $quotaClass = 'Hint'
                } else {
                    $whoCanAdd = "Any authenticated user, up to the quota"
                    $grantedBy = "No policy - the Windows default grants SeMachineAccountPrivilege to Authenticated Users on the domain controllers"
                    $quotaClass = 'Hint'
                }

                $quotaObject = [PSCustomObject]@{
                    'ms-DS-MachineAccountQuota' = $quotaValue
                    whoCanAddComputers          = $whoCanAdd
                    privilegeGrantedBy          = $grantedBy
                }
                $quotaObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'MachineAccountQuota' -Force
                Show-Line "Who can add computers to the domain:" -Class $quotaClass
                Show-Object $quotaObject -Class $quotaClass
                $hasFindings = $true
            }

            # Finding 2: delegated CreateChild on the computer container, inherited
            # grants included (show full AD objects)
            if (@($createComputerAccounts).Count -gt 0) {
                Show-Line "Found $(@($createComputerAccounts).Count) account(s) with CreateChild rights in the computer container ($computersContainerDN):" -Class Finding

                foreach ($account in $createComputerAccounts) {
                    # Check if this is a well-known SID that does NOT belong to the domain partition.
                    # This covers all SIDs that have no domain-specific sub-authorities (S-1-5-21-*):
                    #   - Simple well-known SIDs:  S-1-1-0, S-1-5-11, S-1-5-18 (single authority)
                    #   - BUILTIN group SIDs:       S-1-5-32-544, S-1-5-32-554  (authority + one RID)
                    #   - Other special SIDs:       S-1-3-0, S-1-16-* etc.
                    # These objects do NOT exist as AD objects in the domain partition, so an LDAP
                    # objectSid query would always return nothing and fall into the UNRESOLVABLE path.
                    # ConvertFrom-SID resolves them directly via $Script:SIDToName.
                    $isWellKnownSID = $account.SID -notmatch '^S-1-5-21-'

                    # Try to resolve the SID to a full AD object (skip for well-known SIDs)
                    $adObject = $null
                    if (-not $isWellKnownSID) {
                        $sidHex = ConvertTo-LDAPSIDHex -SID $account.SID
                        if ($sidHex) {
                            $adObject = @(Get-DomainObject -LDAPFilter "(objectSid=$sidHex)" @connectionParams)[0]
                        }
                    }

                    # A right held by Everyone, Domain Users or Domain Computers is not the
                    # same finding as the same right held by one provisioning account: every
                    # member can create a machine account, which is the delegation source an
                    # RBCD attack needs, and it does not depend on the quota at all. The
                    # wording is the one Get-DangerousACLs uses on the domain object, and the
                    # card it selects is the container's own - the domain-object card would
                    # have brought a write-up about the domain with it.
                    $rightsText = "CreateChild (Computer) in the computer container"
                    if (Test-IsBroadTrustee -SID $account.SID) {
                        $rightsText += ' - granted to a broad group so every member holds it'
                    }

                    if ($adObject) {
                        $adObject | Add-Member -NotePropertyName 'dangerousRights' -NotePropertyValue $rightsText -Force
                        $adObject | Add-Member -NotePropertyName 'targetContainer' -NotePropertyValue $computersContainerDN -Force
                        if ($account.Severity -in @('Expected', 'Attention')) {
                            $adObject | Add-Member -NotePropertyName 'dangerousRightsSeverity' -NotePropertyValue 'Hint' -Force
                        }
                        $adObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'AddComputerRight' -Force
                        Show-Object $adObject -Class $(if ([string]$adObject.dangerousRightsSeverity -in @('Expected', 'Attention', 'Hint')) { 'Hint' } else { 'Finding' })
                    } else {
                        # Fallback for well-known SIDs, foreign/deleted principals
                        # For well-known SIDs, resolve name via ConvertFrom-SID
                        $resolvedName = if ($isWellKnownSID) { ConvertFrom-SID -SID $account.SID } else { $account.Name }
                        $fallbackObject = [PSCustomObject]@{
                            sAMAccountName = $resolvedName
                            objectSid = $account.SID
                            dangerousRights = $rightsText
                            targetContainer = $computersContainerDN
                        }
                        if ($account.Severity -in @('Expected', 'Attention')) {
                            $fallbackObject | Add-Member -NotePropertyName 'dangerousRightsSeverity' -NotePropertyValue 'Hint' -Force
                        }
                        $fallbackObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'AddComputerRight' -Force
                        Show-Object $fallbackObject -Class $(if ([string]$fallbackObject.dangerousRightsSeverity -in @('Expected', 'Attention', 'Hint')) { 'Hint' } else { 'Finding' })
                    }
                }
                $hasFindings = $true
            }

            # Finding 3: GPO grants SeMachineAccountPrivilege - as enriched native GPO objects
            # Note: Hint (not Finding) because GPO privilege alone doesn't enable computer creation without quota
            # Every policy that defines the privilege, not only the ones that hand it
            # to ordinary users. A policy restricting SeMachineAccountPrivilege to
            # Administrators is the evidence that the quota is unreachable, and the
            # customer could not cite it: the block was gated on there being a
            # dangerous policy, so the hardened domain got no rows at all. The
            # per-policy class below already distinguishes the two - Secure for the
            # effective policy that restricts, Hint for one that does not - it was
            # simply never reached.
            if (@($gpoFindings).Count -gt 0) {

                # A policy that is not linked or not enabled grants the privilege to nobody.
                # Held back rather than dropped - see Show-GPOInactiveSummary. The verdict
                # was stamped in Check-GPOAddComputerRights, where the linkage lives.
                $inactiveGPOs = @($gpoFindings | Where-Object { $_._ReachInactive })
                $shownGPOs    = if ($IncludeInactive) { @($gpoFindings) } else { @($gpoFindings | Where-Object { -not $_._ReachInactive }) }

                # The dormant list in the shape Split-GPOFindingByReach produces, built by
                # hand because this check stamps the reach verdict itself - the linkage and
                # the status map only exist inside Check-GPOAddComputerRights. One entry per
                # policy, and here that is also one per finding: this check reports one row
                # per GPO to begin with.
                #
                # Name and displayName, not GPOGUID and GPOName: these are native GPO objects
                # and those two are only the row LABELS that $Script:AttributeLabels puts on
                # them for display. Reading the label names here would yield empty strings and
                # print a list of blanks.
                $dormantGPOs = @($inactiveGPOs | ForEach-Object {
                    [PSCustomObject]@{
                        GPOGUID  = "$($_.Name)"
                        GPOName  = "$($_.displayName)"
                        Category = if ($_._ReachUnlinked) { 'unlinked' } else { 'disabled' }
                    }
                })

                # Held-back policies first, then the headline for the active ones - the
                # "Found ..." line heads the finding objects, not the dampening block.
                Show-GPOInactiveSummary `
                    -Unlinked @($inactiveGPOs | Where-Object { $_._ReachUnlinked }).Count `
                    -Disabled @($inactiveGPOs | Where-Object { -not $_._ReachUnlinked }).Count `
                    -Dormant $dormantGPOs `
                    -Listed:$IncludeInactive

                $lineClass = if ($effectiveIsDangerous) { "Hint" } else { "Secure" }
                if (@($shownGPOs).Count -gt 0) {
                    Show-Line "Found $(@($shownGPOs).Count) GPO(s) configuring SeMachineAccountPrivilege:" -Class $lineClass
                } else {
                    Show-Line "No policy that is linked and enabled configures SeMachineAccountPrivilege" -Class Note
                }

                # Show all GPOs that define SeMachineAccountPrivilege, sorted by precedence
                # (highest first). OtherOU is in the map because a scope missing from it
                # sorts as $null, which puts it ahead of the domain-level winner.
                $scopePriorityMap = @{ "DomainControllers" = 1; "Domain" = 2; "OtherOU" = 3; "NotLinked" = 4 }
                $sortedGPOs = @($shownGPOs | Sort-Object @{Expression={$scopePriorityMap[$_._PrecedenceScope]}}, _PrecedenceOrder)

                foreach ($gpo in $sortedGPOs) {
                    $gpo | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'AddComputerGPO' -Force

                    $isEffective = $gpo._IsEffective -eq $true
                    $isDangerous = $gpo._HasAuthenticatedUsers -or $gpo._HasEveryone
                    $objectClass = if ($gpo._ReachInactive) {
                        # Grey whatever the accounts say: the privilege is granted to nobody
                        # while the policy reaches nothing, and EffectiveSetting on the row
                        # says why.
                        'Note'
                    } elseif ($isEffective) {
                        if ($effectiveIsDangerous) { "Hint" } else { "Secure" }
                    } else {
                        if ($isDangerous) { "Hint" } else { "Standard" }
                    }
                    Show-Object $gpo -Class $objectClass
                }
                $hasFindings = $true
            }

            if (-not $hasFindings) {
                # The GPO half of this check reads SeMachineAccountPrivilege out of
                # GptTmpl.inf, and the SYSVOL walk silently skips a Policies folder it may
                # not read. A green line over those folders claims more than was looked at.
                $quotaClass = 'Secure'
                if (Show-SYSVOLCoverageNote -FileFilter @('GptTmpl.inf')) { $quotaClass = 'Note' }
                Show-Line "Add Computer to Domain rights properly configured" -Class $quotaClass
            }

        } catch {
            Write-Log "[Get-AddComputerRights] Error: $_" -Level Error
            Show-Line "Error during check - the rights to add computers to the domain could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-AddComputerRights] Check completed"
    }
}

# Helper Function: Check GPO User Rights Assignment
function Check-GPOAddComputerRights {
    [CmdletBinding()]
    param(
        [string]$DomainFQDN,

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    try {
        # Build connection parameters (exclude DomainFQDN which is not a Get-DomainGPO parameter)
        $connectionParams = @{}
        if ($Domain) { $connectionParams['Domain'] = $Domain }
        if ($Server) { $connectionParams['Server'] = $Server }
        if ($Credential) { $connectionParams['Credential'] = $Credential }

        $gpos = Get-DomainGPO @connectionParams

        if (-not $gpos -or @($gpos).Count -eq 0) { return @() }

        # Indexed once for the whole check: every finding below reports the state of its
        # policy as GPOStatus, the way the other GPO checks do.
        $gpoStatusMap = Get-GPOStatusMap -GPO $gpos

        $dcServer = $Script:LDAPContext.Server
        $domainDN = $Script:LDAPContext.DomainDN
        $dcOUDN = "OU=Domain Controllers,$domainDN"

        # Build GPO precedence map using Get-GPOLinkage (which reliably reads gPLink via Invoke-LDAPSearch)
        # Filter to DC OU and domain root - these are the containers that determine effective DC policy
        Write-Log "[Check-GPOAddComputerRights] Building GPO precedence map from GPO linkage data"
        $Script:gpoAddComputerPrecedenceMap = @{}

        $allGPOLinkage = Get-GPOLinkage
        if ($allGPOLinkage) {
            $dcOUDNUpper = $dcOUDN.ToUpper()
            $domainDNUpper = $domainDN.ToUpper()

            foreach ($gpoGUID in $allGPOLinkage.Keys) {
                foreach ($linkInfo in $allGPOLinkage[$gpoGUID]) {
                    if ($linkInfo.IsDisabled) { continue }

                    $linkDNUpper = $linkInfo.DistinguishedName.ToUpper()
                    $precedenceScope = $null

                    if ($linkDNUpper -eq $dcOUDNUpper) {
                        $precedenceScope = "DomainControllers"
                    } elseif ($linkDNUpper -eq $domainDNUpper) {
                        $precedenceScope = "Domain"
                    }

                    if ($precedenceScope -and -not $Script:gpoAddComputerPrecedenceMap.ContainsKey($gpoGUID)) {
                        $Script:gpoAddComputerPrecedenceMap[$gpoGUID] = [PSCustomObject]@{
                            GUID      = $gpoGUID
                            Scope     = $precedenceScope
                            LinkOrder = $linkInfo.LinkOrder
                        }
                    }
                }
            }
        }
        Write-Log "[Check-GPOAddComputerRights] Precedence map: $($Script:gpoAddComputerPrecedenceMap.Count) GPO(s) linked to DC OU or domain root"

        # Use Invoke-SMBAccess for SYSVOL access (handles SimpleBind credentials and custom DNS)
        $Script:gpoAddComputerFindings = @()

        Invoke-SMBAccess -Description "Scanning GPO User Rights Assignment" -ScriptBlock {
            $sysvolPath = "\\$dcServer\SYSVOL\$DomainFQDN\Policies"

            if (-not (Test-Path $sysvolPath)) {
                Write-Log "[Check-GPOAddComputerRights] SYSVOL path not accessible: $sysvolPath"
                return
            }

            # Iterate the cached SYSVOL listing instead of probing a constructed path per GPO:
            # most GPOs have no GptTmpl.inf, so per-GPO probing costs one SMB round-trip each
            # for a file that usually does not exist.
            $gptTmplFiles = @(Get-CachedSYSVOLFiles -Filter "GptTmpl.inf")

            # GPO GUID -> GPO object, to resolve the file back to its GPO
            $gpoByGuid = @{}
            foreach ($g in $gpos) {
                if ($g.Name) { $gpoByGuid[$g.Name.ToUpper()] = $g }
            }

            $totalGPOs = $gptTmplFiles.Count
            $currentGPOIndex = 0
            foreach ($file in $gptTmplFiles) {
                # Extract GPO GUID from path: ...\Policies\{GUID}\Machine\...
                if ($file.FullName -notmatch '\\Policies\\(\{[^}]+\})\\') { continue }
                $gpo = $gpoByGuid[$Matches[1].ToUpper()]
                if (-not $gpo) { continue }

                $currentGPOIndex++
                if ($totalGPOs -gt $Script:ProgressThreshold) {
                    Show-Progress -Activity "Scanning GPO user rights assignment" -Current $currentGPOIndex -Total $totalGPOs -ObjectName $gpo.DisplayName
                }

                $content = Get-CachedSYSVOLContent -Path $file.FullName
                if ($content) {
                    if ($content -match '(?is)\[Privilege Rights\](.*?)(\[|$)') {
                        $privilegeRightsSection = $Matches[1]

                        # [ \t] around the '=' and a value that stops at the line: \s matches
                        # a newline, so "SeMachineAccountPrivilege =" with nobody assigned
                        # used to capture the following line of the file as its account
                        # list. See the same fix in Get-GPOUserRightsAssignment.
                        if ($privilegeRightsSection -match '(?im)^[ \t]*SeMachineAccountPrivilege[ \t]*=[ \t]*([^\r\n]*)') {
                            $accountsLine = $Matches[1].Trim()
                            $accounts = $accountsLine -split ',' | ForEach-Object { $_.Trim().TrimStart('*') }

                            $accountNames = @()
                            $hasAuthenticatedUsers = $false
                            $hasEveryone = $false

                            foreach ($account in $accounts) {
                                if ([string]::IsNullOrWhiteSpace($account)) { continue }
                                $accountName = ConvertFrom-SID -SID $account
                                $accountNames += $accountName

                                # SID-based detection (language-independent).
                                # S-1-5-11 = Authenticated Users, S-1-1-0 = Everyone.
                                # Equality, not -match: the latter is a substring regex on
                                # the raw INI entry, so a longer SID containing these as a
                                # substring would also have counted. The entry may carry the
                                # GptTmpl.inf '*' prefix.
                                $accountSid = ([string]$account).Trim().TrimStart('*')
                                if ($accountSid -eq 'S-1-5-11') { $hasAuthenticatedUsers = $true }
                                if ($accountSid -eq 'S-1-1-0')  { $hasEveryone = $true }
                            }

                            # Get linkage data for Scope/LinkedOUs (same pattern as LDAP/SMB checks)
                            $gpoLinkage = Get-GPOLinkage
                            $gpoGUIDKey = $gpo.Name.ToUpper()

                            # Three-valued, and the distinction is the whole point. A plain
                            # $gpoLinkage[$key] answers $null both when the map could not be
                            # built and when the map is fine but holds no entry for this GPO -
                            # two states that have to be reported as opposites. The second one
                            # means "linked nowhere", which is knowledge; collapsing it into
                            # "unknown" printed "Unknown - linkage could not be resolved" next
                            # to an EffectiveSetting of "linked nowhere" in the same block, and
                            # let the policy escape the dormant-GPO dampening, because an
                            # unknown reach deliberately never dampens.
                            #
                            # @($linkage[$missingKey]) is not a substitute: that is an array
                            # holding one $null, which is Count 1 and therefore looks linked.
                            $links = $null
                            if ($gpoLinkage) {
                                $links = @()
                                if ($gpoLinkage.ContainsKey($gpoGUIDKey)) { $links = @($gpoLinkage[$gpoGUIDKey]) }
                            }
                            $isDomainWide = $false

                            # Reset per GPO. Assigned only inside the if below, so without
                            # this the previous GPO's links decide this one's scope whenever
                            # linkage could not be resolved.
                            $activeLinks = @()
                            if ($links) {
                                $activeLinks = @($links | Where-Object { $_.LinkStatus -ne "Disabled" })
                                $isDomainWide = ($null -ne ($activeLinks | Where-Object { $_.Scope -eq "Domain" }))
                            }

                            # Determine precedence info (for effective setting calculation after scriptblock).
                            # The map only records links at the Domain Controllers OU and the
                            # domain root, so a policy linked to an ordinary OU is absent from
                            # it - which is not the same as being linked nowhere, and saying
                            # "linked nowhere" about a linked policy would simply be wrong.
                            #
                            # The unresolved case gets a scope of its own. Falling through to
                            # "NotLinked" made the EffectiveSetting row assert "the policy is
                            # linked nowhere" on the strength of a lookup that failed.
                            $precedenceInfo = $Script:gpoAddComputerPrecedenceMap[$gpoGUIDKey]
                            $precedenceScope = if ($precedenceInfo) { $precedenceInfo.Scope }
                                               elseif ($null -eq $links) { "Unknown" }
                                               elseif ($activeLinks.Count -gt 0) { "OtherOU" }
                                               else { "NotLinked" }
                            $precedenceOrder = if ($precedenceInfo -and $precedenceInfo.LinkOrder) { $precedenceInfo.LinkOrder } else { 999 }

                            # Enrich native GPO object (matching LDAP/SMB display pattern)
                            $gpo | Add-Member -NotePropertyName 'Accounts'              -NotePropertyValue $accountNames -Force
                            $gpo | Add-Member -NotePropertyName '_IsEffective'          -NotePropertyValue $false -Force
                            $gpo | Add-Member -NotePropertyName '_HasAnyLink'           -NotePropertyValue ([bool](@($links | Where-Object { $_ }).Count)) -Force

                            # Whether this policy reaches a machine at all, stamped here
                            # rather than in the output block because the linkage and the
                            # status map only exist in this function. Split-GPOFindingByReach
                            # would need both, so the caller reads the verdict instead.
                            #
                            # -eq $false on purpose: an unresolved linkage answers $null,
                            # which must not be read as inactive.
                            $reach = Get-GPOReach -StatusEntry $gpoStatusMap[$gpoGUIDKey] -Scope 'Machine' -Link $links
                            $gpo | Add-Member -NotePropertyName '_ReachInactive' `
                                -NotePropertyValue ($reach.Reaches -eq $false) -Force
                            $gpo | Add-Member -NotePropertyName '_ReachUnlinked' `
                                -NotePropertyValue ([bool]($reach.Reason -like '*linked nowhere*')) -Force

                            # Where the policy applies. The full link records, disabled ones
                            # included - the LinkedOUs transformer marks those and renders an
                            # empty list as "Not linked".
                            $gpo | Add-Member -NotePropertyName 'LinkedOUs' `
                                -NotePropertyValue $(if ($null -eq $links) { 'Unknown - linkage could not be resolved' } else { @($links | Where-Object { $_ }) }) -Force

                            $gpoStatus = Get-GPOEffectiveStatus -StatusEntry $gpoStatusMap[$gpoGUIDKey] `
                                -Scope 'Machine' -Link $(if ($null -eq $links) { $null } else { @($links | Where-Object { $_ }) })
                            if ($gpoStatus) {
                                $gpo | Add-Member -NotePropertyName 'GPOStatus' -NotePropertyValue $gpoStatus -Force
                            }

                            # Internal precedence fields (not displayed, used for effective determination)
                            $gpo | Add-Member -NotePropertyName '_PrecedenceScope'        -NotePropertyValue $precedenceScope -Force
                            $gpo | Add-Member -NotePropertyName '_PrecedenceOrder'        -NotePropertyValue $precedenceOrder -Force
                            $gpo | Add-Member -NotePropertyName '_HasAuthenticatedUsers'  -NotePropertyValue $hasAuthenticatedUsers -Force
                            $gpo | Add-Member -NotePropertyName '_HasEveryone'            -NotePropertyValue $hasEveryone -Force

                            $Script:gpoAddComputerFindings += $gpo
                        }
                    }
                }
            }
            if ($totalGPOs -gt $Script:ProgressThreshold) {
                Show-Progress -Activity "Scanning GPO user rights assignment" -Completed
            }
        }

        $result = $Script:gpoAddComputerFindings
        $Script:gpoAddComputerFindings = $null
        $Script:gpoAddComputerPrecedenceMap = $null

        # Determine effective setting: DC OU GPOs take precedence over Domain GPOs;
        # within same scope, lower _PrecedenceOrder = higher priority (1 = highest)
        # Named explicitly rather than as "everything but NotLinked", so that the OtherOU
        # scope cannot enter a contest only the domain-level scopes hold.
        $linkedResults = @($result | Where-Object { $_._PrecedenceScope -in @('DomainControllers', 'Domain') })
        $effectiveGPO = $null
        if ($linkedResults.Count -gt 0) {
            $scopePriority = @{ "DomainControllers" = 1; "Domain" = 2 }
            $effectiveGPO = $linkedResults | Sort-Object @{Expression={$scopePriority[$_._PrecedenceScope]}}, _PrecedenceOrder | Select-Object -First 1
            if ($effectiveGPO) {
                $effectiveGPO._IsEffective = $true
                Write-Log "[Check-GPOAddComputerRights] Effective GPO: '$($effectiveGPO.displayName)' (Scope=$($effectiveGPO._PrecedenceScope), LinkOrder=$($effectiveGPO._PrecedenceOrder))"
            }
        }

        # A policy linked to an ordinary OU applies there. It was previously left
        # non-effective, which is the mirror of the defect fixed in the LDAP and SMB
        # checks: there an unlinked policy was called effective, here a linked one was not.
        foreach ($gpo in @($result | Where-Object { $_._PrecedenceScope -eq 'OtherOU' })) {
            $gpo._IsEffective = $true
        }

        foreach ($gpo in @($result)) {
            $gpo | Add-Member -NotePropertyName 'EffectiveSetting' -NotePropertyValue (
                Get-GPOEffectiveSettingText -Scope $gpo._PrecedenceScope `
                    -IsEffective $gpo._IsEffective `
                    -WinnerName $(if ($effectiveGPO) { [string]$effectiveGPO.displayName } else { $null }) `
                    -WinnerLinkOrder $(if ($effectiveGPO) { $effectiveGPO._PrecedenceOrder } else { $null }) `
                    -HasAnyLink $gpo._HasAnyLink
            ) -Force
        }

        return $result
    } catch {
        Write-Log "[Check-GPOAddComputerRights] Error: $_" -Level Error
        return @()
    }
}
