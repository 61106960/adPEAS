function Get-GPOPermissions {
    <#
    .SYNOPSIS
    Detects dangerous permissions on Group Policy Objects (GPOs).

    .DESCRIPTION
    Analyzes Access Control Lists (ACLs) on all Group Policy Objects for dangerous permissions that allow non-privileged users to modify GPOs, leading to privilege escalation.

    Checks for:
    - WriteProperty / WriteDacl permissions on GPO objects
    - GenericAll / GenericWrite permissions
    - Non-privileged users with GPO modification rights

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-GPOPermissions

    .EXAMPLE
    Get-GPOPermissions -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: GPO
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
        [switch]$IncludePrivileged
    )

    begin {
        Write-Log "[Get-GPOPermissions] Starting check"

        # Dangerous ACE Types for GPOs
        # Must cover everything Get-ObjectACL -DangerousOnly hands over, otherwise a
        # matching ACE is reported with an empty label and the console line reads
        # "CONTOSO\helpdesk ()". Deleting a linked GPO is a denial of service, so those
        # rights belong in the list rather than being silently unnamed.
        # Ordered by what the right actually gives its holder, not alphabetically. The
        # order used to put WriteProperty ahead of WriteDacl and WriteOwner, and the loop
        # below stopped at the first match: an ACE carrying "WriteProperty, WriteDacl,
        # WriteOwner" was rendered as "(WriteProperty)" and the right that lets its holder
        # grant themselves everything else appeared nowhere. All matches are collected
        # now, so the order only decides how they are listed.
        $Script:DangerousGPOAccessRights = @(
            'GenericAll',
            'WriteDacl',
            'WriteOwner',
            'GenericWrite',
            'WriteProperty',
            'CreateChild',
            'DeleteChild',
            'DeleteTree',
            'Delete',
            'Self',
            'ExtendedRight'
        )

        # The four attributes of a groupPolicyContainer that hand over the policy content.
        # A WriteProperty ACE restricted to one of them is as good as full control of the
        # GPO; one restricted to any other attribute is not, and used to get the same
        # finding card - which states that "gPCFileSysPath can be redirected to an
        # attacker-controlled UNC path" even when the ACE only allows gPCWQLFilter.
        $Script:CriticalGPOAttributes = @(
            'gPCFileSysPath',
            'gPCMachineExtensionNames',
            'gPCUserExtensionNames',
            'versionNumber'
        )

        # The rights only an ACE without an ObjectType grants on the GPO. An object ACE grants
        # its mask on the attribute, property set or class its GUID names and nowhere else
        # (MS-ADTS 5.1.3.3.3), so none of these reaches the GPO from a scoped ACE: GenericAll
        # and GenericWrite scoped to an attribute write that attribute, and the rest drop out.
        $Script:UnscopedGPORights = @(
            'GenericAll',
            'GenericWrite',
            'WriteDacl',
            'WriteOwner',
            'CreateChild',
            'DeleteChild',
            'DeleteTree',
            'Delete'
        )
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

            # ===== Step 1: Enumerate GPOs =====
            Show-SubHeader "Searching for dangerous GPO permissions..." -ObjectType "GPOPermission"

            $allGPOs = @(Get-DomainGPO @connectionParams)

            # Indexed once for the whole check: every finding below reports the state of its
            # policy as GPOStatus, the way the other GPO checks do.
            $gpoStatusMap = Get-GPOStatusMap -GPO $allGPOs

            if (-not $allGPOs -or @($allGPOs).Count -eq 0) {
                Show-Line "No GPOs found in domain" -Class Note
                return
            }

            # Every GPO's security descriptor in one query, because the loop below needs all
            # of them and Get-ObjectACL reads exactly one object per call - which cost one
            # LDAP round trip per GPO, a domain with 400 policies paying 400 of them for
            # data a single search returns. -Raw keeps nTSecurityDescriptor as the bytes
            # Get-ObjectACL parses, so the analysis below is unchanged: it is handed the
            # same descriptor it used to fetch for itself.
            $descriptorLookup = @{}
            try {
                $rawGPOs = @(Get-DomainObject -LDAPFilter '(objectClass=groupPolicyContainer)' `
                    -Properties 'distinguishedName', 'nTSecurityDescriptor' -Raw @connectionParams)

                foreach ($rawGPO in $rawGPOs) {
                    if ($rawGPO.distinguishedName -and $rawGPO.nTSecurityDescriptor) {
                        $descriptorLookup[[string]$rawGPO.distinguishedName] = $rawGPO.nTSecurityDescriptor
                    }
                }
                Write-Log "[Get-GPOPermissions] Prefetched $($descriptorLookup.Count) security descriptor(s) in one query"
            }
            catch {
                # A failed prefetch is not fatal: the loop falls back to reading each
                # descriptor itself, which is what it did before.
                Write-Log "[Get-GPOPermissions] Descriptor prefetch failed, falling back to one read per GPO: $_" -Level Warning
            }

            # ===== Step 2: Enumerate Computers for Impact Analysis =====
            # Include ALL computers (workstations, servers, AND domain controllers) for accurate impact analysis
            # GPOs affecting DCs are often more critical than those affecting workstations
            # objectSid and primaryGroupID for a policy's security filtering, which decides
            # by the computer's token - see Test-GPOFilterCoversComputer.
            $allComputers = @(Get-DomainComputer -Properties "name","distinguishedName","objectSid","primaryGroupID" @connectionParams)
            # The containers above each computer, worked out once for every policy below.
            $computerChainCache = @{}

            if (-not $allComputers) {
                $allComputers = @()
            }

            # ===== Step 3: Get GPO Linkage =====
            $gpoLinkage = Get-GPOLinkage

            # ===== Step 4: Analyze GPO Permissions =====
            $vulnerableGPOsHash = @{}

            # Coverage item B20: the broad groups that may change a policy, per GUID, for the
            # oneLinkAway row once both halves are read. Change means rewrite what the
            # policy applies - not delete it, nor a write that cannot reach its content.
            $broadWritersByGUID = @{}
            $contentChangeRights = @('GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'WriteProperty')

            # GPOs whose security descriptor could not be read or parsed. They used to be
            # counted as analyzed and clean by the Secure line below, which is the one
            # statement a failed read cannot support.
            $unreadGPOs = @()

            # GPOs with no dangerous ACE but a non-default owner. The owner holds WRITE_DAC
            # implicitly, so it is a finding on its own and must not fall through the
            # "no dangerous ACEs" branch unreported.
            $ownerOnlyGPOs = @{}

            $totalGPOs = @($allGPOs).Count
            $currentIndex = 0
            foreach ($gpo in $allGPOs) {
                $currentIndex++
                if ($totalGPOs -gt $Script:ProgressThreshold) { Show-Progress -Activity "Checking GPO permissions" -Current $currentIndex -Total $totalGPOs -ObjectName $gpo.displayName }
                $gpoDisplayName = $gpo.DisplayName
                $gpoDN = $gpo.DistinguishedName
                $gpoGUID = $gpo.Name

                Write-Log "[Get-GPOPermissions] Analyzing GPO: $gpoDisplayName ($gpoGUID)"

                try {
                    # Use Get-ObjectACL for ACL analysis (handles credentials automatically)
                    # Get-ObjectACL returns a wrapper object with .ACEs property containing actual ACE array.
                    # The descriptor comes from the single prefetch above where it is
                    # present, so the same parsing and the same -DangerousOnly filtering run
                    # either way - only the read is gone.
                    #
                    # -AllowOnly and -ExplicitOnly used to be passed as well, and each of
                    # them hid a class of finding.
                    #
                    # -ExplicitOnly dropped every inherited ACE, and a delegation set on
                    # CN=Policies,CN=System is inherited by every GPO in the domain - so
                    # the single most effective GPO delegation mistake there is, one
                    # GenericAll for a helpdesk group at the Policies container, produced
                    # no finding anywhere. Inheritance is carried on the finding instead,
                    # because the remediation differs: an inherited ACE has to be removed
                    # at the parent.
                    #
                    # -AllowOnly dropped the Deny ACEs, and Deny wins the access check. A
                    # deliberately hardened delegation - Allow GenericAll for a group plus
                    # Deny WriteDacl and WriteProperty for the same group - was reported as
                    # full control, which is a finding the customer cannot reproduce. They
                    # are read now and netted out per trustee below.
                    $aclParams = @{ DistinguishedName = $gpoDN; DangerousOnly = $true }
                    if ($descriptorLookup.ContainsKey([string]$gpoDN)) {
                        $aclParams['SecurityDescriptor'] = $descriptorLookup[[string]$gpoDN]
                    }
                    $aclResult = Get-ObjectACL @aclParams @connectionParams

                    # Three states, and two of them used to share this branch under the log
                    # line "No dangerous ACEs found": Get-ObjectACL answers $null both when
                    # the descriptor could not be read and when it could not be parsed, and
                    # the GPO then counted as analyzed and clean in the Secure line below.
                    if (-not $aclResult) {
                        Write-Log "[Get-GPOPermissions] Security descriptor of GPO '$gpoDisplayName' could not be read or parsed - its permissions are unknown" -Level Warning
                        $unreadGPOs += $gpoDisplayName
                        continue
                    }

                    # The owner holds READ_CONTROL and WRITE_DAC implicitly - it can grant
                    # itself every right without an ACE in the DACL - so a GPO owned by an
                    # ordinary account is under that account's control. Neither Owner nor
                    # OwnerSID was ever read here, although Get-ObjectACL supplies both and
                    # the project has Test-IsDefaultOwner for exactly this question.
                    $ownerFinding = $null
                    if ($aclResult.OwnerSID -and -not (Test-IsDefaultOwner -SID $aclResult.OwnerSID)) {
                        $ownerFinding = [PSCustomObject]@{
                            Owner    = if ($aclResult.Owner) { $aclResult.Owner } else { ConvertFrom-SID -SID $aclResult.OwnerSID }
                            OwnerSID = $aclResult.OwnerSID
                        }
                        Write-Log "[Get-GPOPermissions] GPO '$gpoDisplayName' is owned by $($ownerFinding.Owner), which is not a default owner"
                    }

                    if (-not $aclResult.ACEs -or @($aclResult.ACEs).Count -eq 0) {
                        Write-Log "[Get-GPOPermissions] No dangerous ACEs found for GPO: $gpoDisplayName"
                        if ($ownerFinding) { $ownerOnlyGPOs[$gpoGUID] = @{ GPO = $gpo; Owner = $ownerFinding } }
                        continue
                    }

                    # Deny first, so the Allow ACEs below can be netted against it. Keyed
                    # by trustee: a Deny on one trustee says nothing about another. Each
                    # Deny keeps its scope and whether it is inherited, because both decide
                    # which Allow it takes something from - see below.
                    $deniedRights = @{}
                    foreach ($ace in @($aclResult.ACEs)) {
                        if ($ace.AccessControlType -ne 'Deny') { continue }
                        # A Deny that reaches only the descendants takes nothing away from
                        # the trustee's rights on the GPO object, so it must not net out an
                        # Allow that does apply to it.
                        if (-not (Test-ACEAppliesToSelf -ACE $ace)) { continue }
                        $denySID = [string]$ace.TrusteeSID
                        if (-not $denySID) { continue }
                        if (-not $deniedRights.ContainsKey($denySID)) { $deniedRights[$denySID] = @() }
                        $deniedRights[$denySID] += [PSCustomObject]@{
                            Rights      = @($ace.RightsRaw)
                            ObjectType  = [string]$ace.ObjectType
                            IsInherited = [bool]$ace.IsInherited
                        }
                    }

                    $dangerousAces = @($aclResult.ACEs | Where-Object { $_.AccessControlType -eq 'Allow' })
                    Write-Log "[Get-GPOPermissions] Processing $($dangerousAces.Count) dangerous ACE(s) for GPO: $gpoDisplayName"
                    $vulnerableIdentities = @()

                    foreach ($ace in $dangerousAces) {
                        # Get-ObjectACL returns ACEs with: TrusteeSID, Trustee, Rights, RightsRaw
                        $aceSID = $ace.TrusteeSID
                        $aceRights = $ace.Rights  # String like "GenericAll, WriteProperty"
                        $aceRightsRaw = $ace.RightsRaw  # Array for matching

                        # Skip ACEs with empty SID (can occur with orphaned/deleted principals)
                        if ([string]::IsNullOrEmpty($aceSID)) {
                            Write-Log "[Get-GPOPermissions] Skipping ACE with empty SID on GPO $gpoDisplayName (ACE object type: $($ace.GetType().FullName))"
                            continue
                        }

                        # A groupPolicyContainer has children - CN=Machine and CN=User - so an
                        # InheritOnly ACE on it is possible and grants nothing on the GPO
                        # itself. Reported as GPO control it was a false positive: the policy
                        # settings live in SYSVOL and the link lives on the OU, so a right over
                        # those two sub-containers is not a path to modifying the GPO.
                        if (-not (Test-ACEAppliesToSelf -ACE $ace)) {
                            Write-Log "[Get-GPOPermissions] Skipping descendants-only ACE on GPO $gpoDisplayName : $($ace.Trustee), PropagationFlags=$($ace.PropagationFlags)"
                            continue
                        }

                        # Every dangerous right of the ACE, not the first one, and minus
                        # what a Deny ACE takes away from the same trustee.
                        #
                        # Only a Deny that covers what this ACE grants: one for the whole
                        # object, or one scoped to the same attribute. A Deny of one
                        # attribute took the right away by its name, so a trustee allowed to
                        # write every property and denied gPCWQLFilter lost the write of
                        # gPCFileSysPath with it. And an inherited Deny is evaluated after
                        # every explicit ACE, so it takes nothing from an Allow written on
                        # the GPO.
                        $aceScope = [string]$ace.ObjectType
                        $deniedForTrustee = @()
                        if ($deniedRights.ContainsKey([string]$aceSID)) {
                            foreach ($deny in @($deniedRights[[string]$aceSID])) {
                                if ($deny.IsInherited -and -not $ace.IsInherited) { continue }
                                if ($deny.ObjectType -and $deny.ObjectType -ne $aceScope) { continue }
                                $deniedForTrustee += @($deny.Rights)
                            }
                        }

                        $matchedRights = @()
                        foreach ($dangerousRight in $Script:DangerousGPOAccessRights) {
                            if ($aceRightsRaw -notcontains $dangerousRight) { continue }
                            if ($deniedForTrustee -contains $dangerousRight) {
                                Write-Log "[Get-GPOPermissions] $aceSID holds $dangerousRight on GPO $gpoDisplayName but a Deny ACE takes it away"
                                continue
                            }
                            $matchedRights += $dangerousRight
                        }

                        # -DangerousOnly also hands over an ACE whose resolved extended
                        # right name matches DS-Replication, Force-Change-Password or
                        # All-Extended-Rights, and ConvertTo-ADRightsList replaces the
                        # generic "ExtendedRight" label with that name - so no entry of the
                        # list above matched, the label stayed empty and the console read
                        # "CONTOSO\helpdesk ()": a red line with no right named, no finding
                        # id and therefore no remediation. The ACE's own rights are the
                        # fallback.
                        #
                        # Minus whatever a Deny takes away, though. Without that
                        # subtraction this line undid the netting above: when the Deny
                        # covered every dangerous right the ACE granted, $matchedRights was
                        # empty for that reason and the ACE's full right string came
                        # straight back, so the Deny had no effect on the report at all.
                        if (@($matchedRights).Count -eq 0 -and $aceRights) {
                            $remainingRaw = @(@($aceRightsRaw) | Where-Object { $deniedForTrustee -notcontains $_ })
                            if (@($aceRightsRaw).Count -eq 0) {
                                # No decomposed rights to subtract from - nothing was denied
                                # either, so the string stands as it did.
                                $matchedRights = @([string]$aceRights)
                            } elseif (@($remainingRaw).Count -gt 0) {
                                $matchedRights = @(($remainingRaw -join ', '))
                            }
                        }

                        # Nothing left after the Deny ACEs were netted out.
                        if (@($matchedRights).Count -eq 0) { continue }

                        # What the ACE is scoped to, and whether that scope still reaches
                        # the policy content.
                        #
                        # An ACE on a GPO almost always names an ObjectType GUID, and
                        # Get-ObjectACL resolves one only when it is an extended right - an
                        # attribute GUID came back as $null, so every attribute-scoped
                        # WriteProperty ACE looked exactly like an unrestricted one and got
                        # the card that describes a gPCFileSysPath redirect.
                        # Resolve-ObjectTypeGUID knows the attribute GUIDs as well, which is
                        # what makes the distinction below possible.
                        #
                        # A GUID that resolves to nothing deliberately keeps the full
                        # finding: nothing rules out that the attribute behind it is
                        # gPCFileSysPath. It is labelled with the raw GUID so the reader can
                        # look it up.
                        $aceObjectType = [string]$ace.ObjectType
                        $scopeLabel = ''
                        $scopeReachesPolicy = $true

                        if ($aceObjectType) {
                            # An object ACE grants its whole mask on the node its GUID names
                            # and nowhere else (MS-ADTS 5.1.3.3.3) - GenericAll and WriteDacl
                            # included. A right over the whole GPO is checked at the root of
                            # the object type tree, which such an ACE never reaches. This
                            # used to read the other way round, "an ObjectType narrows the
                            # attribute-scoped bits only", and reported a write of one
                            # attribute as full control of the GPO.
                            $resolvedScope = Resolve-ObjectTypeGUID -GUID $aceObjectType
                            if ($resolvedScope -and $resolvedScope.Type -eq 'SchemaClass') {
                                # Scoped to a child class: creates and deletes objects of that
                                # class below the GPO, and writes nothing of it.
                                Write-Log "[Get-GPOPermissions] $($ace.Trustee) holds $aceRights on GPO $gpoDisplayName scoped to the class $($resolvedScope.Name) - no right over the policy"
                                continue
                            }
                            # GenericAll and GenericWrite carry the WriteProperty bit, which is
                            # what they grant on the attribute; the rights over the whole
                            # object drop out.
                            $scopedRights = @()
                            if (@($matchedRights | Where-Object { @('GenericAll', 'GenericWrite', 'WriteProperty') -contains $_ }).Count -gt 0) {
                                $scopedRights += 'WriteProperty'
                            }
                            $scopedRights += @($matchedRights | Where-Object { $Script:UnscopedGPORights -notcontains $_ -and $_ -ne 'WriteProperty' })
                            if (@($scopedRights).Count -eq 0) { continue }
                            $matchedRights = $scopedRights

                            if ($resolvedScope -and $resolvedScope.Name) {
                                $scopeLabel = [string]$resolvedScope.Name
                                if ($resolvedScope.Type -eq 'Property' -and
                                    $Script:CriticalGPOAttributes -notcontains $scopeLabel) {
                                    $scopeReachesPolicy = $false
                                }
                            } else {
                                $scopeLabel = $aceObjectType
                            }
                        }

                        $dangerousRightMatched = @($matchedRights) -join ', '
                        if ($scopeLabel) {
                            $dangerousRightMatched = "$dangerousRightMatched : $scopeLabel"
                            if (-not $scopeReachesPolicy) {
                                # Read back by DANGEROUS_ACL_GPO_WRITEPROPERTY_SCOPED, which
                                # replaces the gPCFileSysPath card with one that describes
                                # what this attribute actually controls.
                                $dangerousRightMatched = "$dangerousRightMatched - does not carry the policy content"
                            }
                        }

                        # Check if SID is expected (Creator Owner, SELF, etc.) using GPO context
                        $expectedCheck = Test-IsExpectedACLIdentity -SID $aceSID -Context 'GPO'
                        if ($expectedCheck.Skip) {
                            Write-Log "[Get-GPOPermissions] Skipping expected identity $aceSID on GPO $gpoDisplayName : $($expectedCheck.Reason)"
                            continue
                        }

                        # Resolve identity name for display
                        $identityName = if ($ace.Trustee) { $ace.Trustee } else { ConvertFrom-SID -SID $aceSID }

                        # Determine severity
                        $severity = 'Finding'

                        if (-not $IncludePrivileged) {
                            # Use scope-based check for GPO permissions
                            $scopeResult = Test-IsExpectedInScope -Identity $aceSID -Scope 'GPO' -ReturnDetails

                            if ($scopeResult.Severity -eq 'Expected') {
                                Write-Log "[Get-GPOPermissions] Expected identity $aceSID has $aceRights on GPO $gpoDisplayName - $($scopeResult.Reason)"
                                continue
                            }

                            if ($scopeResult.Severity -eq 'Attention') {
                                Write-Log "[Get-GPOPermissions] Attention: $identityName has $aceRights on GPO $gpoDisplayName - $($scopeResult.Reason) - skipped (use -IncludePrivileged to include)"
                                continue
                            }

                            $severity = $scopeResult.Severity
                        } else {
                            # -IncludePrivileged: Show ALL accounts, but mark privileged ones for yellow display
                            $scopeResult = Test-IsExpectedInScope -Identity $aceSID -Scope 'GPO' -ReturnDetails
                            $severity = $scopeResult.Severity
                            Write-Log "[Get-GPOPermissions] IncludePrivileged: Including $identityName ($aceSID) with severity $severity on GPO $gpoDisplayName"
                        }

                        # A write that cannot reach the policy content is not the takeover
                        # the unrestricted right would be, and the colour follows the card.
                        # Only downgraded, never upgraded: a trustee the scope check already
                        # called Expected or Attention keeps that verdict.
                        if (-not $scopeReachesPolicy -and @('Expected', 'Attention') -notcontains $severity) {
                            $severity = 'Hint'
                        }

                        Write-Log "[Get-GPOPermissions] FINDING: $identityName has $dangerousRightMatched on GPO $gpoDisplayName (inherited: $([bool]$ace.IsInherited))"

                        $vulnerableIdentities += [PSCustomObject]@{
                            Identity = $identityName
                            SID = $aceSID
                            Rights = $aceRights
                            DangerousRight = $dangerousRightMatched
                            Severity = $severity
                            IsInherited = [bool]$ace.IsInherited
                        }
                    }

                    $broadNames = @($vulnerableIdentities | Where-Object {
                        $_.Severity -eq 'Finding' -and (Test-IsBroadTrustee -SID ([string]$_.SID)) -and
                        @(@(([string]$_.DangerousRight -split ' : ')[0] -split ',\s*') | Where-Object { $contentChangeRights -contains $_ }).Count -gt 0
                    } | ForEach-Object { [string]$_.Identity })
                    if ($broadNames.Count -gt 0) { $broadWritersByGUID[$gpoGUID] = $broadNames }

                    # If we found vulnerable identities for this GPO, add to results
                    if (@($vulnerableIdentities).Count -gt 0) {
                        # Get GPO Linkage for this GPO. Three-valued: $null when the map could
                        # not be built, @() when the map is fine but holds no entry - the
                        # second means "linked nowhere", which is knowledge and not the same
                        # thing. A bare index on a $null map also emits a "Cannot index into a
                        # null array" error record into the host.
                        $links = $null
                        if ($null -ne $gpoLinkage) {
                            $links = @()
                            if ($gpoLinkage.ContainsKey($gpoGUID)) { $links = @($gpoLinkage[$gpoGUID]) }
                        }
                        $activeLinks = @()
                        $isDomainWide = $false
                        $linkCount = 0

                        if ($links) {
                            $activeLinks = @($links | Where-Object { $_.LinkStatus -ne "Disabled" })
                            $linkCount = $activeLinks.Count

                            $domainWideLink = $activeLinks | Where-Object { $_.Scope -eq "Domain" }
                            $isDomainWide = ($null -ne $domainWideLink)
                        }

                        $affectedComputerCount = 0
                        # The computers the links put in scope, for the security filtering below.
                        $inScopeComputers = New-Object System.Collections.ArrayList

                        # A link on a container reaches the computers below it, unless a
                        # container between them blocks inheritance and the link is not
                        # enforced (coverage item A11) - the rule the reachesDomainControllers
                        # row and the signing contest go by. The domain root is a link like any
                        # other here: a policy linked there reaches no computer below an OU that
                        # blocks inheritance unless the link is enforced, and the count used to
                        # take every computer of the domain. A site link matches no container of
                        # the domain, so it is counted nowhere here - see below. Without the
                        # blocking containers (the context could not be read) no link counts as
                        # blocked, as before.
                        $containerLinks = @($activeLinks)
                        $blockedContainers = $null
                        $blockedOutComputers = 0
                        if ($containerLinks.Count -gt 0) {
                            $gpoContext = Get-DomainControllerGPOContext
                            if ($null -ne $gpoContext) { $blockedContainers = $gpoContext.BlockedContainers }

                            foreach ($computer in $allComputers) {
                                $computerDN = [string]$computer.distinguishedName
                                $computerChain = $computerChainCache[$computerDN]
                                if ($null -eq $computerChain) {
                                    $computerChain = @(Get-DNParentChain -DistinguishedName $computerDN -StopAt $domainDN)
                                    $computerChainCache[$computerDN] = $computerChain
                                }

                                $isCovered = $false
                                $passedBlock = $false
                                $stoppedByBlock = $false
                                foreach ($container in $computerChain) {
                                    foreach ($link in $containerLinks) {
                                        if (-not [string]::Equals([string]$link.DistinguishedName, $container, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
                                        $linkEnforced = ($link.IsEnforced -eq $true) -or ($link.LinkStatus -eq 'Enforced')
                                        if ($linkEnforced -or -not $passedBlock) { $isCovered = $true; break }
                                        $stoppedByBlock = $true
                                    }
                                    if ($isCovered) { break }
                                    # A block on this container stops what comes from above it, not
                                    # what is linked here.
                                    if ($blockedContainers -and $blockedContainers.ContainsKey($container.ToLowerInvariant())) { $passedBlock = $true }
                                }

                                if ($isCovered) { [void]$inScopeComputers.Add($computer) }
                                elseif ($stoppedByBlock) { $blockedOutComputers++ }
                            }
                        }
                        $affectedComputerCount = $inScopeComputers.Count
                        $blockNote = $null
                        if ($blockedOutComputers -gt 0) {
                            $blockNote = "$blockedOutComputers computer(s) below its links are not counted: inheritance is blocked on the way and none of those links is enforced"
                        }

                        # Security filtering (coverage item A10): a computer in scope applies
                        # the policy only if its token holds a principal granted Apply Group
                        # Policy and none denied it. The count used to take every computer
                        # below a link. Where the filtering is not known, or lets every
                        # computer apply the policy, the count stands as it was.
                        $securityFilterNote = $null
                        $securityFilter = Get-GPOSecurityFilter -GPOGUID $gpoGUID
                        if ($null -ne $securityFilter -and -not ($securityFilter.Everyone -and @($securityFilter.DenySIDs).Count -eq 0)) {
                            $applyingComputers = 0
                            $undecidedComputers = 0
                            foreach ($computer in $inScopeComputers) {
                                $filterVerdict = Test-GPOFilterCoversComputer -Filter $securityFilter -Computer $computer
                                if ($filterVerdict -eq 'Yes') { $applyingComputers++ }
                                elseif ($filterVerdict -eq 'Unknown') { $undecidedComputers++ }
                            }
                            $affectedComputerCount = $applyingComputers
                            $securityFilterNote = "security filtering: $(Format-GPOSecurityFilter -Filter $securityFilter)"
                            if ($undecidedComputers -gt 0) {
                                $securityFilterNote += " - $undecidedComputers more computer(s) may apply it, whose membership could not be read"
                            }
                        }

                        # A site link applies to whichever computers sit in that site, and
                        # site membership follows the IP subnet a computer is in when it
                        # starts - nothing the directory records per computer. The OU walk
                        # above therefore never counts one, and "0" next to a site link read
                        # as "affects nothing". Unknown when the site is all there is; with
                        # OU links beside it the count stands as what it is, a lower bound,
                        # and the row next to it says so.
                        $affectedComputersNote = $null
                        $hasSiteLink = @($activeLinks | Where-Object { $_.Scope -eq 'Site' }).Count -gt 0
                        if ($hasSiteLink -and -not $isDomainWide) {
                            if ($affectedComputerCount -eq 0) {
                                $affectedComputerCount = 'unknown - site membership follows IP subnets, not the directory'
                            } else {
                                $affectedComputersNote = 'plus the computers of the linked site(s), which the directory does not record - site membership follows IP subnets'
                            }
                        }
                        foreach ($extraNote in @($blockNote, $securityFilterNote)) {
                            if (-not $extraNote) { continue }
                            if ($affectedComputersNote) { $affectedComputersNote = "$affectedComputersNote; $extraNote" }
                            else { $affectedComputersNote = $extraNote }
                        }

                        # Where the policy applies. The full link records, disabled ones
                        # included - the LinkedOUs transformer marks those and renders an
                        # empty list as "Not linked". Handed over as an array rather than a
                        # newline-joined string, so each link is its own row and can carry
                        # its own colour.
                        # Only the unresolved case needs a string: "Not linked" would be a
                        # claim the failed lookup cannot support.
                        $linkedOUsDisplay = $links
                        if ($null -eq $links) {
                            $linkedOUsDisplay = 'Unknown - linkage could not be resolved'
                        }

                        # Format vulnerable identities for display.
                        #
                        # Inheritance is named because the remediation differs: an inherited
                        # ACE cannot be removed on the GPO, it has to be removed at the
                        # container it comes from - otherwise the reader deletes it in the
                        # GPO's delegation tab, sees it reappear, and has no idea why.
                        # Outside the parentheses, so it stays clear of the rights the
                        # DangerousPermissions triggers read.
                        $identityDisplay = ($vulnerableIdentities | ForEach-Object {
                            $row = "$($_.Identity) ($($_.DangerousRight))"
                            if ($_.IsInherited) {
                                $row = "$row [inherited - remove it at the parent container]"
                            }
                            $row
                        }) -join "`n"

                        # What colour the DangerousPermissions block renders in.
                        #
                        # DANGEROUS_RIGHTS_CONTEXT decides severity for this attribute family
                        # from the source object's dangerousRightsSeverity: Expected,
                        # Attention or Hint downgrade the block to yellow, anything else -
                        # including the property being absent - leaves it red. This check
                        # never set it, so a -IncludePrivileged run, whose whole purpose is to
                        # show privileged trustees as expected rather than as findings,
                        # rendered them in the same red as a genuine one.
                        #
                        # One value for the whole block, because that is the granularity this
                        # check has: one object per GPO, every vulnerable trustee joined into
                        # one attribute. Yellow only when every reported trustee is an
                        # expected one - a single genuine finding in the list makes the block
                        # a finding, and colouring it yellow because a privileged trustee sits
                        # next to it would understate it. Without -IncludePrivileged the
                        # expected ones never reach this list at all, so the aggregate is
                        # always Finding there and nothing changes.
                        # 'Hint' is in the list because an attribute-scoped write that
                        # cannot reach the policy content sets it above, for the same
                        # reason: a block that holds nothing worse than that is not a
                        # finding either.
                        $unexpectedIdentities = @($vulnerableIdentities |
                            Where-Object { $_.Severity -notin @('Expected', 'Attention', 'Hint') })
                        $blockSeverity = if ($unexpectedIdentities.Count -eq 0) { 'Hint' } else { 'Finding' }

                        $enrichedGPO = $gpo.PSObject.Copy()
                        $enrichedGPO | Add-Member -NotePropertyName "DangerousPermissions" -NotePropertyValue $identityDisplay -Force
                        $enrichedGPO | Add-Member -NotePropertyName "dangerousRightsSeverity" -NotePropertyValue $blockSeverity -Force

                        # GPOOwner, not Owner: the generic 'Owner' attribute carries
                        # NON_DEFAULT_OWNER, a Hint, for every object type there is. An
                        # owner of a GPO can grant itself full control over code that runs
                        # on every machine the policy reaches, which is not the same
                        # finding, and a trigger cannot tell the object types apart.
                        if ($ownerFinding) {
                            $enrichedGPO | Add-Member -NotePropertyName "GPOOwner" -NotePropertyValue $ownerFinding.Owner -Force
                        }
                        $enrichedGPO | Add-Member -NotePropertyName "LinkedOUs" -NotePropertyValue $linkedOUsDisplay -Force
                        # Which of those links put a domain controller in the policy's scope -
                        # whoever can edit this policy then runs code there. Marked on
                        # LinkedOUs, no verdict.
                        Add-GPODomainControllerReach -Object $enrichedGPO -Reach (Get-GPODomainControllerReachDetail -Link $links -GPOGUID $gpoGUID)
                        Add-GPOConditionRow -Object $enrichedGPO -GPOGUID $gpoGUID

                        # The object is a copy of the GPO and already carries GPOStatus from
                        # Get-DomainGPO; the transformer hides it when it says "Enabled".
                        # This only adds what that attribute cannot know: links that exist
                        # and are switched off to the last one. Scope 'Any' - a permission on
                        # the GPO object belongs to neither half of the policy.
                        # $links, not $linkedOUsDisplay: the display value may be the Unknown
                        # string, and Get-GPOEffectiveStatus needs the $null that makes it
                        # decline to judge rather than a one-element array of text.
                        $gpoStatus = Get-GPOEffectiveStatus -StatusEntry $gpoStatusMap[$gpoGUID] `
                            -Scope 'Any' -Link $links
                        if ($gpoStatus) {
                            $enrichedGPO | Add-Member -NotePropertyName "GPOStatus" -NotePropertyValue $gpoStatus -Force
                        }
                        $enrichedGPO | Add-Member -NotePropertyName "affectedComputerCount" -NotePropertyValue $affectedComputerCount -Force
                        if ($affectedComputersNote) {
                            $enrichedGPO | Add-Member -NotePropertyName "affectedComputersNote" -NotePropertyValue $affectedComputersNote -Force
                        }
                        $enrichedGPO | Add-Member -NotePropertyName "IsDomainWide" -NotePropertyValue $isDomainWide -Force

                        $vulnerableGPOsHash[$gpoGUID] = $enrichedGPO
                    }
                }
                catch {
                    Write-Log "[Get-GPOPermissions] Error analyzing GPO $gpoDisplayName : $_"
                }
            }
            if ($totalGPOs -gt $Script:ProgressThreshold) { Show-Progress -Activity "Checking GPO permissions" -Completed }

            # ===== Step 5: The other half of each policy - the SYSVOL folder =====
            #
            # A GPO is a directory object and a folder, and everything above reads the
            # object. The folder under \\<domain>\SYSVOL\<domain>\Policies\{GUID}\ is where
            # the policy's content actually lives: Registry.pol, GptTmpl.inf, the Scripts
            # folder, ScheduledTasks.xml, GPT.ini. Write access there rewrites what every
            # machine in scope applies, and needs no permission on the directory object at
            # all - which is the standard outcome of somebody once setting "Everyone:
            # Modify" on a policy folder, or rebuilding SYSVOL inheritance by hand.
            #
            # Script-scoped, because the scriptblock Invoke-SMBAccess invokes runs in a
            # child scope: a plain assignment inside it would be discarded. Cleared in
            # Clear-SessionState with everything else.
            $Script:_gpoSysvolRows = @{}
            $Script:_gpoSysvolUnread = @()
            $Script:_gpoSysvolScanned = $false
            # Coverage item B19: a policy whose folder or gpt.ini is not there, and a folder
            # named for no policy object, are facts of their own - neither is a folder that
            # could not be read, which is how the first used to be reported.
            $Script:_gpoSysvolMissing = @()
            $Script:_gpoSysvolOrphans = @()
            $Script:_gpoSysvolBroadWriters = @{}

            Invoke-SMBAccess -Description "Reading the NTFS permissions of the GPO folders in SYSVOL" -ScriptBlock {
                $policiesPath = "\\$($Script:LDAPContext.Server)\SYSVOL\$($Script:LDAPContext.Domain)\Policies"

                if (-not (Test-Path $policiesPath)) {
                    Write-Log "[Get-GPOPermissions] SYSVOL is not reachable at $policiesPath - the folder permissions were not examined"
                    return
                }

                $Script:_gpoSysvolScanned = $true

                # The folders under Policies, by name. $null where the listing failed: then
                # no folder can be said to be missing.
                $policyFolders = $null
                $folderListErrors = @()
                $listedFolders = @(Get-ChildItem -Force -LiteralPath $policiesPath -Directory -ErrorAction SilentlyContinue -ErrorVariable +folderListErrors)
                if (@($folderListErrors).Count -eq 0) {
                    $policyFolders = @{}
                    foreach ($listedFolder in $listedFolders) { $policyFolders[[string]$listedFolder.Name] = $true }
                } else {
                    Write-Log "[Get-GPOPermissions] Could not list $policiesPath - missing and orphaned policy folders are not told apart: $($folderListErrors[0])"
                }

                # The policies with a gpt.ini, from the SYSVOL listing. A client opens the
                # gpt.ini of every policy in its scope before it applies any (MS-GPOL, GPO
                # Search). $null where the listing did not reach SYSVOL, and a policy whose
                # folder it could not read is left unknown rather than called empty.
                $gptIniGUIDs = $null
                $gptIniUnknown = @{}
                $gptIniFiles = @(Get-CachedSYSVOLFiles -Filter 'gpt.ini')
                $listingCoverage = Get-SYSVOLCacheCoverage
                if ($null -ne $listingCoverage -and $listingCoverage.Reachable) {
                    $gptIniGUIDs = @{}
                    foreach ($gptIniFile in $gptIniFiles) {
                        if ([string]$gptIniFile.FullName -match '(?i)\\Policies\\(\{[0-9A-F-]+\})\\gpt\.ini$') { $gptIniGUIDs[$Matches[1]] = $true }
                    }
                    foreach ($skippedPath in @($listingCoverage.SkippedPaths)) {
                        if ("$skippedPath" -match '(?i)\\Policies\\?$') { $gptIniGUIDs = $null; break }
                        if ("$skippedPath" -match '(?i)\\Policies\\(\{[0-9A-F-]+\})\\?$') { $gptIniUnknown[$Matches[1]] = $true }
                    }
                }

                $sysvolTotal = @($allGPOs).Count
                $sysvolIndex = 0
                foreach ($sysvolGPO in $allGPOs) {
                    $sysvolIndex++
                    if ($sysvolTotal -gt $Script:ProgressThreshold) {
                        Show-Progress -Activity "Checking GPO folder permissions in SYSVOL" -Current $sysvolIndex -Total $sysvolTotal -ObjectName $sysvolGPO.displayName
                    }

                    $sysvolGUID = [string]$sysvolGPO.Name
                    if (-not $sysvolGUID) { continue }

                    # Built from the GUID rather than taken from gPCFileSysPath. That
                    # attribute holds the domain DFS namespace path, which is a different
                    # SMB target than the DC hostname Invoke-SMBAccess authenticated
                    # against - a client that reaches one may not reach the other, and the
                    # mismatch fails silently. A gPCFileSysPath pointing somewhere else
                    # entirely is its own finding on the directory object above.
                    $gpoFolder = Join-Path $policiesPath $sysvolGUID

                    # Only a policy whose gPCFileSysPath names this folder - or none - is
                    # expected to have it. One that points elsewhere keeps its files there.
                    $sysvolPathAttr = [string]$sysvolGPO.gPCFileSysPath
                    $folderExpected = (-not $sysvolPathAttr) -or ($sysvolPathAttr.TrimEnd('\') -match "(?i)\\Policies\\$([regex]::Escape($sysvolGUID))$")

                    if ($folderExpected -and $null -ne $policyFolders -and -not $policyFolders.ContainsKey($sysvolGUID)) {
                        $Script:_gpoSysvolMissing += [PSCustomObject]@{ GPO = $sysvolGPO; What = 'no folder' }
                        continue
                    }

                    $rules = Get-DirectoryAccessRules -Path $gpoFolder

                    # $null means the folder could not be read, which is not the same as
                    # "nobody has write access to it".
                    if ($null -eq $rules) {
                        $Script:_gpoSysvolUnread += ([string]$sysvolGPO.DisplayName)
                        continue
                    }

                    # Deny netting, the write mask and the two identity gates the directory
                    # half uses - see Select-NTFSWriteAccess, which Get-GPOScheduledTasks
                    # shares for the program a SYSTEM or privileged task starts from a share.
                    #
                    # Inherit-only rules count here. The children of a policy folder are
                    # the policy, so a Modify that reaches only them still rewrites it.
                    $folderWriters = @(Select-NTFSWriteAccess -Rules $rules -Target $gpoFolder `
                        -Caller 'Get-GPOPermissions' -IncludePrivileged:$IncludePrivileged)
                    $folderRows = @($folderWriters | ForEach-Object { $_.Row })

                    if (@($folderRows).Count -gt 0) {
                        $Script:_gpoSysvolRows[$sysvolGUID] = @($folderRows)
                    }

                    # Every trustee here may rewrite the policy content - see oneLinkAway.
                    $broadFolderWriters = @($folderWriters | Where-Object { Test-IsBroadTrustee -SID ([string]$_.SID) } |
                        ForEach-Object { [string]$_.Identity })
                    if ($broadFolderWriters.Count -gt 0) { $Script:_gpoSysvolBroadWriters[$sysvolGUID] = $broadFolderWriters }

                    if ($folderExpected -and $null -ne $gptIniGUIDs -and
                        -not $gptIniGUIDs.ContainsKey($sysvolGUID) -and -not $gptIniUnknown.ContainsKey($sysvolGUID)) {
                        $Script:_gpoSysvolMissing += [PSCustomObject]@{ GPO = $sysvolGPO; What = 'no gpt.ini' }
                    }
                }

                # Folders named like a policy GUID that no policy object read above has. Left
                # over from a deleted policy as a rule - or the folder of a policy this account
                # may not read, which security filtering can hide; the line says both.
                if ($null -ne $policyFolders) {
                    $knownGUIDs = @{}
                    foreach ($knownGPO in $allGPOs) { if ($knownGPO.Name) { $knownGUIDs[[string]$knownGPO.Name] = $true } }
                    foreach ($folderName in @($policyFolders.Keys | Sort-Object)) {
                        if ($folderName -match '^\{[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}$' -and
                            -not $knownGUIDs.ContainsKey($folderName)) {
                            $Script:_gpoSysvolOrphans += $folderName
                        }
                    }
                }

                if ($sysvolTotal -gt $Script:ProgressThreshold) {
                    Show-Progress -Activity "Checking GPO folder permissions in SYSVOL" -Completed
                }
            }

            $vulnerableGPOs = @($vulnerableGPOsHash.Values)

            # The SYSVOL rows join the card the directory half already built, so one
            # policy is one card with both halves on it rather than two cards that look
            # like two findings.
            foreach ($sysvolGUID in @($Script:_gpoSysvolRows.Keys)) {
                if (-not $vulnerableGPOsHash.ContainsKey($sysvolGUID)) { continue }
                $vulnerableGPOsHash[$sysvolGUID] | Add-Member -NotePropertyName 'SysvolPermissions' `
                    -NotePropertyValue ((@($Script:_gpoSysvolRows[$sysvolGUID])) -join "`n") -Force
            }

            # A policy whose DACL holds nothing dangerous but which needs a card anyway:
            # its owner is not a default one, or its SYSVOL folder is writable, or both.
            # Both used to fall through the "no dangerous ACEs" branch - the owner because
            # it was never read, the folder because nothing in the project looked at it.
            $gpoByGUID = @{}
            foreach ($indexedGPO in $allGPOs) {
                if ($indexedGPO.Name) { $gpoByGUID[[string]$indexedGPO.Name] = $indexedGPO }
            }

            $extraCardGUIDs = @{}
            foreach ($extraGUID in @($ownerOnlyGPOs.Keys)) { $extraCardGUIDs[$extraGUID] = $true }
            foreach ($extraGUID in @($Script:_gpoSysvolRows.Keys)) {
                if (-not $vulnerableGPOsHash.ContainsKey($extraGUID)) { $extraCardGUIDs[$extraGUID] = $true }
            }

            foreach ($extraGUID in @($extraCardGUIDs.Keys)) {
                $extraSource = $null
                if ($ownerOnlyGPOs.ContainsKey($extraGUID)) { $extraSource = $ownerOnlyGPOs[$extraGUID].GPO }
                elseif ($gpoByGUID.ContainsKey($extraGUID)) { $extraSource = $gpoByGUID[$extraGUID] }
                if (-not $extraSource) { continue }

                $extraCard = $extraSource.PSObject.Copy()

                if ($ownerOnlyGPOs.ContainsKey($extraGUID)) {
                    $extraCard | Add-Member -NotePropertyName "GPOOwner" -NotePropertyValue $ownerOnlyGPOs[$extraGUID].Owner.Owner -Force
                }
                if ($Script:_gpoSysvolRows.ContainsKey($extraGUID)) {
                    $extraCard | Add-Member -NotePropertyName "SysvolPermissions" `
                        -NotePropertyValue ((@($Script:_gpoSysvolRows[$extraGUID])) -join "`n") -Force
                }

                $extraLinks = $null
                if ($null -ne $gpoLinkage) {
                    $extraLinks = @()
                    if ($gpoLinkage.ContainsKey($extraGUID)) { $extraLinks = @($gpoLinkage[$extraGUID]) }
                }
                $extraLinksDisplay = $extraLinks
                if ($null -eq $extraLinks) {
                    $extraLinksDisplay = 'Unknown - linkage could not be resolved'
                }
                $extraCard | Add-Member -NotePropertyName "LinkedOUs" -NotePropertyValue $extraLinksDisplay -Force
                Add-GPODomainControllerReach -Object $extraCard -Reach (Get-GPODomainControllerReachDetail -Link $extraLinks -GPOGUID $extraGUID)
                Add-GPOConditionRow -Object $extraCard -GPOGUID $extraGUID

                $extraStatus = Get-GPOEffectiveStatus -StatusEntry $gpoStatusMap[$extraGUID] -Scope 'Any' -Link $extraLinks
                if ($extraStatus) {
                    $extraCard | Add-Member -NotePropertyName "GPOStatus" -NotePropertyValue $extraStatus -Force
                }

                $vulnerableGPOs += $extraCard
            }

            # Coverage item B20: a policy that applies nowhere is not harmless when a broad
            # group may change it. Whatever a member writes into it waits there, and the
            # policy applies it the moment anyone links it - an administrator reviving an old
            # policy, or whoever may write gPLink on an OU, a site or the domain. Only where
            # the links are known: unresolved links say nothing either way.
            if ($null -ne $gpoLinkage) {
                foreach ($card in @($vulnerableGPOs)) {
                    $cardGUID = [string]$card.Name
                    $cardLinks = @()
                    if ($gpoLinkage.ContainsKey($cardGUID)) { $cardLinks = @($gpoLinkage[$cardGUID]) }
                    if (@($cardLinks | Where-Object { $_.LinkStatus -ne 'Disabled' }).Count -gt 0) { continue }

                    $cardWriters = @()
                    if ($broadWritersByGUID.ContainsKey($cardGUID)) { $cardWriters += @($broadWritersByGUID[$cardGUID]) }
                    if ($Script:_gpoSysvolBroadWriters.ContainsKey($cardGUID)) { $cardWriters += @($Script:_gpoSysvolBroadWriters[$cardGUID]) }
                    $cardWriters = @($cardWriters | Select-Object -Unique)
                    if ($cardWriters.Count -eq 0) { continue }

                    $notApplied = 'nothing links it'
                    if ($cardLinks.Count -gt 0) { $notApplied = 'its links are disabled' }
                    $card | Add-Member -NotePropertyName 'oneLinkAway' `
                        -NotePropertyValue "$($cardWriters -join ', ') may change it and $notApplied - one link applies whatever it then holds below that link" -Force
                }
            }

            # Same coverage contract as the OU permission checks: the note names how many
            # objects were not readable and lists them, and a clean conclusion drops from
            # Secure to Note when it does not cover everything.
            $coverageIncomplete = Show-OUPermissionsCoverageNote -UnreadOUs $unreadGPOs -TotalOUs @($allGPOs).Count

            # The SYSVOL half has its own coverage question: a folder that could not be
            # read says nothing about who may write it.
            $sysvolCoverageIncomplete = $false
            if (-not $Script:_gpoSysvolScanned) {
                # What write access in SYSVOL buys an attacker is on the card. The console
                # says what was not examined.
                Show-Line "SYSVOL was not reachable - the NTFS permissions of the policy folders were not examined" -Class Finding
                $sysvolCoverageIncomplete = $true
            }
            elseif (@($Script:_gpoSysvolUnread).Count -gt 0) {
                Show-Line "The NTFS permissions of $(@($Script:_gpoSysvolUnread).Count) of $(@($allGPOs).Count) policy folder(s) in SYSVOL could not be read - who may rewrite their content is unknown" -Class Finding
                foreach ($unreadFolder in (@($Script:_gpoSysvolUnread) | Select-Object -First 10)) {
                    Show-Line "  not read: $unreadFolder" -Class Hint
                }
                if (@($Script:_gpoSysvolUnread).Count -gt 10) {
                    Show-Line "  ... and $(@($Script:_gpoSysvolUnread).Count - 10) more" -Class Hint
                }
                $sysvolCoverageIncomplete = $true
            }

            # A client that cannot open the gpt.ini of a policy in its scope stops - Event
            # 1058 reads "Group Policy processing aborted". Whether that reaches anybody is a
            # question of the links, and links that could not be resolved are said to be so
            # rather than taken for none.
            if (@($Script:_gpoSysvolMissing).Count -gt 0) {
                $missingLines = @()
                $missingReachesAnybody = $false
                foreach ($missing in @($Script:_gpoSysvolMissing)) {
                    $missingGUID = [string]$missing.GPO.Name
                    $linkState = 'links unknown'
                    if ($null -ne $gpoLinkage) {
                        $linkState = 'not linked'
                        if ($gpoLinkage.ContainsKey($missingGUID) -and
                            @($gpoLinkage[$missingGUID] | Where-Object { $_.LinkStatus -ne 'Disabled' }).Count -gt 0) {
                            $linkState = 'linked'
                        }
                    }
                    if ($linkState -ne 'not linked') { $missingReachesAnybody = $true }
                    $missingLines += "  $($missing.GPO.DisplayName) $missingGUID - $($missing.What), $linkState"
                }
                $missingClass = 'Note'
                if ($missingReachesAnybody) { $missingClass = 'Hint' }
                Show-Line "$(@($missingLines).Count) GPO(s) have no folder or no gpt.ini in SYSVOL on $($Script:LDAPContext.Server) - Group Policy processing aborts where they are linked" -Class $missingClass -FindingId 'GPO_SYSVOL_GPT_MISSING'
                foreach ($missingLine in (@($missingLines) | Select-Object -First 10)) {
                    Show-Line $missingLine -Class $missingClass
                }
                if (@($missingLines).Count -gt 10) {
                    Show-Line "  ... and $(@($missingLines).Count - 10) more" -Class $missingClass
                }
            }

            if (@($Script:_gpoSysvolOrphans).Count -gt 0) {
                Show-Line "$(@($Script:_gpoSysvolOrphans).Count) folder(s) in SYSVOL\Policies on $($Script:LDAPContext.Server) belong to no GPO this account can read - deleted, or hidden from it" -Class Note -FindingId 'GPO_SYSVOL_FOLDER_ORPHANED'
                foreach ($orphanFolder in (@($Script:_gpoSysvolOrphans) | Select-Object -First 10)) {
                    Show-Line "  $orphanFolder" -Class Note
                }
                if (@($Script:_gpoSysvolOrphans).Count -gt 10) {
                    Show-Line "  ... and $(@($Script:_gpoSysvolOrphans).Count - 10) more" -Class Note
                }
            }

            if (@($vulnerableGPOs).Count -gt 0) {
                $ownerOnlyCount = @($ownerOnlyGPOs.Keys).Count
                $sysvolCount = @($Script:_gpoSysvolRows.Keys).Count
                $summary = "Found $(@($vulnerableGPOs).Count) GPO(s) with dangerous permissions, a writable SYSVOL folder or a non-default owner"
                $summaryDetail = @()
                if ($ownerOnlyCount -gt 0) { $summaryDetail += "$ownerOnlyCount of them by ownership alone" }
                if ($sysvolCount -gt 0) { $summaryDetail += "$sysvolCount with a writable policy folder" }
                if (@($summaryDetail).Count -gt 0) {
                    $summary = "$summary (" + ($summaryDetail -join ', ') + ")"
                }
                Show-Line $summary -Class Finding

                foreach ($gpo in $vulnerableGPOs) {
                    $gpo | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPOPermission' -Force

                    # The class the policy is filed under - the console ignores it, the JSON
                    # export and the report diff do not. A finding, unless all the policy is
                    # listed for is an ACE block this check rated a hint above: privileged
                    # trustees under -IncludePrivileged, or a write that cannot reach the
                    # policy content. A non-default owner or a writable policy folder is a
                    # finding of its own.
                    $gpoClass = 'Finding'
                    if ([string]$gpo.dangerousRightsSeverity -eq 'Hint' -and
                        -not $gpo.PSObject.Properties['GPOOwner'] -and
                        -not $gpo.PSObject.Properties['SysvolPermissions']) {
                        $gpoClass = 'Hint'
                    }
                    Show-Object $gpo -Class $gpoClass
                }
            }
            else {
                # This line used to count every GPO as analyzed, unreadable descriptors
                # included, and to say "No dangerous GPO permissions" - which a reader
                # takes to cover the whole policy while only the directory object had been
                # looked at. Both halves are read now, and the sentence names them.
                $readCount = @($allGPOs).Count - @($unreadGPOs).Count
                $conclusionClass = 'Secure'
                if ($coverageIncomplete -or $sysvolCoverageIncomplete) { $conclusionClass = 'Note' }
                Show-Line "No dangerous permissions, no non-default owner and no unexpected SYSVOL write access on $readCount of $(@($allGPOs).Count) GPO(s)" -Class $conclusionClass
            }

        } catch {
            Write-Log "[Get-GPOPermissions] Error: $_" -Level Error
            Show-Line "Error during check - GPO permissions could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-GPOPermissions] Check completed"
    }
}
