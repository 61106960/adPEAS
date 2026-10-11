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

        # The rights an ObjectType GUID cannot narrow. ObjectType restricts the
        # attribute-scoped bits - WriteProperty, ReadProperty, Self, ExtendedRight - and
        # nothing else, so an ACE that also grants one of these is not limited by the
        # attribute it names.
        # The NTFS rights that let their holder rewrite the content of a policy folder.
        # A mask rather than a list of names, because FileSystemRights is a flag field and
        # the combinations that occur in practice - FullControl, Modify, Write - do not
        # decompose into a fixed set of names.
        #
        # WriteAttributes and WriteExtendedAttributes are deliberately not in it: they
        # change timestamps and metadata, not file content, and including them would put a
        # finding on the default ACL of every policy folder in the domain.
        $Script:SysvolWriteRights = [int](
            [System.Security.AccessControl.FileSystemRights]::CreateFiles -bor
            [System.Security.AccessControl.FileSystemRights]::CreateDirectories -bor
            [System.Security.AccessControl.FileSystemRights]::Delete -bor
            [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
            [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
            [System.Security.AccessControl.FileSystemRights]::TakeOwnership
        )

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
            $allComputers = @(Get-DomainComputer -Properties "name","distinguishedName" @connectionParams)

            if (-not $allComputers) {
                $allComputers = @()
            }

            # ===== Step 3: Get GPO Linkage =====
            $gpoLinkage = Get-GPOLinkage

            # ===== Step 4: Analyze GPO Permissions =====
            $vulnerableGPOsHash = @{}

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
                    # by trustee: a Deny on one trustee says nothing about another.
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
                        $deniedRights[$denySID] += @($ace.RightsRaw)
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
                        $deniedForTrustee = @()
                        if ($deniedRights.ContainsKey([string]$aceSID)) {
                            $deniedForTrustee = @($deniedRights[[string]$aceSID])
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

                        # An ObjectType narrows the attribute-scoped bits only. An ACE that
                        # also grants GenericAll or WriteDacl is not limited by the
                        # attribute it names.
                        $unscopedMatched = @($matchedRights | Where-Object { $Script:UnscopedGPORights -contains $_ })

                        if ($aceObjectType -and @($unscopedMatched).Count -eq 0) {
                            $resolvedScope = Resolve-ObjectTypeGUID -GUID $aceObjectType
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

                        if ($isDomainWide) {
                            $affectedComputerCount = @($allComputers).Count
                        }
                        elseif (@($activeLinks).Count -gt 0) {
                            foreach ($computer in $allComputers) {
                                $computerDN = $computer.distinguishedName

                                if ($computerDN -match '^CN=[^,]+,(.+)$') {
                                    $computerParentDN = $Matches[1]
                                    $isCovered = $false
                                    $currentDN = $computerParentDN

                                    while ($currentDN -ne $domainDN -and -not $isCovered) {
                                        foreach ($link in $activeLinks) {
                                            if ($link.DistinguishedName -eq $currentDN) {
                                                $isCovered = $true
                                                break
                                            }
                                        }

                                        if ($isCovered) { break }

                                        if ($currentDN -match '^[^,]+,(.+)$') {
                                            $currentDN = $Matches[1]
                                        }
                                        else {
                                            break
                                        }
                                    }

                                    if ($isCovered) {
                                        $affectedComputerCount++
                                    }
                                }
                            }
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

            Invoke-SMBAccess -Description "Reading the NTFS permissions of the GPO folders in SYSVOL" -ScriptBlock {
                $policiesPath = "\\$($Script:LDAPContext.Server)\SYSVOL\$($Script:LDAPContext.Domain)\Policies"

                if (-not (Test-Path $policiesPath)) {
                    Write-Log "[Get-GPOPermissions] SYSVOL is not reachable at $policiesPath - the folder permissions were not examined"
                    return
                }

                $Script:_gpoSysvolScanned = $true

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
                    $rules = Get-DirectoryAccessRules -Path $gpoFolder

                    # $null means the folder could not be read, which is not the same as
                    # "nobody has write access to it".
                    if ($null -eq $rules) {
                        $Script:_gpoSysvolUnread += ([string]$sysvolGPO.DisplayName)
                        continue
                    }

                    # Deny first and per trustee, the same way the DACL half does it: a
                    # Deny rule wins the access check, so an Allow it covers grants
                    # nothing. Masks rather than names, because FileSystemRights is a flag
                    # field and the combinations do not all have names.
                    $deniedMask = @{}
                    foreach ($rule in $rules) {
                        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Deny) { continue }
                        $denySID = [string]$rule.IdentityReference.Value
                        if (-not $denySID) { continue }
                        if (-not $deniedMask.ContainsKey($denySID)) { $deniedMask[$denySID] = 0 }
                        $deniedMask[$denySID] = $deniedMask[$denySID] -bor [int]$rule.FileSystemRights
                    }

                    $folderRows = @()
                    foreach ($rule in $rules) {
                        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }

                        $ruleSID = [string]$rule.IdentityReference.Value
                        if (-not $ruleSID) { continue }

                        $effective = [int]$rule.FileSystemRights
                        if ($deniedMask.ContainsKey($ruleSID)) {
                            $effective = $effective -band (-bnot $deniedMask[$ruleSID])
                        }

                        $writeBits = $effective -band $Script:SysvolWriteRights
                        if ($writeBits -eq 0) { continue }

                        # The same two gates the directory half uses, so one identity is
                        # not expected on the object and a finding on its folder.
                        $sysvolExpected = Test-IsExpectedACLIdentity -SID $ruleSID -Context 'GPO'
                        if ($sysvolExpected.Skip) { continue }

                        $sysvolScope = Test-IsExpectedInScope -Identity $ruleSID -Scope 'GPO' -ReturnDetails
                        if ($sysvolScope.Severity -eq 'Expected') { continue }
                        if (-not $IncludePrivileged -and $sysvolScope.Severity -eq 'Attention') {
                            Write-Log "[Get-GPOPermissions] Attention: $ruleSID can write the SYSVOL folder of $($sysvolGPO.DisplayName) - $($sysvolScope.Reason) - skipped (use -IncludePrivileged to include)"
                            continue
                        }

                        $ruleIdentity = ConvertFrom-SID -SID $ruleSID
                        if (-not $ruleIdentity) { $ruleIdentity = $ruleSID }

                        # The effective rights, not the write bits of them: an admin reads
                        # "FullControl" in Explorer, not the six flags it decomposes into.
                        # Where a Deny took something away the name changes with it, which
                        # is the point. Synchronize sits on every rule and says nothing.
                        $rightsText = ([System.Security.AccessControl.FileSystemRights]$effective).ToString() -replace '(,\s*)?Synchronize', ''
                        if (-not $rightsText) { $rightsText = "$writeBits" }

                        $row = "$ruleIdentity ($rightsText)"
                        if ($rule.IsInherited) {
                            $row = "$row [inherited - remove it at the parent folder]"
                        }
                        $folderRows += $row
                        Write-Log "[Get-GPOPermissions] FINDING: $ruleIdentity can write $gpoFolder ($rightsText)"
                    }

                    if (@($folderRows).Count -gt 0) {
                        $Script:_gpoSysvolRows[$sysvolGUID] = @($folderRows)
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

                $extraStatus = Get-GPOEffectiveStatus -StatusEntry $gpoStatusMap[$extraGUID] -Scope 'Any' -Link $extraLinks
                if ($extraStatus) {
                    $extraCard | Add-Member -NotePropertyName "GPOStatus" -NotePropertyValue $extraStatus -Force
                }

                $vulnerableGPOs += $extraCard
            }

            # Same coverage contract as the OU permission checks: the note names how many
            # objects were not readable and lists them, and a clean conclusion drops from
            # Secure to Note when it does not cover everything.
            $coverageIncomplete = Show-OUPermissionsCoverageNote -UnreadOUs $unreadGPOs -TotalOUs @($allGPOs).Count

            # The SYSVOL half has its own coverage question: a folder that could not be
            # read says nothing about who may write it.
            $sysvolCoverageIncomplete = $false
            if (-not $Script:_gpoSysvolScanned) {
                Show-Line "SYSVOL was not reachable - the NTFS permissions of the policy folders were not examined, and write access there rewrites the policy content without any permission on the directory object" -Class Finding
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
                    Show-Object $gpo
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
                Show-Line "No dangerous permissions and no non-default owner on $readCount of $(@($allGPOs).Count) GPO directory object(s), and no unexpected write access to their policy folders in SYSVOL" -Class $conclusionClass
            }

        } catch {
            Write-Log "[Get-GPOPermissions] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-GPOPermissions] Check completed"
    }
}
