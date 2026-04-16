function Get-AddComputerRights {
    <#
    .SYNOPSIS
    Analyzes "Add Computer to Domain" permissions and quota settings.

    .DESCRIPTION
    Performs comprehensive analysis of computer account creation permissions:

    1. ms-DS-MachineAccountQuota (Domain attribute)
       - Default: 10 (any authenticated user can add 10 computers)
       - Secure: 0 (only explicit permissions)

    2. ACL on CN=Computers container
       - Create Computer Objects permission
       - Extended Right "Add workstations to domain"

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
        [switch]$IncludePrivileged
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
            $machineQuota = if ($domainResult -and $domainResult.'ms-DS-MachineAccountQuota') {
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

            # ===== Step 2: Check ACL on CN=Computers Container =====
            $computersContainerDN = "CN=Computers,$domainDN"
            $createComputerAccounts = @()

            # Use Get-ObjectACL for ACL analysis (handles credentials automatically)
            $computerClassGUID = 'bf967a86-0de6-11d0-a285-00aa003049e2'
            $aclResult = Get-ObjectACL -DistinguishedName $computersContainerDN -Rights 'GenericAll','CreateChild' -AllowOnly -ExplicitOnly @connectionParams

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

                    # Check if this ACE grants CreateChild for Computer objects
                    $hasCreateChild = $false
                    if ($ace.RightsRaw -contains 'GenericAll') {
                        $hasCreateChild = $true
                    } elseif ($ace.RightsRaw -contains 'CreateChild') {
                        # CreateChild must be for all objects or specifically for Computer class
                        if (-not $ace.ObjectType -or $ace.ObjectType -eq $computerClassGUID) {
                            $hasCreateChild = $true
                        }
                    }

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

            # ===== Step 4: Output findings as objects =====

            # Finding 1: MachineAccountQuota as object
            # Note: Quota > 0 is a Hint (not Finding) - it's a configuration worth noting but not critical
            if ($quotaValue -eq 0) {
                Show-Line "ms-DS-MachineAccountQuota is 0 - computer creation restricted to explicit permissions" -Class Secure
            } else {
                Show-Line "Found ms-DS-MachineAccountQuota configured - any authenticated user can add computers:" -Class Hint

                $quotaObject = [PSCustomObject]@{
                    'ms-DS-MachineAccountQuota' = $quotaValue
                }
                $quotaObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'MachineAccountQuota' -Force
                Show-Object $quotaObject
                $hasFindings = $true
            }

            # Finding 2: Explicit ACLs on CN=Computers (show full AD objects)
            if (@($createComputerAccounts).Count -gt 0) {
                Show-Line "Found $(@($createComputerAccounts).Count) account(s) with explicit CreateChild rights on CN=Computers:" -Class Finding

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

                    if ($adObject) {
                        $adObject | Add-Member -NotePropertyName 'dangerousRights' -NotePropertyValue "CreateChild (Computer) on CN=Computers" -Force
                        $adObject | Add-Member -NotePropertyName 'targetContainer' -NotePropertyValue $computersContainerDN -Force
                        if ($account.Severity -in @('Expected', 'Attention')) {
                            $adObject | Add-Member -NotePropertyName 'dangerousRightsSeverity' -NotePropertyValue 'Hint' -Force
                        }
                        $adObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'AddComputerRight' -Force
                        Show-Object $adObject
                    } else {
                        # Fallback for well-known SIDs, foreign/deleted principals
                        # For well-known SIDs, resolve name via ConvertFrom-SID
                        $resolvedName = if ($isWellKnownSID) { ConvertFrom-SID -SID $account.SID } else { $account.Name }
                        $fallbackObject = [PSCustomObject]@{
                            sAMAccountName = $resolvedName
                            objectSid = $account.SID
                            dangerousRights = "CreateChild (Computer) on CN=Computers"
                            targetContainer = $computersContainerDN
                        }
                        if ($account.Severity -in @('Expected', 'Attention')) {
                            $fallbackObject | Add-Member -NotePropertyName 'dangerousRightsSeverity' -NotePropertyValue 'Hint' -Force
                        }
                        $fallbackObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'AddComputerRight' -Force
                        Show-Object $fallbackObject
                    }
                }
                $hasFindings = $true
            }

            # Finding 3: GPO grants SeMachineAccountPrivilege - as enriched native GPO objects
            # Note: Hint (not Finding) because GPO privilege alone doesn't enable computer creation without quota
            $dangerousGPOs = @($gpoFindings | Where-Object { $_._HasAuthenticatedUsers -or $_._HasEveryone })

            if (@($dangerousGPOs).Count -gt 0) {
                $effectiveGPO = @($gpoFindings | Where-Object { $_.IsEffectiveSetting -eq $true })[0]
                $effectiveIsDangerous = $effectiveGPO -and ($effectiveGPO._HasAuthenticatedUsers -or $effectiveGPO._HasEveryone)

                $lineClass = if ($effectiveIsDangerous) { "Hint" } else { "Secure" }
                Show-Line "Found $(@($gpoFindings).Count) GPO(s) configuring SeMachineAccountPrivilege:" -Class $lineClass

                # Show all GPOs that define SeMachineAccountPrivilege, sorted by precedence (highest first)
                $scopePriorityMap = @{ "DomainControllers" = 1; "Domain" = 2; "NotLinked" = 3 }
                $sortedGPOs = @($gpoFindings | Sort-Object @{Expression={$scopePriorityMap[$_._PrecedenceScope]}}, _PrecedenceOrder)

                foreach ($gpo in $sortedGPOs) {
                    $gpo | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'AddComputerGPO' -Force

                    $isEffective = $gpo.IsEffectiveSetting -eq $true
                    $isDangerous = $gpo._HasAuthenticatedUsers -or $gpo._HasEveryone
                    $objectClass = if ($isEffective) {
                        if ($effectiveIsDangerous) { "Hint" } else { "Secure" }
                    } else {
                        if ($isDangerous) { "Hint" } else { "Standard" }
                    }
                    Show-Object $gpo -Class $objectClass
                }
                $hasFindings = $true
            }

            if (-not $hasFindings) {
                Show-Line "Add Computer to Domain rights properly configured" -Class Secure
            }

        } catch {
            Write-Log "[Get-AddComputerRights] Error: $_" -Level Error
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

        $dcServer = $Script:LDAPContext.Server
        $domainDN = $Script:LDAPContext.DomainDN
        $dcOUDN = "OU=Domain Controllers,$domainDN"

        # Build GPO precedence map using Get-GPOLinkage (which reliably reads gPLink via Invoke-LDAPSearch)
        # Filter to DC OU and domain root — these are the containers that determine effective DC policy
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

            $totalGPOs = @($gpos).Count
            $currentGPOIndex = 0
            foreach ($gpo in $gpos) {
                $currentGPOIndex++
                if ($totalGPOs -gt $Script:ProgressThreshold) {
                    Show-Progress -Activity "Scanning GPO user rights assignment" -Current $currentGPOIndex -Total $totalGPOs -ObjectName $gpo.DisplayName
                }
                $gptTmplPath = Join-Path $sysvolPath "$($gpo.Name)\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

                $content = Get-CachedSYSVOLContent -Path $gptTmplPath
                if ($content) {
                    if ($content -match '(?s)\[Privilege Rights\](.*?)(\[|$)') {
                        $privilegeRightsSection = $Matches[1]

                        if ($privilegeRightsSection -match 'SeMachineAccountPrivilege\s*=\s*(.+)') {
                            $accountsLine = $Matches[1].Trim()
                            $accounts = $accountsLine -split ',' | ForEach-Object { $_.Trim().TrimStart('*') }

                            $accountNames = @()
                            $hasAuthenticatedUsers = $false
                            $hasEveryone = $false

                            foreach ($account in $accounts) {
                                if ([string]::IsNullOrWhiteSpace($account)) { continue }
                                $accountName = ConvertFrom-SID -SID $account
                                $accountNames += $accountName

                                # SID-based detection (language-independent)
                                # S-1-5-11 = Authenticated Users, S-1-1-0 = Everyone
                                if ($account -match 'S-1-5-11') { $hasAuthenticatedUsers = $true }
                                if ($account -match 'S-1-1-0')  { $hasEveryone = $true }
                            }

                            # Get linkage data for Scope/LinkedOUs (same pattern as LDAP/SMB checks)
                            $gpoLinkage = Get-GPOLinkage
                            $gpoGUIDKey = $gpo.Name.ToUpper()
                            $links = if ($gpoLinkage) { $gpoLinkage[$gpoGUIDKey] } else { $null }
                            $activeLinks = @()
                            $isDomainWide = $false

                            if ($links) {
                                $activeLinks = @($links | Where-Object { $_.LinkStatus -ne "Disabled" })
                                $isDomainWide = ($null -ne ($activeLinks | Where-Object { $_.Scope -eq "Domain" }))
                            }

                            # Determine precedence info (for effective setting calculation after scriptblock)
                            $precedenceInfo = $Script:gpoAddComputerPrecedenceMap[$gpoGUIDKey]
                            $precedenceScope = if ($precedenceInfo) { $precedenceInfo.Scope } else { "NotLinked" }
                            $precedenceOrder = if ($precedenceInfo -and $precedenceInfo.LinkOrder) { $precedenceInfo.LinkOrder } else { 999 }

                            # Enrich native GPO object (matching LDAP/SMB display pattern)
                            $gpo | Add-Member -NotePropertyName 'Accounts'              -NotePropertyValue $accountNames -Force
                            $gpo | Add-Member -NotePropertyName 'IsEffectiveSetting'    -NotePropertyValue $false -Force

                            if (@($activeLinks).Count -gt 0) {
                                $linkedOUsDisplay = @($activeLinks | ForEach-Object { $_.DistinguishedName })
                                $gpo | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $linkedOUsDisplay -Force
                                $scopeInfo = if ($isDomainWide) {
                                    "Domain-wide ($(@($activeLinks).Count) link(s))"
                                } else {
                                    "$(@($activeLinks).Count) OU(s)"
                                }
                                $gpo | Add-Member -NotePropertyName 'Scope' -NotePropertyValue $scopeInfo -Force
                            } else {
                                $gpo | Add-Member -NotePropertyName 'Scope' -NotePropertyValue "NOT LINKED" -Force
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
        $linkedResults = @($result | Where-Object { $_._PrecedenceScope -ne "NotLinked" })
        if ($linkedResults.Count -gt 0) {
            $scopePriority = @{ "DomainControllers" = 1; "Domain" = 2 }
            $effectiveGPO = $linkedResults | Sort-Object @{Expression={$scopePriority[$_._PrecedenceScope]}}, _PrecedenceOrder | Select-Object -First 1
            if ($effectiveGPO) {
                $effectiveGPO.IsEffectiveSetting = $true
                Write-Log "[Check-GPOAddComputerRights] Effective GPO: '$($effectiveGPO.displayName)' (Scope=$($effectiveGPO._PrecedenceScope), LinkOrder=$($effectiveGPO._PrecedenceOrder))"
            }
        }

        return $result
    } catch {
        Write-Log "[Check-GPOAddComputerRights] Error: $_" -Level Error
        return @()
    }
}
