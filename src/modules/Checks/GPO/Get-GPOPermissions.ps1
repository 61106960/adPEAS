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
        $Script:DangerousGPOAccessRights = @(
            'GenericAll',
            'GenericWrite',
            'WriteProperty',
            'WriteDacl',
            'WriteOwner'
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

            if (-not $allGPOs -or @($allGPOs).Count -eq 0) {
                Show-Line "No GPOs found in domain" -Class Note
                return
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
                    # Get-ObjectACL returns a wrapper object with .ACEs property containing actual ACE array
                    $aclResult = Get-ObjectACL -DistinguishedName $gpoDN -DangerousOnly -AllowOnly -ExplicitOnly @connectionParams

                    if (-not $aclResult -or -not $aclResult.ACEs -or @($aclResult.ACEs).Count -eq 0) {
                        Write-Log "[Get-GPOPermissions] No dangerous ACEs found for GPO: $gpoDisplayName"
                        continue
                    }

                    $dangerousAces = @($aclResult.ACEs)
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

                        # Determine which dangerous right matched (using RightsRaw array)
                        $dangerousRightMatched = ""
                        foreach ($dangerousRight in $Script:DangerousGPOAccessRights) {
                            if ($aceRightsRaw -contains $dangerousRight) {
                                $dangerousRightMatched = $dangerousRight
                                break
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

                        Write-Log "[Get-GPOPermissions] FINDING: $identityName has $aceRights on GPO $gpoDisplayName"

                        $vulnerableIdentities += [PSCustomObject]@{
                            Identity = $identityName
                            SID = $aceSID
                            Rights = $aceRights
                            DangerousRight = $dangerousRightMatched
                            Severity = $severity
                        }
                    }

                    # If we found vulnerable identities for this GPO, add to results
                    if (@($vulnerableIdentities).Count -gt 0) {
                        # Get GPO Linkage for this GPO
                        $links = $gpoLinkage[$gpoGUID]
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

                        # Build scope info and linked OUs list
                        $scopeInfo = if ($isDomainWide) {
                            "Domain-wide"
                        } elseif ($linkCount -gt 0) {
                            "Linked to $linkCount OU(s)"
                        } else {
                            "NOT LINKED"
                        }

                        # Build LinkedOUs list (show where GPO is linked) - use full DN
                        $linkedOUsDisplay = $null
                        if (@($activeLinks).Count -gt 0) {
                            $linkedOUsDisplay = ($activeLinks | ForEach-Object {
                                $_.DistinguishedName
                            }) -join "`n"
                        }

                        # Format vulnerable identities for display
                        $identityDisplay = ($vulnerableIdentities | ForEach-Object {
                            "$($_.Identity) ($($_.DangerousRight))"
                        }) -join "`n"

                        $enrichedGPO = $gpo.PSObject.Copy()
                        $enrichedGPO | Add-Member -NotePropertyName "DangerousPermissions" -NotePropertyValue $identityDisplay -Force
                        $enrichedGPO | Add-Member -NotePropertyName "Scope" -NotePropertyValue $scopeInfo -Force
                        if ($linkedOUsDisplay) {
                            $enrichedGPO | Add-Member -NotePropertyName "LinkedOUs" -NotePropertyValue $linkedOUsDisplay -Force
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

            $vulnerableGPOs = @($vulnerableGPOsHash.Values)

            if (@($vulnerableGPOs).Count -gt 0) {
                Show-Line "Found $(@($vulnerableGPOs).Count) GPO(s) with dangerous permissions" -Class Finding

                foreach ($gpo in $vulnerableGPOs) {
                    $gpo | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPOPermission' -Force
                    Show-Object $gpo
                }
            }
            else {
                Show-Line "No dangerous GPO permissions found in $(@($allGPOs).Count) analyzed GPO(s)" -Class Secure
            }

        } catch {
            Write-Log "[Get-GPOPermissions] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-GPOPermissions] Check completed"
    }
}
