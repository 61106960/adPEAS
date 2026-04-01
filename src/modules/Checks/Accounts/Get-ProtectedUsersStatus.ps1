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
    - Kerberos pre-authentication always required (no AS-REP Roasting)
    - Kerberos TGT lifetime limited to 4 hours (instead of 10)
    - No DES/RC4 encryption for Kerberos (AES only)
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

            # Get Protected Users members (SIDs for comparison)
            $protectedMemberSIDs = @{}
            if ($protectedUsersGroup.member) {
                foreach ($memberDN in @($protectedUsersGroup.member)) {
                    $memberObj = @(Get-DomainUser -Identity $memberDN -Properties 'objectSid','sAMAccountName' @PSBoundParameters)[0]
                    if ($memberObj -and $memberObj.objectSid) {
                        $protectedMemberSIDs[$memberObj.objectSid] = $memberObj.sAMAccountName
                    }
                }
            }

            Write-Log "[Get-ProtectedUsersStatus] Found $($protectedMemberSIDs.Count) members in Protected Users group"

            # ===== Step 2: Collect all Tier-0 account members =====
            # Get Tier-0 group SIDs from central definition
            $tier0GroupSIDs = Get-Tier0GroupSIDs -DomainSID $domainSID

            $tier0Accounts = @{}  # SID → Account object (deduplicated)
            $tier0AccountGroups = @{}  # SID → Array of group names (for display)

            foreach ($groupSID in $tier0GroupSIDs) {
                $groupObj = @(Get-DomainGroup -Identity $groupSID @PSBoundParameters)[0]

                if (-not $groupObj) {
                    Write-Log "[Get-ProtectedUsersStatus] Group not found: $groupSID"
                    continue
                }

                $groupName = $groupObj.sAMAccountName
                Write-Log "[Get-ProtectedUsersStatus] Processing Tier-0 group: $groupName ($groupSID)"

                # Get recursive members using LDAP_MATCHING_RULE_IN_CHAIN
                $groupDN = $groupObj.distinguishedName
                $escapedDN = $groupDN -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29'

                # Query all users who are (recursively) members of this group
                $members = @(Get-DomainUser -LDAPFilter "(memberOf:1.2.840.113556.1.4.1941:=$escapedDN)" @PSBoundParameters)

                foreach ($member in $members) {
                    if (-not $member.objectSid) { continue }

                    $memberSID = $member.objectSid

                    # Add to deduplicated list
                    if (-not $tier0Accounts.ContainsKey($memberSID)) {
                        $tier0Accounts[$memberSID] = $member
                        $tier0AccountGroups[$memberSID] = @()
                    }

                    # Track which groups this account belongs to
                    $tier0AccountGroups[$memberSID] += $groupName
                }

                # Also add direct group members (Get-DomainGroup returns member DNs)
                if ($groupObj.member) {
                    foreach ($memberDN in @($groupObj.member)) {
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
                    $account | Add-Member -NotePropertyName 'tier0Groups' -NotePropertyValue $item.Groups -Force
                    $account | Add-Member -NotePropertyName 'protectedUsersStatus' -NotePropertyValue 'NOT PROTECTED' -Force
                    $account | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'Tier0Account' -Force
                    $account | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'Unprotected' -Force
                    Show-Object $account
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
                    $account | Add-Member -NotePropertyName 'tier0Groups' -NotePropertyValue $item.Groups -Force
                    $account | Add-Member -NotePropertyName 'protectedUsersStatus' -NotePropertyValue 'Protected' -Force
                    $account | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'Tier0Account' -Force
                    $account | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'Protected' -Force
                    Show-Object $account
                }
            }

            # Show excluded accounts (informational)
            if (@($excludedAccounts.Keys).Count -gt 0) {
                Show-Line "$($excludedAccounts.Count) account(s) excluded from metric (not applicable for Protected Users):" -Class Note

                foreach ($sid in $excludedAccounts.Keys) {
                    $info = $excludedAccounts[$sid]
                    $account = $info.Account
                    $account | Add-Member -NotePropertyName 'excludedReason' -NotePropertyValue $info.Reason -Force
                    $account | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'Tier0Account' -Force
                    $account | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'Excluded' -Force
                    Show-Object $account
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
                    $memberObj = @(Get-DomainUser -Identity $memberDN -Properties 'objectSid' @PSBoundParameters)[0]
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
                    Show-Object $finding
                }
            }

        } catch {
            Write-Log "[Get-ProtectedUsersStatus] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-ProtectedUsersStatus] Check completed"
    }
}
