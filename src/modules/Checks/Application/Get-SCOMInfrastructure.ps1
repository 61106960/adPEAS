function Get-SCOMInfrastructure {
    <#
    .SYNOPSIS
    Detects Microsoft System Center Operations Manager (SCOM) infrastructure.

    .DESCRIPTION
    Performs passive detection of SCOM infrastructure components using LDAP queries.
    Identifies management servers, service accounts, and SCOM-related security groups.

    Detection Methods:
    1. Computers with SCOM-related SPNs (MSOMSdkSvc/*, MSOMHSvc/*)
    2. User accounts with SCOM-related SPNs
    3. SCOM-related security groups (*SCOM*, *OpsMgr*, *Operations Manager*)

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-SCOMInfrastructure

    .EXAMPLE
    Get-SCOMInfrastructure -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Application
    Author: Alexander Sturz (@_61106960_)
    Based on research from SharpSCOM (@breakfix)
    Reference: https://github.com/breakfix/SharpSCOM
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
        Write-Log "[Get-SCOMInfrastructure] Starting check"
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                # Return without output to avoid redundant error display
                return
            }

            # ===== Step 1: Check for SCOM Infrastructure =====
            Show-SubHeader "Checking for SCOM infrastructure..." -ObjectType "SCOMServer"

            $scomDetected = $false

            # Detection Method 1: SCOM SPNs on computers (SDK Service, Health Service)
            $scomSPNPatterns = @("MSOMSdkSvc*", "MSOMHSvc*")
            foreach ($spnPattern in $scomSPNPatterns) {
                $scomComputers = Get-DomainComputer -LDAPFilter "(servicePrincipalName=$spnPattern)" @PSBoundParameters
                if ($scomComputers) {
                    $scomDetected = $true
                    break
                }
            }

            # Detection Method 2: SCOM-related groups (with word boundary filtering)
            if (-not $scomDetected) {
                $allGroups = Get-DomainGroup -LDAPFilter "(|(cn=*SCOM*)(cn=*OpsMgr*)(cn=*Operations Manager*))" @PSBoundParameters
                if ($allGroups) {
                    # Apply word boundary regex to avoid false positives (e.g., "TeamsCommunicationsCom")
                    $filteredGroups = @($allGroups | Where-Object {
                        $_.cn -match '\bSCOM\b' -or
                        $_.cn -match '\bOpsMgr\b' -or
                        $_.cn -match 'Operations\s+Manager'
                    })
                    if ($filteredGroups.Count -gt 0) {
                        $scomDetected = $true
                    }
                }
            }

            # If no SCOM detected, stop here
            if (-not $scomDetected) {
                Show-Line "No SCOM infrastructure detected" -Class Note
                return
            }

            # ===== SCOM Detected - Continue with detailed enumeration =====
            Show-Line "SCOM infrastructure detected" -Class Hint

            # ===== Step 2: Enumerate SCOM Management Servers =====
            Show-SubHeader "Searching for SCOM management servers..." -ObjectType "SCOMServer"

            $scomServers = @()

            foreach ($spnPattern in $scomSPNPatterns) {
                $servers = Get-DomainComputer -LDAPFilter "(servicePrincipalName=$spnPattern)" @PSBoundParameters

                if ($servers) {
                    foreach ($server in $servers) {
                        # Avoid duplicates
                        if ($server.dNSHostName -notin $scomServers.dNSHostName) {
                            $scomServers += $server
                        }
                    }
                }
            }

            if (@($scomServers).Count -gt 0) {
                Show-Line "Found $(@($scomServers).Count) SCOM management server(s)" -Class Hint

                foreach ($server in $scomServers) {
                    $server | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SCOMServer' -Force
                    Show-Object $server
                }
            } else {
                Show-Line "No SCOM management servers found via SPN detection" -Class Note
            }

            # ===== Step 3: SCOM Service Accounts =====
            Show-SubHeader "Searching for SCOM service accounts..." -ObjectType "SCOMServer"

            $serviceAccounts = @()

            foreach ($spnPattern in $scomSPNPatterns) {
                $accounts = Get-DomainUser -LDAPFilter "(servicePrincipalName=$spnPattern)" @PSBoundParameters

                if ($accounts) {
                    foreach ($account in $accounts) {
                        if ($account.sAMAccountName -notin $serviceAccounts.sAMAccountName) {
                            $serviceAccounts += $account
                        }
                    }
                }
            }

            if (@($serviceAccounts).Count -gt 0) {
                Show-Line "Found $(@($serviceAccounts).Count) SCOM service account(s)" -Class Hint

                foreach ($account in $serviceAccounts) {
                    $account | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SCOMServiceAccount' -Force
                    Show-Object $account
                }
            } else {
                Show-Line "No SCOM service accounts found" -Class Note
            }

            # ===== Step 4: SCOM-Related Security Groups =====
            Show-SubHeader "Searching for SCOM-related security groups..." -ObjectType "SCOMServer"

            # Broad LDAP query to get potential SCOM groups
            $allGroups = Get-DomainGroup -LDAPFilter "(|(cn=*SCOM*)(cn=*OpsMgr*)(cn=*Operations Manager*))" @PSBoundParameters

            # Client-side filtering with word boundary regex to eliminate false positives
            # (e.g., "TeamsCommunicationsCom" should NOT match)
            $scomGroupsFound = @()
            if ($allGroups) {
                $scomGroupsFound = @($allGroups | Where-Object {
                    $_.cn -match '\bSCOM\b' -or
                    $_.cn -match '\bOpsMgr\b' -or
                    $_.cn -match 'Operations\s+Manager'
                })
            }

            if (@($scomGroupsFound).Count -gt 0) {
                Show-Line "Found $(@($scomGroupsFound).Count) SCOM-related group(s)" -Class Hint

                foreach ($group in $scomGroupsFound) {
                    # Add member count without resolving individual members (avoids O(n) LDAP queries)
                    $memberCount = 0
                    if ($group.member) {
                        $memberCount = @($group.member).Count
                    }
                    $group | Add-Member -NotePropertyName 'MemberCount' -NotePropertyValue "$memberCount member(s)" -Force
                    # Remove member attribute to prevent Extended-attribute rendering from triggering
                    # per-DN SID resolution (Convert-DNsToMemberInfo → ConvertTo-SID per member)
                    $group.PSObject.Properties.Remove('member')
                    $group | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SCOMGroup' -Force
                    Show-Object $group
                }
            } else {
                Show-Line "No SCOM-related groups found" -Class Note
            }

        } catch {
            Write-Log "[Get-SCOMInfrastructure] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-SCOMInfrastructure] Check completed"
    }
}
