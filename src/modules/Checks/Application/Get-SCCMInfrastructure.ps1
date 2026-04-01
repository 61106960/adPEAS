function Get-SCCMInfrastructure {
    <#
    .SYNOPSIS
    Detects Microsoft System Center Configuration Manager (SCCM/MECM) infrastructure.

    .DESCRIPTION
    Performs passive detection of SCCM/MECM infrastructure components using LDAP queries.
    Identifies site servers, management points, site hierarchy, service accounts, PXE/WDS servers, and the System Management container.

    Detection Methods:
    1. System Management container (CN=System Management,CN=System,<Domain DN>)
    2. mSSMSSite objects (SCCM site codes and hierarchy)
    3. mSSMSManagementPoint objects (MP hostnames, site type determination)
    4. Computers with SCCM-related SPNs (SMS*, SMSSQLBKUP*)
    5. PXE/WDS boot servers (connectionPoint, intellimirrorSCP)
    6. User accounts with SCCM-related SPNs
    7. SCCM-related security groups (*SCCM*, *SMS*, *ConfigMgr*, *MECM*)

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-SCCMInfrastructure

    .EXAMPLE
    Get-SCCMInfrastructure -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Application
    Author: Alexander Sturz (@_61106960_)
    Based on research from Misconfiguration-Manager (@subat0mik)
    Reference: https://github.com/subat0mik/Misconfiguration-Manager
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
        Write-Log "[Get-SCCMInfrastructure] Starting check"
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                # Return without output to avoid redundant error display
                return
            }

            $domainDN = $Script:LDAPContext.DomainDN

            # ===== Step 1: Check for SCCM Infrastructure =====
            Show-SubHeader "Checking for SCCM/MECM infrastructure..." -ObjectType "SCCMServer"

            $sccmDetected = $false
            $systemManagementPath = "CN=System Management,CN=System,$domainDN"
            $systemMgmt = $null

            # Detection Method 1: System Management Container
            try {
                $systemMgmt = Get-DomainObject -Identity $systemManagementPath @PSBoundParameters
                if ($systemMgmt) {
                    $sccmDetected = $true
                }
            } catch {
                Write-Log "[Get-SCCMInfrastructure] System Management container not found"
            }

            # Detection Method 2: SCCM SPNs on computers (lightweight, only for detection)
            if (-not $sccmDetected) {
                $sccmDetectionComputers = Get-DomainComputer -LDAPFilter "(servicePrincipalName=SMS*)" -Properties "cn" @PSBoundParameters
                if ($sccmDetectionComputers) {
                    $sccmDetected = $true
                }
            }

            # Detection Method 3: SCCM-related groups (lightweight, only for detection)
            if (-not $sccmDetected) {
                $sccmDetectionGroups = Get-DomainGroup -LDAPFilter "(|(cn=*SCCM*)(cn=*ConfigMgr*)(cn=*MECM*))" -Properties "cn" @PSBoundParameters
                if ($sccmDetectionGroups) {
                    $sccmDetected = $true
                }
            }

            # If no SCCM detected, stop here
            if (-not $sccmDetected) {
                Show-Line "No SCCM/MECM infrastructure detected" -Class Note
                return
            }

            # ===== SCCM Detected - Continue with detailed enumeration =====
            Show-Line "SCCM/MECM infrastructure detected" -Class Hint

            # ===== Step 2: System Management Container Details =====
            Show-SubHeader "Analyzing System Management container..." -ObjectType "SCCMServer"

            # Reuse result from Detection Method 1 (no duplicate query)
            if ($systemMgmt) {
                Show-Line "System Management container found at: $systemManagementPath" -Class Hint
            } else {
                Show-Line "System Management container not found (unusual if SCCM detected)" -Class Hint
            }

            # ===== Step 3: SCCM Sites via mSSMSSite =====
            Show-SubHeader "Enumerating SCCM sites from AD schema objects..." -ObjectType "SCCMSite"

            $sccmSiteInfos = @{}  # Hashtable for cross-reference in Step 4

            try {
                $sccmSiteObjects = @(Get-DomainObject -LDAPFilter "(objectClass=mSSMSSite)" -SearchBase $systemManagementPath -Properties "mSSMSSiteCode","mSSMSSourceForest","mSSMSHealthState","cn","distinguishedName" @PSBoundParameters)

                if ($sccmSiteObjects.Count -gt 0) {
                    Show-Line "Found $($sccmSiteObjects.Count) SCCM site(s) published to Active Directory" -Class Hint

                    foreach ($site in $sccmSiteObjects) {
                        $siteCode = $site.mSSMSSiteCode
                        $sourceForest = $site.mSSMSSourceForest

                        # Extract GUID from mSSMSHealthState (format: "SITECODE.{GUID}")
                        $siteGuid = $null
                        if ($site.mSSMSHealthState -match '\{([0-9a-fA-F\-]+)\}') {
                            $siteGuid = $Matches[1]
                        }

                        # Store for cross-reference with management points
                        if ($siteCode) {
                            $sccmSiteInfos[$siteCode] = @{
                                SourceForest = $sourceForest
                                SiteGuid = $siteGuid
                                CN = $site.cn
                            }
                        }

                        # Build display object for Show-Object (dynamic fallback renders all properties)
                        $siteObj = [PSCustomObject]@{
                            Name = $siteCode
                            SiteCode = $siteCode
                            SourceForest = $sourceForest
                            SiteGUID = $siteGuid
                            DistinguishedName = $site.distinguishedName
                        }
                        $siteObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SCCMSite' -Force
                        Show-Object $siteObj
                    }
                } else {
                    Show-Line "No mSSMSSite objects found in System Management container" -Class Note
                }
            } catch {
                Write-Log "[Get-SCCMInfrastructure] Error querying mSSMSSite: $_" -Level Warning
            }

            # ===== Step 4: Management Points + Site Hierarchy =====
            Show-SubHeader "Enumerating SCCM Management Points and site hierarchy..." -ObjectType "SCCMManagementPoint"

            $casDetected = $false

            try {
                $mgmtPoints = @(Get-DomainObject -LDAPFilter "(objectClass=mSSMSManagementPoint)" -SearchBase $systemManagementPath -Properties "mSSMSMPName","mSSMSSiteCode","mSSMSCapabilities","cn","distinguishedName" @PSBoundParameters)

                if ($mgmtPoints.Count -gt 0) {
                    Show-Line "Found $($mgmtPoints.Count) SCCM Management Point(s)" -Class Hint

                    foreach ($mp in $mgmtPoints) {
                        $mpName = $mp.mSSMSMPName
                        $mpSiteCode = $mp.mSSMSSiteCode

                        # Parse mSSMSCapabilities XML for site hierarchy
                        $cmdLineSiteCode = $null
                        $rootSiteCode = $null
                        $forest = $null
                        $siteType = "Unknown"

                        if ($mp.mSSMSCapabilities) {
                            $xmlText = [string]$mp.mSSMSCapabilities
                            try {
                                # Clean entities for safe XML parsing
                                $xmlText = $xmlText -replace '&(?!amp;|lt;|gt;|quot;|apos;)', '&amp;'
                                $xmlDoc = [xml]$xmlText

                                # Extract CommandLine SMSSITECODE
                                $cmdLine = $xmlDoc.ClientOperationalSettings.CCM.CommandLine
                                if ($cmdLine -match 'SMSSITECODE=(\w+)') {
                                    $cmdLineSiteCode = $Matches[1]
                                }

                                # Extract RootSiteCode
                                $rootSiteCode = $xmlDoc.ClientOperationalSettings.RootSiteCode

                                # Extract Forest
                                $forest = $xmlDoc.ClientOperationalSettings.Forest.Value
                            } catch {
                                # XML parsing failed - try regex fallback for SMSSITECODE
                                if ($xmlText -match 'SMSSITECODE=(\w+)') {
                                    $cmdLineSiteCode = $Matches[1]
                                }
                                Write-Log "[Get-SCCMInfrastructure] XML parse warning for MP $mpName - using regex fallback" -Level Warning
                            }
                        }

                        # Determine site type (same logic as ConfigManBearPig)
                        if ($cmdLineSiteCode -and $mpSiteCode) {
                            if ($cmdLineSiteCode -eq $mpSiteCode) {
                                $siteType = "Primary Site"
                            } elseif ($rootSiteCode -eq $mpSiteCode) {
                                $siteType = "Central Administration Site (CAS)"
                                $casDetected = $true
                            } else {
                                $siteType = "Secondary Site"
                            }
                        }

                        # Build display object for Show-Object
                        $mpObj = [PSCustomObject]@{
                            Name = $mpName
                            ManagementPoint = $mpName
                            SiteCode = $mpSiteCode
                            SiteType = $siteType
                        }
                        if ($cmdLineSiteCode -and $cmdLineSiteCode -ne $mpSiteCode) {
                            $mpObj | Add-Member -NotePropertyName 'CommandLineSiteCode' -NotePropertyValue $cmdLineSiteCode -Force
                        }
                        if ($rootSiteCode) {
                            $mpObj | Add-Member -NotePropertyName 'RootSiteCode' -NotePropertyValue $rootSiteCode -Force
                        }
                        if ($forest) {
                            $mpObj | Add-Member -NotePropertyName 'Forest' -NotePropertyValue $forest -Force
                        }
                        $mpObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SCCMManagementPoint' -Force
                        Show-Object $mpObj
                    }

                    # CAS Finding
                    if ($casDetected) {
                        Show-Line "Central Administration Site (CAS) detected - multi-site SCCM hierarchy" -Class Finding -FindingId "SCCM_SITE_HIERARCHY"
                    }
                } else {
                    Show-Line "No mSSMSManagementPoint objects found in System Management container" -Class Note
                }
            } catch {
                Write-Log "[Get-SCCMInfrastructure] Error querying mSSMSManagementPoint: $_" -Level Warning
            }

            # ===== Step 5: Enumerate SCCM Servers =====
            Show-SubHeader "Searching for SCCM site servers..." -ObjectType "SCCMServer"

            $sccmServers = [System.Collections.ArrayList]::new()
            $seenServerDNs = @{}

            $servers = Get-DomainComputer -LDAPFilter "(|(servicePrincipalName=SMS*)(servicePrincipalName=SMSSQLBKUP*))" @PSBoundParameters

            if ($servers) {
                foreach ($server in @($servers)) {
                    $dn = $server.distinguishedName
                    if ($dn -and -not $seenServerDNs.ContainsKey($dn)) {
                        $seenServerDNs[$dn] = $true
                        [void]$sccmServers.Add($server)
                    }
                }
            }

            if ($sccmServers.Count -gt 0) {
                Show-Line "Found $($sccmServers.Count) SCCM server(s)" -Class Hint

                foreach ($server in $sccmServers) {
                    $server | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SCCMServer' -Force
                    Show-Object $server
                }
            } else {
                Show-Line "No SCCM servers found via SPN detection" -Class Note
            }

            # ===== Step 6: PXE/WDS Discovery =====
            Show-SubHeader "Searching for PXE/WDS boot servers..." -ObjectType "SCCMPXEServer"

            $pxeServersFound = $false

            try {
                # PXE Boot Servers via connectionPoint with netbootserver
                $pxePoints = @(Get-DomainObject -LDAPFilter "(&(objectClass=connectionPoint)(netbootserver=*))" -Properties "cn","distinguishedName","netbootserver" @PSBoundParameters)

                if ($pxePoints.Count -gt 0) {
                    $pxeServersFound = $true
                    Show-Line "Found $($pxePoints.Count) PXE boot server(s)" -Class Hint

                    foreach ($pxe in $pxePoints) {
                        $parentDN = $pxe.distinguishedName -replace '^[^,]+,', ''
                        $pxeObj = [PSCustomObject]@{
                            Name = $pxe.netbootserver
                            PXEServer = $pxe.netbootserver
                            ParentObject = $parentDN
                        }
                        $pxeObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SCCMPXEServer' -Force
                        Show-Object $pxeObj
                    }
                }
            } catch {
                Write-Log "[Get-SCCMInfrastructure] Error querying PXE connectionPoints: $_" -Level Warning
            }

            try {
                # WDS Service Connection Points
                $wdsPoints = @(Get-DomainObject -LDAPFilter "(objectClass=intellimirrorSCP)" -Properties "cn","distinguishedName","serviceBindingInformation" @PSBoundParameters)

                if ($wdsPoints.Count -gt 0) {
                    $pxeServersFound = $true
                    Show-Line "Found $($wdsPoints.Count) WDS service connection point(s)" -Class Hint

                    foreach ($wds in $wdsPoints) {
                        $parentDN = $wds.distinguishedName -replace '^[^,]+,', ''
                        $wdsObj = [PSCustomObject]@{
                            Name = $wds.cn
                            WDSServicePoint = $wds.cn
                            ParentObject = $parentDN
                        }
                        if ($wds.serviceBindingInformation) {
                            $wdsObj | Add-Member -NotePropertyName 'BindingInfo' -NotePropertyValue $wds.serviceBindingInformation -Force
                        }
                        $wdsObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SCCMPXEServer' -Force
                        Show-Object $wdsObj
                    }
                }
            } catch {
                Write-Log "[Get-SCCMInfrastructure] Error querying intellimirrorSCP: $_" -Level Warning
            }

            if ($pxeServersFound) {
                Show-Line "PXE/WDS servers detected" -Class Hint -FindingId "SCCM_PXE_EXPOSURE"
            } else {
                Show-Line "No PXE/WDS boot servers found" -Class Note
            }

            # ===== Step 7: SCCM Service Accounts =====
            Show-SubHeader "Searching for SCCM service accounts..." -ObjectType "SCCMServiceAccount"

            $serviceAccounts = Get-DomainUser -LDAPFilter "(servicePrincipalName=SMS*)" @PSBoundParameters

            if ($serviceAccounts) {
                Show-Line "Found $(@($serviceAccounts).Count) SCCM service account(s) with SMS* SPN" -Class Hint -FindingId "SCCM_SERVICE_ACCOUNT"

                foreach ($account in $serviceAccounts) {
                    $account | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SCCMServiceAccount' -Force
                    Show-Object $account
                }
            } else {
                Show-Line "No SCCM service accounts found" -Class Secure
            }

            # ===== Step 8: SCCM-Related Groups =====
            Show-SubHeader "Searching for SCCM-related security groups..." -ObjectType "SCCMGroup"

            # Single LDAP query with OR filter (SMS_SiteToSiteConnection_ is SCCM-specific, avoids generic *SMS* false positives)
            $sccmGroupsFound = [System.Collections.ArrayList]::new()
            $seenGroupDNs = @{}

            $groups = Get-DomainGroup -LDAPFilter "(|(cn=*SCCM*)(cn=SMS_SiteToSiteConnection_*)(cn=SMS_SiteSystemToSiteServerConnection_*)(cn=*ConfigMgr*)(cn=*MECM*))" @PSBoundParameters

            if ($groups) {
                foreach ($group in @($groups)) {
                    $dn = $group.distinguishedName
                    if ($dn -and -not $seenGroupDNs.ContainsKey($dn)) {
                        $seenGroupDNs[$dn] = $true
                        [void]$sccmGroupsFound.Add($group)
                    }
                }
            }

            if ($sccmGroupsFound.Count -gt 0) {
                Show-Line "Found $($sccmGroupsFound.Count) SCCM-related group(s)" -Class Hint

                foreach ($group in $sccmGroupsFound) {
                    # Add member count without resolving individual members (avoids O(n) LDAP queries)
                    $memberCount = 0
                    if ($group.member) {
                        $memberCount = @($group.member).Count
                    }
                    $group | Add-Member -NotePropertyName 'MemberCount' -NotePropertyValue "$memberCount member(s)" -Force
                    # Remove member attribute to prevent Extended-attribute rendering from triggering
                    # per-DN SID resolution (Convert-DNsToMemberInfo → ConvertTo-SID per member)
                    $group.PSObject.Properties.Remove('member')
                    $group | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SCCMGroup' -Force
                    Show-Object $group
                }
            } else {
                Show-Line "No SCCM-related groups found" -Class Note
            }

        } catch {
            Write-Log "[Get-SCCMInfrastructure] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-SCCMInfrastructure] Check completed"
    }
}
