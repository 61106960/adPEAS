<#
.SYNOPSIS
    Collects comprehensive Active Directory domain information.

.DESCRIPTION
    Collects:
    - Domain Name (DNS + NetBIOS), SID, Functional Level
    - Forest Information
    - Parent/Child Domain Detection
    - Domain Controllers (detailed information)
    - Kerberos Policy
    - krbtgt Account Security Check
    - Guest Account Status (enabled/disabled, password age, group memberships)
    - Active Directory Sites and Subnets

.PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

.PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

.PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

.EXAMPLE
    Get-DomainInformation
    Returns comprehensive domain information for the current domain.

.EXAMPLE
    Get-DomainInformation -Domain "contoso.com" -Credential (Get-Credential)
    Returns domain information for contoso.com using specified credentials.

.NOTES
    Category: Domain
    Author: Alexander Sturz (@_61106960_)
#>

function Get-DomainInformation {
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
        Write-Log "[Get-DomainInformation] Starting domain enumeration"

        # Domain Functional Level Mapping
        $DomainModeLevel = @{
            0 = "Windows 2000 native"
            1 = "Windows 2003 interim"
            2 = "Windows 2003"
            3 = "Windows 2008"
            4 = "Windows 2008 R2"
            5 = "Windows 2012"
            6 = "Windows 2012 R2"
            7 = "Windows 2016"
            10 = "Windows 2025"
        }
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            $NetBIOSName = $null
            $KerberosPolicy = $null
            $PdcFSMO = $null

            # Use cached RootDSE data from LDAPContext (already available after Ensure-LDAPConnection)
            $DomainDN = $Script:LDAPContext.DomainDN
            $ForestDN = $Script:LDAPContext.RootDomainNamingContext
            $ConfigDN = $Script:LDAPContext.ConfigurationNamingContext
            $DomainFunc = $Script:LDAPContext.DomainFunctionality
            $ForestFunc = $Script:LDAPContext.ForestFunctionality
            $DomainName = $Script:LDAPContext.Domain
            $DomainSID = $Script:LDAPContext.DomainSID
            $ForestRootName = $ForestDN -replace "DC=", "" -replace ",", "."

            # Query domain object for additional attributes not in RootDSE
            try {
                $DomainObject = @(Get-DomainObject -LDAPFilter "(objectClass=domain)" -Scope Base @PSBoundParameters)[0]

                if ($DomainObject) {
                    if ($DomainObject.name) {
                        $NetBIOSName = $DomainObject.name
                        Write-Log "[Get-DomainInformation] NetBIOS name found: $NetBIOSName"
                    }

                    # Kerberos Policy
                    $MaxTicketAge = $null
                    $MaxRenewAge = $null

                    if ($DomainObject.maxTicketAge) {
                        $TicketAgeTicks = [Math]::Abs([Int64]$DomainObject.maxTicketAge)
                        $MaxTicketAge = [TimeSpan]::FromTicks($TicketAgeTicks)
                    }

                    if ($DomainObject.maxRenewAge) {
                        $RenewAgeTicks = [Math]::Abs([Int64]$DomainObject.maxRenewAge)
                        $MaxRenewAge = [TimeSpan]::FromTicks($RenewAgeTicks)
                    }

                    $KerberosPolicy = @{
                        MaxTicketAge = $MaxTicketAge
                        MaxRenewAge = $MaxRenewAge
                    }

                    $PdcFSMO = $DomainObject.fSMORoleOwner
                }
            } catch {
                Write-Log "[Get-DomainInformation] Error retrieving domain object: $_"
            }

            # Parent/Child Domain Detection
            $ParentDomain = $null
            $ChildDomains = @()

            try {
                Write-Log "[Get-DomainInformation] Checking for parent/child domains"

                # Check if current domain is NOT the forest root (= has parent)
                if ($DomainDN -ne $ForestDN) {
                    $ParentDomain = $ForestRootName
                }

                # Query all domains in forest for child domains
                $PartitionsSearchBase = "CN=Partitions,$ConfigDN"
                $AllDomainsFilter = "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))"
                $AllDomains = Get-DomainObject -LDAPFilter $AllDomainsFilter -SearchBase $PartitionsSearchBase @PSBoundParameters

                if ($AllDomains) {
                    # Ensure $AllDomains is always an array
                    $AllDomainsArray = @($AllDomains)
                    foreach ($CrossRefEntry in $AllDomainsArray) {
                        $DomainNCName = $CrossRefEntry.nCName
                        $DomainDnsRoot = $CrossRefEntry.dnsRoot

                        # Check if this domain is a child of current domain
                        if ($DomainNCName -ne $DomainDN -and $DomainNCName -like "*,$DomainDN") {
                            $ChildDomains += $DomainDnsRoot
                        }
                    }
                }
            } catch {
                Write-Log "[Get-DomainInformation] Error retrieving parent/child domains: $_"
            }

            $DomainControllers = @()

            try {
                Write-Log "[Get-DomainInformation] Querying Domain Controllers with full details"
                $DCs = Get-DomainComputer -LDAPFilter "(primaryGroupID=516)" @PSBoundParameters

                if ($DCs) {
                    # Filter to current domain only (referral-chasing defense-in-depth)
                    $DomainControllers = @($DCs) | Where-Object {
                        -not $DomainDN -or $_.distinguishedName -like "*,$DomainDN"
                    }
                    $DomainControllers = @($DomainControllers)
                }
            } catch {
                Write-Log "[Get-DomainInformation] Error retrieving domain controllers: $_"
            }

            # krbtgt Account Age Check
            $KrbtgtInfo = $null
            $KrbtgtPasswordAge = $null
            $KrbtgtSeverity = "Info"

            try {
                Write-Log "[Get-DomainInformation] Checking krbtgt account password age"
                $KrbtgtAccount = @(Get-DomainObject -LDAPFilter "(sAMAccountName=krbtgt)" @PSBoundParameters)[0]

                if ($KrbtgtAccount -and $KrbtgtAccount.pwdLastSet) {
                    # pwdLastSet is already converted to DateTime by Get-DomainObject
                    $PwdLastSet = $KrbtgtAccount.pwdLastSet

                    $PasswordAge = (Get-Date) - $PwdLastSet
                    $KrbtgtPasswordAge = $PasswordAge.Days

                    # Determine severity
                    if ($KrbtgtPasswordAge -gt 730) {
                        # > 2 years
                        $KrbtgtSeverity = "Critical"
                    } elseif ($KrbtgtPasswordAge -gt 365) {
                        # > 1 year
                        $KrbtgtSeverity = "High"
                    } elseif ($KrbtgtPasswordAge -gt 180) {
                        # > 180 days
                        $KrbtgtSeverity = "Medium"
                    } else {
                        $KrbtgtSeverity = "Info"
                    }

                    $KrbtgtInfo = @{
                        PasswordLastSet = $PwdLastSet
                        PasswordAgeDays = $KrbtgtPasswordAge
                        Severity = $KrbtgtSeverity
                    }
                }
            } catch {
                Write-Log "[Get-DomainInformation] Error retrieving krbtgt account: $_"
            }

            # Guest Account Status Check
            $GuestInfo = $null
            $GuestEnabled = $false

            try {
                Write-Log "[Get-DomainInformation] Checking Guest account status"

                # Guest account has fixed RID 501 in domain
                $GuestSID = "$DomainSID-501"
                Write-Log "[Get-DomainInformation] Guest SID: $GuestSID"
                $GuestAccount = @(Get-DomainUser -Identity $GuestSID @PSBoundParameters)[0]
                Write-Log "[Get-DomainInformation] Found Guest accounts: $(@(Get-DomainUser -Identity $GuestSID @PSBoundParameters).Count)"

                if ($GuestAccount) {
                    # Check if account is enabled (userAccountControl already parsed by Get-DomainUser)
                    $uacFlags = $GuestAccount.userAccountControl
                    if ($uacFlags) {
                        # Check if ACCOUNTDISABLE flag is present in array
                        $GuestEnabled = -not ($uacFlags -contains 'ACCOUNTDISABLE')
                    }

                    # Get group memberships (only direct memberships)
                    $GuestGroups = @()
                    if ($GuestAccount.memberOf) {
                        $GuestGroups = @($GuestAccount.memberOf)
                    }

                    # Check if Guest is in privileged groups
                    $GuestSID = @($GuestAccount.objectSid)[0]
                    $IsPrivileged = (Test-IsPrivileged -Identity $GuestSID).IsPrivileged
                    Write-Log "[Get-DomainInformation] Guest IsPrivileged: $IsPrivileged"

                    $GuestInfo = @{
                        Enabled = $GuestEnabled
                        MemberOf = $GuestGroups
                        IsPrivileged = $IsPrivileged
                    }
                }
            } catch {
                Write-Log "[Get-DomainInformation] Error retrieving Guest account: $_"
            }

            # Sites and Subnets - Query via LDAP from Configuration Partition
            # Sites are forest-wide (stored in CN=Sites,CN=Configuration,DC=<forest-root>)
            # Works correctly for sub-domains because ConfigurationNamingContext always points to forest root
            $Sites = @()
            $Subnets = @()

            try {
                $configNC = $Script:LDAPContext.ConfigurationNamingContext
                if ($configNC) {
                    $sitesContainer = "CN=Sites,$configNC"
                    Write-Log "[Get-DomainInformation] Querying Sites and Subnets via LDAP from $sitesContainer"

                    # Query all site objects
                    $siteObjects = Get-DomainObject -LDAPFilter "(objectClass=site)" -SearchBase $sitesContainer -Properties 'name','distinguishedName' @PSBoundParameters
                    foreach ($siteObj in @($siteObjects)) {
                        if ($siteObj.name) {
                            $Sites += [PSCustomObject]@{
                                Name = $siteObj.name
                                DomainControllers = @()
                            }
                        }
                    }

                    # Query all subnet objects
                    $subnetContainer = "CN=Subnets,$sitesContainer"
                    $subnetObjects = Get-DomainObject -LDAPFilter "(objectClass=subnet)" -SearchBase $subnetContainer -Properties 'name','siteObject' @PSBoundParameters
                    foreach ($subnetObj in @($subnetObjects)) {
                        if ($subnetObj.name) {
                            # Extract site name from siteObject DN: CN=<SiteName>,CN=Sites,...
                            $subnetSiteName = $null
                            if ($subnetObj.siteObject -match '^CN=([^,]+),CN=Sites') {
                                $subnetSiteName = $Matches[1]
                            }
                            $Subnets += [PSCustomObject]@{
                                Name = $subnetObj.name
                                Site = $subnetSiteName
                            }
                        }
                    }

                    Write-Log "[Get-DomainInformation] Found $($Sites.Count) sites and $($Subnets.Count) subnets"

                    # Resolve DC-to-Site mapping
                    # Server objects: CN=<DC>,CN=Servers,CN=<SiteName>,CN=Sites,CN=Configuration,...
                    $serverObjects = Get-DomainObject -LDAPFilter "(objectClass=server)" -SearchBase $sitesContainer -Properties 'dNSHostName','distinguishedName' @PSBoundParameters

                    foreach ($serverObj in @($serverObjects)) {
                        $serverDN = $serverObj.distinguishedName
                        $serverDNS = $serverObj.dNSHostName
                        if (-not $serverDN -or -not $serverDNS) { continue }

                        # Extract site name from DN: CN=<DC>,CN=Servers,CN=<SiteName>,CN=Sites,...
                        if ($serverDN -match 'CN=Servers,CN=([^,]+),CN=Sites') {
                            $siteName = $Matches[1]
                            $siteEntry = $Sites | Where-Object { $_.Name -eq $siteName }
                            if ($siteEntry) {
                                $siteEntry.DomainControllers += $serverDNS
                            }
                        }
                    }
                    Write-Log "[Get-DomainInformation] DC-to-Site mapping completed"
                } else {
                    Write-Log "[Get-DomainInformation] No ConfigurationNamingContext available - skipping Sites/Subnets"
                }
            } catch {
                Write-Log "[Get-DomainInformation] Error retrieving Sites/Subnets: $_"
            }

            # ===================================================================
            # SubCheck 1: Domain Information
            # Severity: Finding (Anonymous LDAP), Hint (old FL), Note (default)
            # ===================================================================
            Show-SubHeader "Collecting domain information..." -ObjectType "DomainBasicInfo"

            # Build functional level texts
            $DomainFuncLevelText = $DomainModeLevel[[int]$DomainFunc]
            if (-not $DomainFuncLevelText) {
                $DomainFuncLevelText = "Unknown (Level $DomainFunc)"
            }

            $ForestFuncLevelText = $DomainModeLevel[[int]$ForestFunc]
            if (-not $ForestFuncLevelText) {
                $ForestFuncLevelText = "Unknown (Level $ForestFunc)"
            }

            # NetBIOS Name
            $NetBIOSDisplay = if ($NetBIOSName) { $NetBIOSName } else { "(not found)" }

            # Create domain info object (Domain Controllers shown separately with FSMO roles)
            $domainInfoObj = [PSCustomObject]@{
                domainNameDNS = $DomainName
                domainNameNetBIOS = $NetBIOSDisplay
                domainSID = $DomainSID
                domainFunctionalLevel = $DomainFuncLevelText
                forestFunctionalLevel = $ForestFuncLevelText
                forestName = $ForestRootName
            }

            # Add optional properties
            if ($ParentDomain) {
                $domainInfoObj | Add-Member -NotePropertyName 'parentDomain' -NotePropertyValue $ParentDomain -Force
            }
            if (@($ChildDomains).Count -gt 0) {
                $domainInfoObj | Add-Member -NotePropertyName 'childDomains' -NotePropertyValue ($ChildDomains -join ', ') -Force
            }

            # Determine severity for Domain Information
            # Finding: Anonymous LDAP Access enabled
            # Hint: Functional Level < 2016 (level 7)
            # Note: Everything OK
            $domainInfoSeverity = "Note"

            # Anonymous LDAP Access Warning - Critical finding
            if ($Script:LDAPContext['AnonymousAccessEnabled']) {
                $domainInfoObj | Add-Member -NotePropertyName 'anonymousLDAPAccess' -NotePropertyValue "ENABLED - Security Risk!" -Force
                $anonDetails = $Script:LDAPContext['AnonymousAccessDetails']
                if ($anonDetails -and $anonDetails.ReadableAttributes -and $anonDetails.ReadableAttributes.Count -gt 0) {
                    $domainInfoObj | Add-Member -NotePropertyName 'anonymousReadableAttributes' -NotePropertyValue ($anonDetails.ReadableAttributes -join ', ') -Force
                }
                $domainInfoSeverity = "Finding"
            }
            # Check for old functional level (< 2016 = level 7)
            elseif ([int]$DomainFunc -lt 7) {
                $domainInfoSeverity = "Hint"
            }

            # Output domain info object
            Show-Line "Found domain information:" -Class $domainInfoSeverity
            $domainInfoObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'DomainBasicInfo' -Force
            Show-Object $domainInfoObj

            # ===================================================================
            # SubCheck 2: Kerberos Policy
            # Severity: Finding (krbtgt > 365d), Hint (krbtgt > 180d), Note (default)
            # ===================================================================
            Show-SubHeader "Analyzing Kerberos policy..." -ObjectType "KerberosPolicy"

            # Build Kerberos policy values
            $maxTicketAgeText = "10 hours (default)"
            $maxRenewalAgeText = "7 days (default)"

            if ($KerberosPolicy -and $KerberosPolicy.MaxTicketAge) {
                $TicketAgeHours = [Math]::Round($KerberosPolicy.MaxTicketAge.TotalHours, 1)
                $maxTicketAgeText = "$TicketAgeHours hours"
                if ($TicketAgeHours -eq 10) {
                    $maxTicketAgeText += " (default)"
                }
            }
            if ($KerberosPolicy -and $KerberosPolicy.MaxRenewAge) {
                $RenewAgeDays = [Math]::Round($KerberosPolicy.MaxRenewAge.TotalDays, 1)
                $maxRenewalAgeText = "$RenewAgeDays days"
                if ($RenewAgeDays -eq 7) {
                    $maxRenewalAgeText += " (default)"
                }
            }

            # Query DC current time from RootDSE (direct LdapConnection query, not via Invoke-LDAPSearch
            # because Invoke-LDAPSearch overrides empty SearchBase with DomainDN)
            $dcTimeText = $null
            try {
                $rootDSEReq = New-Object System.DirectoryServices.Protocols.SearchRequest
                $rootDSEReq.DistinguishedName = ""
                $rootDSEReq.Filter = "(objectClass=*)"
                $rootDSEReq.Scope = [System.DirectoryServices.Protocols.SearchScope]::Base
                [void]$rootDSEReq.Attributes.Add("currentTime")
                $rootDSEResp = $Script:LdapConnection.SendRequest($rootDSEReq)
                if ($rootDSEResp -and $rootDSEResp.Entries.Count -gt 0 -and $rootDSEResp.Entries[0].Attributes.Contains("currenttime")) {
                    $dcTimeStr = $rootDSEResp.Entries[0].Attributes["currenttime"].GetValues([string])[0]
                    # currentTime format: yyyyMMddHHmmss.0Z (Generalized Time)
                    $dcTimeUTC = [DateTime]::ParseExact($dcTimeStr.Substring(0, 14), "yyyyMMddHHmmss", $null)
                    $localTimeUTC = [DateTime]::UtcNow
                    $clockSkew = $dcTimeUTC - $localTimeUTC
                    $skewSeconds = [Math]::Round($clockSkew.TotalSeconds)
                    $skewAbs = [Math]::Abs($skewSeconds)
                    $skewSign = if ($skewSeconds -ge 0) { "+" } else { "-" }
                    if ($skewAbs -ge 3600) {
                        $skewDisplay = "${skewSign}$([Math]::Floor($skewAbs / 3600))h $([Math]::Floor(($skewAbs % 3600) / 60))m"
                    } elseif ($skewAbs -ge 60) {
                        $skewDisplay = "${skewSign}$([Math]::Floor($skewAbs / 60))m $($skewAbs % 60)s"
                    } else {
                        $skewDisplay = "${skewSign}${skewAbs}s"
                    }
                    $dcTimeText = "$($dcTimeUTC.ToString('yyyy-MM-dd HH:mm:ss')) UTC (skew: $skewDisplay)"
                }
            }
            catch {
                Write-Log "[Get-DomainInformation] Failed to query DC currentTime: $_"
            }

            $kerberosObj = [PSCustomObject]@{
                maxTicketAgeTGT = $maxTicketAgeText
                maxRenewalAge = $maxRenewalAgeText
            }

            # Add DC time if available
            if ($dcTimeText) {
                $kerberosObj | Add-Member -NotePropertyName 'domainControllerTime' -NotePropertyValue $dcTimeText -Force
            }

            # Determine severity for Kerberos Policy based on krbtgt age
            # Finding: krbtgt > 365 days (1 year)
            # Hint: krbtgt > 180 days
            # Note: krbtgt <= 180 days or not available
            $kerberosSeverity = "Note"

            if ($KrbtgtInfo) {
                $LastChanged = $KrbtgtInfo.PasswordLastSet.ToString('yyyy-MM-dd')
                $AgeText = "$KrbtgtPasswordAge days (last changed: $LastChanged)"
                $kerberosObj | Add-Member -NotePropertyName 'krbtgtPasswordAge' -NotePropertyValue $AgeText -Force

                # Set severity based on krbtgt age
                if ($KrbtgtPasswordAge -gt 365) {
                    $kerberosSeverity = "Finding"
                } elseif ($KrbtgtPasswordAge -gt 180) {
                    $kerberosSeverity = "Hint"
                }
            }

            # Output Kerberos policy object
            Show-Line "Found Kerberos policy:" -Class $kerberosSeverity
            $kerberosObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'KerberosPolicy' -Force
            Show-Object $kerberosObj

            # ===================================================================
            # SubCheck 3: Guest Account Status
            # Severity: Finding (enabled + privileged), Hint (enabled), Secure (disabled)
            # ===================================================================
            Show-SubHeader "Checking Guest Account Status..." -ObjectType "GuestAccount"

            if ($GuestInfo) {
                $statusText = if ($GuestInfo.Enabled) { "ENABLED" } else { "Disabled" }

                # Determine severity
                if ($GuestInfo.Enabled) {
                    if ($GuestInfo.IsPrivileged) {
                        $guestClass = "Finding"  # Enabled + privileged = critical
                        Write-Log "[Get-DomainInformation] Guest severity: Finding (enabled + privileged)"
                    } else {
                        $guestClass = "Hint"     # Enabled but not privileged
                        Write-Log "[Get-DomainInformation] Guest severity: Hint (enabled but not privileged)"
                    }
                } else {
                    $guestClass = "Secure"       # Disabled = secure
                    Write-Log "[Get-DomainInformation] Guest severity: Secure (disabled)"
                }

                # Build guest account object for display
                $guestObj = [PSCustomObject]@{
                    accountStatus = $statusText
                }

                # Add group memberships as array (not concatenated string) for proper transformer processing
                if (@($GuestInfo.MemberOf).Count -gt 0) {
                    $guestObj | Add-Member -NotePropertyName 'memberOf' -NotePropertyValue $GuestInfo.MemberOf -Force
                }

                Show-Line "Found $($statusText.ToLower()) Guest account" -Class $guestClass
                $guestObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GuestAccount' -Force
                Show-Object $guestObj

            } else {
                Show-Line "Guest account not found (unusual - RID 501 should always exist)" -Class Hint
            }

            # ===================================================================
            # SubCheck 4: Domain Controllers
            # Severity: Note (informational only, OS/LDAPS checked elsewhere)
            # ===================================================================
            Show-SubHeader "Searching for Domain Controllers..." -ObjectType "DomainController"

            # Query FSMO Roles first to associate with DCs
            $FSMORoles = @{}
            $FSMOByDC = @{}  # Map DC DN to list of FSMO roles
            try {
                Write-Log "[Get-DomainInformation] Querying FSMO role holders"

                # PDC Emulator (from domain object)
                if ($PdcFSMO) {
                    $FSMORoles['PDC Emulator'] = $PdcFSMO
                    Write-Log "[Get-DomainInformation] PDC Emulator: $PdcFSMO"
                }

                # Schema Master (forest-wide)
                $SchemaRole = @(Get-DomainObject -LDAPFilter "(objectClass=*)" -SearchBase "CN=Schema,$ConfigDN" -Scope Base @PSBoundParameters)[0]
                if ($SchemaRole -and $SchemaRole.fSMORoleOwner) {
                    $FSMORoles['Schema Master'] = $SchemaRole.fSMORoleOwner
                }

                # Infrastructure Master (domain-wide)
                $InfraRole = @(Get-DomainObject -LDAPFilter "(objectClass=*)" -SearchBase "CN=Infrastructure,$DomainDN" -Scope Base @PSBoundParameters)[0]
                if ($InfraRole -and $InfraRole.fSMORoleOwner) {
                    $FSMORoles['Infrastructure Master'] = $InfraRole.fSMORoleOwner
                }

                # RID Master (domain-wide)
                $RidRole = @(Get-DomainObject -LDAPFilter "(objectClass=*)" -SearchBase "CN=RID Manager`$,CN=System,$DomainDN" -Scope Base @PSBoundParameters)[0]
                if ($RidRole -and $RidRole.fSMORoleOwner) {
                    $FSMORoles['RID Master'] = $RidRole.fSMORoleOwner
                }

                # Domain Naming Master (forest-wide)
                $NamingRole = @(Get-DomainObject -LDAPFilter "(objectClass=*)" -SearchBase "CN=Partitions,$ConfigDN" -Scope Base @PSBoundParameters)[0]
                if ($NamingRole -and $NamingRole.fSMORoleOwner) {
                    $FSMORoles['Domain Naming Master'] = $NamingRole.fSMORoleOwner
                }

                # Build reverse mapping: DC DN -> FSMO roles
                # FSMO role owner is stored as: CN=NTDS Settings,CN=DCNAME,CN=Servers,CN=Site,CN=Sites,...
                foreach ($roleName in $FSMORoles.Keys) {
                    $roleOwnerDN = $FSMORoles[$roleName]
                    if ($roleOwnerDN -match 'CN=NTDS Settings,CN=([^,]+),') {
                        $dcName = $Matches[1]
                        if (-not $FSMOByDC.ContainsKey($dcName)) {
                            $FSMOByDC[$dcName] = @()
                        }
                        $FSMOByDC[$dcName] += $roleName
                    }
                }

                Write-Log "[Get-DomainInformation] FSMO role mapping complete: $($FSMOByDC.Count) DCs have FSMO roles"
            } catch {
                Write-Log "[Get-DomainInformation] Error querying FSMO roles: $_"
            }

            # Output Domain Controllers with FSMO roles
            if (@($DomainControllers).Count -gt 0) {
                # Build DC list with FSMO roles
                $dcDisplayList = @()
                foreach ($dc in $DomainControllers) {
                    $dcHostName = if ($dc.dNSHostName) { $dc.dNSHostName } else { $dc.name }
                    $dcName = $dc.name

                    # Check if this DC has any FSMO roles
                    $roles = @()
                    if ($FSMOByDC.ContainsKey($dcName)) {
                        $roles = $FSMOByDC[$dcName]
                    }

                    if (@($roles).Count -gt 0) {
                        $rolesText = $roles -join ", "
                        $dcDisplayList += "$dcHostName [$rolesText]"
                    } else {
                        $dcDisplayList += $dcHostName
                    }
                }

                $dcObj = [PSCustomObject]@{
                    domainControllers = $dcDisplayList -join "`n"
                }
                Show-Line "Found $(@($DomainControllers).Count) domain controller(s):" -Class Note
                $dcObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'DomainControllers' -Force
                Show-Object $dcObj
            } else {
                Show-Line "No domain controllers found" -Class Note
            }

            # ===================================================================
            # SubCheck 5: Sites and Subnets
            # Severity: Hint (no subnets), Note (subnets found)
            # ===================================================================
            Show-SubHeader "Searching for Sites and Subnets..." -ObjectType "SitesAndSubnets"

            if (@($Sites).Count -gt 0) {
                Show-Line "Found $(@($Sites).Count) site(s) and $(@($Subnets).Count) subnet(s):" -Class Note

                foreach ($siteInfo in $Sites) {
                    # Build site object with subnets and DCs
                    $siteSubnets = @($Subnets | Where-Object { $_.Site -eq $siteInfo.Name })
                    $subnetDisplay = if ($siteSubnets.Count -gt 0) {
                        ($siteSubnets | ForEach-Object { $_.Name }) -join ", "
                    } else {
                        "(none)"
                    }
                    $dcDisplay = if ($siteInfo.DomainControllers.Count -gt 0) {
                        ($siteInfo.DomainControllers) -join ", "
                    } else {
                        "(none)"
                    }

                    $siteObj = [PSCustomObject]@{
                        Name = $siteInfo.Name
                        siteName = $siteInfo.Name
                        siteSubnets = $subnetDisplay
                        siteDomainControllers = $dcDisplay
                    }
                    $siteObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SitesAndSubnets' -Force
                    Show-Object $siteObj
                }
            } else {
                Show-Line "No AD sites found" -Class Hint
            }

        } catch {
            Write-Log "[Get-DomainInformation] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-DomainInformation] Domain enumeration completed"
    }
}
