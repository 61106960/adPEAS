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

            # Resolved from the crossRef at connect time and therefore already known,
            # whatever the domain object query below does. It used to be read inside that
            # query's success branch, so an unreadable domain object - a permissions
            # problem, a timeout - reported the NetBIOS name as "(not found)" even though
            # the session had it in hand.
            if ($Script:LDAPContext.DomainNetBIOS) {
                $NetBIOSName = $Script:LDAPContext.DomainNetBIOS
                Write-Log "[Get-DomainInformation] NetBIOS name (from crossRef): $NetBIOSName"
            }

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
                    # The domain object's 'name' attribute is the DNS label (e.g. "example"),
                    # NOT the NetBIOS name. It is only a last resort for the case where the
                    # crossRef lookup above produced nothing.
                    if (-not $NetBIOSName -and $DomainObject.name) {
                        $NetBIOSName = $DomainObject.name
                        Write-Log "[Get-DomainInformation] NetBIOS name fallback (domain object name/DNS label): $NetBIOSName"
                    }

                    # The Kerberos policy is not read here: maxTicketAge and maxRenewAge
                    # belong to class Domain-Policy, not to the domain object, which never
                    # carries them. Get-DomainKerberosPolicy reads it from SYSVOL below.

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

                # By RID, not by name. krbtgt can be renamed - it happens after an
                # incident, which is exactly when its password age matters most - and a
                # name-based lookup then finds nothing, leaves $KrbtgtInfo null and drops
                # the whole statement without a word. The kerberoast check already
                # excludes the account by (objectSid=<domain>-502) and says why; this is
                # the same identity, asked the same way. Name only as the fallback for a
                # session that has no resolved domain SID.
                $krbtgtDomainSID = $Script:LDAPContext['DomainSID']
                $krbtgtFilter = if ($krbtgtDomainSID) {
                    "(objectSid=$krbtgtDomainSID-502)"
                } else {
                    Write-Log "[Get-DomainInformation] No domain SID in session - looking up krbtgt by name"
                    "(sAMAccountName=krbtgt)"
                }
                $KrbtgtAccount = @(Get-DomainObject -LDAPFilter $krbtgtFilter @PSBoundParameters)[0]

                if (-not $KrbtgtAccount) {
                    # Said rather than skipped: the krbtgt password age is the Golden Ticket
                    # window, and silence here reads as "in order".
                    Show-Line "The krbtgt account could not be read - its password age is unknown" -Class Note
                }

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

            # Anonymous LDAP access: three states, and the row used to exist for one.
            #
            # Connect-LDAP skips the test under -UseLDAPS and for a global catalog
            # connection, and the flag it sets beforehand is $false - so no row was
            # written and the report looked exactly like a domain that refuses anonymous
            # binds. A reader takes an absent row for an absent problem, and -UseLDAPS is
            # the mode a security-conscious customer picks.
            if ($Script:LDAPContext['AnonymousAccessEnabled']) {
                $domainInfoObj | Add-Member -NotePropertyName 'anonymousLDAPAccess' -NotePropertyValue "ENABLED - Security Risk!" -Force
                $anonDetails = $Script:LDAPContext['AnonymousAccessDetails']
                if ($anonDetails -and $anonDetails.ReadableAttributes -and $anonDetails.ReadableAttributes.Count -gt 0) {
                    $domainInfoObj | Add-Member -NotePropertyName 'anonymousReadableAttributes' -NotePropertyValue ($anonDetails.ReadableAttributes -join ', ') -Force
                }
                $domainInfoSeverity = "Finding"
            }
            elseif ($Script:LDAPContext['AnonymousAccessTested']) {
                # Measured and refused. This is the earned green state, and nothing used
                # to say it out loud. "(tested)" is what sets it apart from the dsHeuristics
                # reading; what was tried is the card's to explain.
                $domainInfoObj | Add-Member -NotePropertyName 'anonymousLDAPAccess' -NotePropertyValue 'Refused (tested)' -Force
            }
            else {
                # Not asked, or asked and never answered. Neutral on purpose: this is the one
                # state where adPEAS has nothing to report either way, and saying so - with
                # the reason Connect-LDAP recorded, in a word or two - is the whole point.
                # A context without that key claims no reason of its own.
                $anonSkipReason = [string]$Script:LDAPContext['AnonymousAccessSkipReason']
                $anonNotTested = if ($anonSkipReason) { "Not tested ($anonSkipReason)" } else { 'Not tested' }
                $domainInfoObj | Add-Member -NotePropertyName 'anonymousLDAPAccess' -NotePropertyValue $anonNotTested -Force
            }
            # What a deletion leaves behind in this forest. Without the Recycle Bin a deleted
            # object becomes a tombstone that keeps a handful of attributes - group
            # memberships and most of what a restore or an investigation needs are gone - and
            # the tombstone lifetime bounds the age of a backup that can still be restored.
            # Neither was read anywhere.
            $deletionParams = @{}
            foreach ($key in @($PSBoundParameters.Keys)) { $deletionParams[$key] = $PSBoundParameters[$key] }
            $deletion = Get-ForestDeletionSetting -ConnectionParams $deletionParams
            $maintenanceHint = $false

            if ($null -eq $deletion.TombstoneLifetime) {
                $tombstoneText = 'Unknown (not readable)'
            } else {
                # Short on purpose - what the lifetime bounds is the card's to say.
                $tombstoneDays = $deletion.TombstoneLifetime
                $tombstoneText = if ($deletion.TombstoneLifetimeSet) { "$tombstoneDays days" } else { "$tombstoneDays days (not set)" }
                if ($tombstoneDays -lt 180) {
                    $maintenanceHint = $true
                    $tombstoneText += ' - below the 180-day default'
                }
            }
            $domainInfoObj | Add-Member -NotePropertyName 'tombstoneLifetime' -NotePropertyValue $tombstoneText -Force

            # Short as well: what a disabled Recycle Bin costs is its card's to say.
            if ($null -eq $deletion.RecycleBin) {
                $recycleBinText = 'Unknown (not readable)'
            } elseif ($deletion.RecycleBin) {
                $recycleBinText = 'Enabled'
            } elseif ([int]$ForestFunc -lt 4) {
                $recycleBinText = 'Not available (needs forest level 2008 R2)'
            } else {
                $maintenanceHint = $true
                $recycleBinText = 'Disabled'
            }
            $domainInfoObj | Add-Member -NotePropertyName 'recycleBin' -NotePropertyValue $recycleBinText -Force
            if ($deletion.RecycleBin -and $null -ne $deletion.DeletedObjectLifetime) {
                # Unset, it takes the tombstone lifetime, and the two rows read like two
                # settings that happen to agree unless this one says where its value is from.
                $deletedText = "$($deletion.DeletedObjectLifetime) days"
                if (-not $deletion.DeletedObjectLifetimeSet) { $deletedText += ' (not set, follows tombstoneLifetime)' }
                $domainInfoObj | Add-Member -NotePropertyName 'deletedObjectLifetime' -NotePropertyValue $deletedText -Force
            }

            # Which service replicates SYSVOL. FRS is deprecated, and a domain that still
            # replicates SYSVOL with it accepts no domain controller from Windows Server 1709
            # on - it says the domain controllers and their maintenance are old. Not read
            # anywhere before. The row names the mode; the card says what FRS costs.
            $sysvolReplication = Get-SysvolReplication -DomainDN $DomainDN -ConnectionParams $deletionParams
            $sysvolText = switch ($sysvolReplication.Mode) {
                'DFSR' { 'DFSR' }
                'FRS' {
                    $maintenanceHint = $true
                    'FRS (not migrated to DFSR)'
                }
                'Migrating' {
                    $maintenanceHint = $true
                    $stateText = if ($sysvolReplication.State) { $sysvolReplication.State } else { 'not set' }
                    "FRS and DFSR (migration state $stateText)"
                }
                default { 'Unknown (not found)' }
            }
            $domainInfoObj | Add-Member -NotePropertyName 'sysvolReplication' -NotePropertyValue $sysvolText -Force

            if ($maintenanceHint -and $domainInfoSeverity -eq "Note") {
                $domainInfoSeverity = "Hint"
            }

            # Check for old functional level (< 2016 = level 7).
            #
            # Its own statement now, guarded on the severity rather than chained: it
            # used to be an elseif of the anonymous-access branch above, which worked
            # only as long as that branch had a single arm. The guard keeps the old
            # precedence - a Finding above outranks this hint.
            if ($domainInfoSeverity -eq "Note" -and [int]$DomainFunc -lt 7) {
                $domainInfoSeverity = "Hint"
            }

            # Output domain info object
            Show-Line "Found domain information:" -Class $domainInfoSeverity
            $domainInfoObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'DomainBasicInfo' -Force
            Show-Object $domainInfoObj -Class $domainInfoSeverity

            # ===================================================================
            # SubCheck 2: Kerberos Policy
            # Severity: Finding (krbtgt > 365d), Hint (krbtgt > 180d), Note (default)
            # ===================================================================
            Show-SubHeader "Analyzing Kerberos policy..." -ObjectType "KerberosPolicy"

            # Build Kerberos policy values, from the [Kerberos Policy] section of the
            # domain-linked GPOs (Get-DomainKerberosPolicy). Not "the default" until
            # something was read: an unread policy is Unknown, and a policy no GPO sets is
            # said to be the Windows default, with that reason.
            $kerberosConnection = @{}
            foreach ($key in @('Domain', 'Server', 'Credential')) {
                if ($PSBoundParameters.ContainsKey($key)) { $kerberosConnection[$key] = $PSBoundParameters[$key] }
            }
            $KerberosPolicy = Get-DomainKerberosPolicy -ConnectionParams $kerberosConnection

            # Unit, Windows default, and the clause the verdict uses for each setting.
            # 0 is "never expires" for the two ticket lifetimes (Microsoft's policy
            # reference); for the renewal window and the clock skew it is just a number.
            # The clauses name the default only - the value is in the row above.
            $kerberosSettings = @(
                @{ Name = 'MaxTicketAge';  Unit = 'hours';   Default = 10
                   Clause = 'TGT lifetime above 10 hours'; NeverClause = 'TGT never expires' }
                @{ Name = 'MaxRenewAge';   Unit = 'days';    Default = 7
                   Clause = 'renewal above 7 days'; NeverClause = $null }
                @{ Name = 'MaxServiceAge'; Unit = 'minutes'; Default = 600
                   Clause = 'service ticket lifetime above 600 minutes'; NeverClause = 'service ticket never expires' }
                @{ Name = 'MaxClockSkew';  Unit = 'minutes'; Default = 5
                   Clause = 'clock skew above 5 minutes'; NeverClause = $null }
            )
            # Short rows: a default value does not say which GPO carries it, an unset one
            # says "(not set)" - the card explains both. A value off the default names
            # its GPO, because that is where the fix goes.
            $kerberosTexts = @{}
            $verdictClauses = @()
            foreach ($setting in $kerberosSettings) {
                if ($null -eq $KerberosPolicy) {
                    $kerberosTexts[$setting.Name] = 'Unknown (not readable)'
                    continue
                }
                $entry = $KerberosPolicy[$setting.Name]
                if ($null -eq $entry -or $null -eq $entry.Value) {
                    $kerberosTexts[$setting.Name] = "$($setting.Default) $($setting.Unit) (default, not set)"
                    continue
                }
                $value = [int]$entry.Value
                if ($value -eq 0 -and $setting.NeverClause) {
                    $kerberosTexts[$setting.Name] = "0 (never expires, set by $($entry.Source))"
                    $verdictClauses += $setting.NeverClause
                    continue
                }
                $kerberosTexts[$setting.Name] = if ($value -eq $setting.Default) {
                    "$value $($setting.Unit) (default)"
                } else {
                    "$value $($setting.Unit) (set by $($entry.Source))"
                }
                if ($value -gt $setting.Default) { $verdictClauses += $setting.Clause }
            }
            $maxTicketAgeText = $kerberosTexts['MaxTicketAge']
            $maxRenewalAgeText = $kerberosTexts['MaxRenewAge']

            # Above the defaults a stolen ticket keeps working for longer, which is the
            # whole of what these settings decide. One sentence for all of them: the
            # renewal window is the outer bound, and separate rows say the same thing.
            $ticketLifetimeVerdict = $null
            if (@($verdictClauses).Count -gt 0) {
                $ticketLifetimeVerdict = 'EXTENDED - ' + (@($verdictClauses) -join ', ')
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
                    $dcTimeUTC = [DateTime]::ParseExact($dcTimeStr.Substring(0, 14), "yyyyMMddHHmmss", [System.Globalization.CultureInfo]::InvariantCulture)
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
                    $dcTimeText = "$(Format-adPEASDate $dcTimeUTC 'yyyy-MM-dd HH:mm:ss') UTC (skew: $skewDisplay)"
                }
            }
            catch {
                Write-Log "[Get-DomainInformation] Failed to query DC currentTime: $_"
            }

            $kerberosObj = [PSCustomObject]@{
                maxTicketAgeTGT = $maxTicketAgeText
                maxRenewalAge = $maxRenewalAgeText
                maxServiceTicketAge = $kerberosTexts['MaxServiceAge']
                maxClockSkew = $kerberosTexts['MaxClockSkew']
            }

            # Add DC time if available
            if ($dcTimeText) {
                $kerberosObj | Add-Member -NotePropertyName 'domainControllerTime' -NotePropertyValue $dcTimeText -Force
            }

            # The verdict on the two lifetimes, on an attribute of its own so it can
            # carry a write-up. Written only when something was actually widened: a
            # row saying "the defaults are in place" on every ordinary domain is a
            # sentence nobody reads twice.
            if ($ticketLifetimeVerdict) {
                $kerberosObj | Add-Member -NotePropertyName 'ticketLifetime' -NotePropertyValue $ticketLifetimeVerdict -Force
            }

            # Determine severity for Kerberos Policy based on krbtgt age
            # Finding: krbtgt > 365 days (1 year)
            # Hint: krbtgt > 180 days
            # Note: krbtgt <= 180 days or not available
            $kerberosSeverity = "Note"

            if ($KrbtgtInfo) {
                $LastChanged = (Format-adPEASDate $KrbtgtInfo.PasswordLastSet 'yyyy-MM-dd')
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
            Show-Object $kerberosObj -Class $kerberosSeverity

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
                Show-Object $guestObj -Class $guestClass

            } else {
                Show-Line "Guest account not found (unusual - RID 501 should always exist)" -Class Hint
            }

            # ===================================================================
            # SubCheck 4: Domain Controllers
            # Severity: Note (informational only, OS/LDAPS checked elsewhere)
            # ===================================================================
            # Its own header and object type: Get-InfrastructureServers lists the Domain
            # Controller computer accounts under "Searching for Domain Controllers...", and
            # the report titles a card by the object type of its header - both sections
            # came out as "Domain Controllers" with the inventory's help text.
            Show-SubHeader "Listing the Domain Controllers and their FSMO roles..." -ObjectType "DomainControllers"

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
                Show-Object $dcObj -Class Note
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
                        # Join with newline (not ", ") so the renderer prints one subnet per line,
                        # each padded to the value column - consistent with domainControllers above.
                        # A comma-joined string renders as one long line that wraps out of alignment.
                        ($siteSubnets | ForEach-Object { $_.Name }) -join "`n"
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
                    Show-Object $siteObj -Class Note
                }
            } else {
                Show-Line "No AD sites found" -Class Hint
            }

        } catch {
            Write-Log "[Get-DomainInformation] Error: $_" -Level Error
            Show-Line "Error during check - the domain information could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-DomainInformation] Domain enumeration completed"
    }
}

<#
.SYNOPSIS
    What happens to a deleted object in this forest: tombstone lifetime and Recycle Bin.

.DESCRIPTION
    Both are forest-wide, and neither was read anywhere.

    tombstoneLifetime and msDS-DeletedObjectLifetime are on CN=Directory Service in the
    configuration partition, in days (MS-ADTS 3.1.1.1.5.1). Without a value the tombstone
    lifetime is 60 days; a value below 2 counts as 2 on Windows Server 2008 R2 and later.
    The deleted-object lifetime defaults to the tombstone lifetime.

    The Recycle Bin is an optional feature, enabled for the forest when msDS-EnabledFeature
    on the Partitions container names its feature object, CN=Recycle Bin Feature under
    CN=Optional Features (MS-ADTS 3.1.1.9, 3.1.1.9.1). It needs forest functional level
    Windows Server 2008 R2 and cannot be disabled once enabled.

.PARAMETER ConnectionParams
    Domain/Server/Credential hashtable, passed through unchanged.

.OUTPUTS
    PSCustomObject: TombstoneLifetime (days, effective), TombstoneLifetimeSet ($true when
    the attribute carries a value), DeletedObjectLifetime (days, effective),
    DeletedObjectLifetimeSet (the same for msDS-DeletedObjectLifetime), both lifetimes $null
    when the Directory Service object could not be read; RecycleBin $true, $false, or $null
    when the Partitions container could not be read.
#>
function Get-ForestDeletionSetting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$ConnectionParams = @{}
    )

    $result = [PSCustomObject]@{
        TombstoneLifetime        = $null
        TombstoneLifetimeSet     = $false
        DeletedObjectLifetime    = $null
        DeletedObjectLifetimeSet = $false
        RecycleBin               = $null
    }
    $configDN = $Script:LDAPContext.ConfigurationNamingContext
    if (-not $configDN) { return $result }

    try {
        $dirService = @(Get-DomainObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$configDN" -Properties 'tombstoneLifetime', 'msDS-DeletedObjectLifetime' @ConnectionParams)[0]
        if ($dirService) {
            $days = 0
            if ([int]::TryParse([string]$dirService.tombstoneLifetime, [ref]$days)) {
                $result.TombstoneLifetimeSet = $true
                $result.TombstoneLifetime = [Math]::Max($days, 2)
            } else {
                $result.TombstoneLifetime = 60
            }
            $deletedDays = 0
            if ([int]::TryParse([string]$dirService.'msDS-DeletedObjectLifetime', [ref]$deletedDays)) {
                $result.DeletedObjectLifetimeSet = $true
                $result.DeletedObjectLifetime = [Math]::Max($deletedDays, 2)
            } else {
                $result.DeletedObjectLifetime = $result.TombstoneLifetime
            }
        }
    } catch {
        Write-Log "[Get-DomainInformation] Could not read the tombstone lifetime: $_"
    }

    try {
        $partitions = @(Get-DomainObject -Identity "CN=Partitions,$configDN" -Properties 'msDS-EnabledFeature' @ConnectionParams)[0]
        if ($partitions) {
            $result.RecycleBin = (@(@($partitions.'msDS-EnabledFeature') | Where-Object {
                "$_" -like 'CN=Recycle Bin Feature,CN=Optional Features,*'
            }).Count -gt 0)
        }
    } catch {
        Write-Log "[Get-DomainInformation] Could not read the enabled optional features: $_"
    }

    return $result
}

<#
.SYNOPSIS
    Which service replicates SYSVOL in this domain: FRS, DFSR, or both during a migration.

.DESCRIPTION
    Read from three objects under CN=System of the domain:
    - CN=Domain System Volume (SYSVOL share),CN=File Replication Service - the FRS replica
      set of SYSVOL. The PDC removes it when a migration to DFSR reaches Eliminated.
    - CN=Domain System Volume,CN=DFSR-GlobalSettings - the DFSR replication group of SYSVOL,
      created when a migration reaches Prepared, and present from the start in a domain
      that never used FRS.
    - msDFSR-Flags on CN=DFSR-GlobalSettings - the global migration state: 0 Start,
      16 Prepared, 32 Redirected, 48 Eliminated; a final cleanup removes it again.
    (AskDS, "DFSR SYSVOL Migration FAQ".) FRS is deprecated, and no domain controller from
    Windows Server 1709 on can be added to a domain that still replicates SYSVOL with it
    (KB4025991, KB4023141).

.PARAMETER DomainDN
    The distinguished name of the domain.

.PARAMETER ConnectionParams
    Domain/Server/Credential hashtable, passed through unchanged.

.OUTPUTS
    PSCustomObject: Mode 'FRS', 'Migrating', 'DFSR' or $null when neither replication object
    was found; State the global migration state by name, or $null.
#>
function Get-SysvolReplication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainDN,

        [Parameter(Mandatory = $false)]
        [hashtable]$ConnectionParams = @{}
    )

    $frsSet = $null
    $dfsrGroup = $null
    $globalSettings = $null
    try {
        $frsSet = @(Get-DomainObject -Identity "CN=Domain System Volume (SYSVOL share),CN=File Replication Service,CN=System,$DomainDN" -Properties 'distinguishedName' @ConnectionParams)[0]
    } catch {
        Write-Log "[Get-DomainInformation] Could not read the FRS replica set of SYSVOL: $_"
    }
    try {
        $dfsrGroup = @(Get-DomainObject -Identity "CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,$DomainDN" -Properties 'distinguishedName' @ConnectionParams)[0]
        $globalSettings = @(Get-DomainObject -Identity "CN=DFSR-GlobalSettings,CN=System,$DomainDN" -Properties 'msDFSR-Flags' @ConnectionParams)[0]
    } catch {
        Write-Log "[Get-DomainInformation] Could not read the DFSR replication group of SYSVOL: $_"
    }

    $state = $null
    if ($globalSettings) {
        $flags = 0
        if ([int]::TryParse([string]$globalSettings.'msDFSR-Flags', [ref]$flags)) {
            $state = switch ($flags) {
                0  { 'Start' }
                16 { 'Prepared' }
                32 { 'Redirected' }
                48 { 'Eliminated' }
                default { "Unknown ($flags)" }
            }
        }
    }

    $mode = if ($frsSet -and $dfsrGroup) { 'Migrating' } elseif ($frsSet) { 'FRS' } elseif ($dfsrGroup) { 'DFSR' } else { $null }
    return [PSCustomObject]@{ Mode = $mode; State = $state }
}

<#
.SYNOPSIS
    The domain's Kerberos policy, read where Group Policy keeps it.

.DESCRIPTION
    The Kerberos policy is the [Kerberos Policy] section of GptTmpl.inf in a GPO linked to
    the domain - MaxTicketAge in hours, MaxRenewAge in days, MaxServiceAge and MaxClockSkew
    in minutes - and the domain controllers take it from there and from nowhere else. The
    check used to read maxTicketAge and maxRenewAge from the domain object; per the schema
    those attributes belong to class Domain-Policy, not to the domain, so the row always
    said Unknown and KERBEROS_TICKET_LIFETIME_EXTENDED could never fire.

    Per setting, the value comes from the highest-ranked domain-linked GPO that sets it: an
    enforced link before the others, then link order. None setting it is the Windows
    default. A policy linked anywhere else does not count; the domain controllers ignore
    Kerberos policy that is not linked to the domain.

.OUTPUTS
    $null when the GPOs, their links or SYSVOL could not be read. Otherwise a hashtable:
    setting name -> @{ Value = [int] or $null; Source = GPO display name or $null }.
#>
function Get-DomainKerberosPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$ConnectionParams = @{}
    )

    $settingNames = @('MaxTicketAge', 'MaxRenewAge', 'MaxServiceAge', 'MaxClockSkew')

    try {
        $gpoByGuid = @{}
        foreach ($gpo in @(Get-DomainGPO @ConnectionParams)) {
            if ($gpo.Name) { $gpoByGuid[([string]$gpo.Name).ToUpper()] = $gpo }
        }
        $linkage = Get-GPOLinkage
        if ($null -eq $linkage) {
            Write-Log "[Get-DomainKerberosPolicy] GPO linkage could not be resolved"
            return $null
        }

        # The candidates: every GPO with an active link on the domain object, ranked.
        $candidates = @()
        foreach ($guid in @($linkage.Keys)) {
            $domainLinks = @(@($linkage[$guid]) | Where-Object { $_ -and $_.Scope -eq 'Domain' -and -not $_.IsDisabled })
            if ($domainLinks.Count -eq 0) { continue }
            $best = @($domainLinks | ForEach-Object {
                [PSCustomObject]@{
                    Rank  = $(if ($_.IsEnforced -eq $true) { 0 } else { 1 })
                    Order = $(if ($_.LinkOrder) { [int]$_.LinkOrder } else { 999 })
                }
            } | Sort-Object Rank, Order)[0]
            $name = if ($gpoByGuid.ContainsKey(([string]$guid).ToUpper())) { [string]$gpoByGuid[([string]$guid).ToUpper()].DisplayName } else { [string]$guid }
            $candidates += [PSCustomObject]@{ Guid = ([string]$guid).ToUpper(); Name = $name; Rank = $best.Rank; Order = $best.Order }
        }

        # The [Kerberos Policy] section of each candidate's GptTmpl.inf. Handed out through
        # a script variable because Invoke-SMBAccess runs the block in a scope of its own,
        # and cleared in the finally below.
        $Script:KerberosPolicySections = @{}
        $Script:KerberosPolicySysvolRead = $false
        $candidateGuids = @($candidates | ForEach-Object { $_.Guid })
        Invoke-SMBAccess -Description "Reading the Kerberos policy from SYSVOL" -ScriptBlock {
            foreach ($file in @(Get-CachedSYSVOLFiles -Filter 'GptTmpl.inf')) {
                if (-not $file -or "$($file.FullName)" -notmatch '\\Policies\\(\{[^}]+\})\\') { continue }
                $fileGuid = $Matches[1].ToUpper()
                if ($candidateGuids -notcontains $fileGuid) { continue }
                $content = Get-CachedSYSVOLContent -Path $file.FullName
                if ($null -eq $content) { continue }
                $values = @{}
                $inSection = $false
                foreach ($line in ([string]$content -split "`r?`n")) {
                    $trimmed = $line.Trim()
                    if ($trimmed -match '^\[(.+)\]$') { $inSection = ($Matches[1] -eq 'Kerberos Policy'); continue }
                    if ($inSection -and $trimmed -match '^(\w+)\s*=\s*(-?\d+)\s*$') { $values[$Matches[1]] = [int]$Matches[2] }
                }
                $Script:KerberosPolicySections[$fileGuid] = $values
            }
            $Script:KerberosPolicySysvolRead = $true
        }
        if (-not $Script:KerberosPolicySysvolRead) {
            Write-Log "[Get-DomainKerberosPolicy] SYSVOL could not be read"
            return $null
        }

        $ranked = @($candidates | Sort-Object Rank, Order, Name)
        $policy = @{}
        foreach ($setting in $settingNames) {
            $policy[$setting] = @{ Value = $null; Source = $null }
            foreach ($candidate in $ranked) {
                $section = $Script:KerberosPolicySections[$candidate.Guid]
                if ($section -and $section.ContainsKey($setting)) {
                    $policy[$setting] = @{ Value = [int]$section[$setting]; Source = $candidate.Name }
                    break
                }
            }
        }
        return $policy
    } catch {
        Write-Log "[Get-DomainKerberosPolicy] Error: $_"
        return $null
    } finally {
        $Script:KerberosPolicySections = $null
        $Script:KerberosPolicySysvolRead = $null
    }
}
