<#
.SYNOPSIS
    Reports the non-computer accounts that carry one of a service's SPNs.

.DESCRIPTION
    An SPN sits on the identity the service authenticates as. Where SQL Server, SCCM or
    SCOM runs under a domain service account - routine in a managed environment, and the
    precondition for Kerberos against the service rather than an exception - the SPN is on
    a user or gMSA object, and a query over computer objects sees none of it. The inventory
    a reader bases their attack surface on then understates it, without saying so.

    The host part of the SPN is what names the target system, so it is reported with the
    account: the account is the credential, the host is what runs there.

    objectCategory, not objectClass: a gMSA carries 'computer' among its object classes, so
    (!(objectClass=computer)) would exclude the very accounts this is looking for.
    objectCategory names the most specific class, which is what tells the two apart.

.PARAMETER ServiceName
    How the service is called in the report, e.g. 'MSSQL'.

.PARAMETER SPNFilter
    The same LDAP filter clause the computer query uses, e.g. "(servicePrincipalName=MSSQLSvc/*)".

.PARAMETER SPNPrefix
    The SPN prefixes whose host part is worth printing, e.g. @('MSSQLSvc/').

.PARAMETER ConnectionParams
    Domain/Server/Credential, as the caller received them.

.PARAMETER PrivilegedFindingId
    When given, each account is also checked for privileged rights in the domain, and the
    privileged ones are reported under this finding. A service runs its code as the account
    and the host stores the account's password, so whoever controls the service or its host
    holds the account's rights - for SQL Server, a sysadmin reaches them through xp_cmdshell.
    Without it the accounts are listed and nothing more.

.NOTES
    Internal helper function
#>
function Show-SPNServiceAccounts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServiceName,

        [Parameter(Mandatory=$true)]
        [string]$SPNFilter,

        [Parameter(Mandatory=$true)]
        [string[]]$SPNPrefix,

        [Parameter(Mandatory=$false)]
        [hashtable]$ConnectionParams = @{},

        [Parameter(Mandatory=$false)]
        [string]$PrivilegedFindingId
    )

    $accounts = @()
    try {
        $accounts = @(Get-DomainObject -LDAPFilter "(&$SPNFilter(!(objectCategory=computer)))" `
            -Properties 'sAMAccountName', 'servicePrincipalName', 'objectClass', 'objectSid' @ConnectionParams)
    } catch {
        Write-Log "[Get-InfrastructureServers] $ServiceName service account lookup failed: $_" -Level Error
        Show-Line "$ServiceName service accounts could not be read - result unknown, not empty" -Class "Note"
        return
    }

    if (@($accounts).Count -eq 0) { return }

    $described = @()
    $privileged = @()
    $unevaluated = @()
    foreach ($account in $accounts) {
        $hostNames = @()
        foreach ($spn in @($account.servicePrincipalName)) {
            foreach ($prefix in $SPNPrefix) {
                if ("$spn" -like "$prefix*") {
                    # MSSQLSvc/host.contoso.com:1433 and MSSQLSvc/host:INSTANCE both end the
                    # host at the first colon; SMS and CCM SPNs carry no port.
                    $hostPart = ("$spn".Substring($prefix.Length) -split '[:/]')[0]
                    if ($hostPart -and ($hostNames -notcontains $hostPart)) { $hostNames += $hostPart }
                }
            }
        }

        $label = "$($account.sAMAccountName)"
        if (@($hostNames).Count -gt 0) { $label = $label + ' (' + (@($hostNames) -join ', ') + ')' }
        $described += $label

        if (-not $PrivilegedFindingId) { continue }

        # Operators included: Backup and Server Operators reach a domain controller as
        # surely as Domain Admins do, and the service hands either to whoever controls it.
        # An account whose privileges cannot be told is named as unknown rather than
        # counted with the unprivileged ones.
        $privilegeCheck = $null
        $accountSID = "$($account.objectSid)"
        if (-not [string]::IsNullOrWhiteSpace($accountSID)) {
            try {
                $privilegeCheck = Test-IsPrivileged -Identity $accountSID -IncludeOperators
            } catch {
                Write-Log "[Get-InfrastructureServers] Could not evaluate privileges of $($account.sAMAccountName): $_"
            }
        }

        if ($null -eq $privilegeCheck -or $null -eq $privilegeCheck.IsPrivileged) {
            $unevaluated += "$($account.sAMAccountName)"
        } elseif ($privilegeCheck.IsPrivileged -eq $true) {
            $via = if ($privilegeCheck.MatchedGroup) { $privilegeCheck.MatchedGroup } else { $privilegeCheck.Reason }
            $privileged += "$($account.sAMAccountName) ($via)"
        }
    }

    Show-Line "$ServiceName also runs under $(@($described).Count) domain account(s), host from the SPN: $(@($described) -join '; ')" -Class "Hint"

    if (@($privileged).Count -gt 0) {
        Show-Line "$(@($privileged).Count) of them hold privileged rights in the domain, and whoever controls the service or its host holds them too: $(@($privileged) -join '; ')" -Class "Finding" -FindingId $PrivilegedFindingId
    }
    if (@($unevaluated).Count -gt 0) {
        Show-Line "The privileges of $(@($unevaluated).Count) of them could not be evaluated - result unknown, not unprivileged: $(@($unevaluated) -join '; ')" -Class "Note"
    }
}

<#
.SYNOPSIS
    Names the computer accounts of a service that show no recent activity.

.DESCRIPTION
    Test-AccountActivity -IsEnabled filters disabled accounts, not idle ones. A machine
    that was decommissioned without being disabled keeps its SPN, so it was reported as a
    live server of that kind - the other error direction of the same inventory, and a
    reader cannot tell which rows are real.

    A Note rather than a finding: an idle account is not a weakness, and the count stays
    separate from the inventory line above it so neither number is diluted.

.PARAMETER ServiceName
    How the service is called in the report, e.g. 'MSSQL'.

.PARAMETER Server
    The objects the inventory reported, annotated by Test-AccountActivity -IncludeDetails.

.NOTES
    Internal helper function
#>
function Show-SPNIdleServers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServiceName,

        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        $Server
    )

    $idle = @(@($Server) | Where-Object {
        $_ -and $_.PSObject.Properties['ActivityDetails'] -and $_.ActivityDetails -and (-not $_.ActivityDetails.IsActive)
    })
    if (@($idle).Count -eq 0) { return }

    $names = @($idle | ForEach-Object { "$($_.sAMAccountName)" -replace '\$$', '' })
    Show-Line "$(@($idle).Count) of the $ServiceName computer account(s) show no recent logon - possibly decommissioned: $(@($names) -join ', ')" -Class "Note"
}
<#
.SYNOPSIS
    Returns the computer DNs the configuration partition registers as Domain Controllers.

.DESCRIPTION
    A promotion creates a server object under CN=Sites whose serverReference names the
    computer account, and below it the NTDS Settings object (nTDSDSA, nTDSDSARO for an
    RODC). The role flag on the computer account is only userAccountControl: whoever holds
    DS-Install-Replica on the domain object and may write the account's
    userAccountControl can set SERVER_TRUST_ACCOUNT, which makes the account's primary
    group Domain Controllers - with its replication rights - and creates neither object.

    Sites are forest-wide, so the set holds the Domain Controllers of every domain in the
    forest; the caller compares it with its own accounts.

.OUTPUTS
    Hashtable keyed by computer DN - case-insensitive, as every PowerShell hashtable -
    or $null when the configuration partition could not be read. Every forest has an NTDS
    Settings object, so none at all counts as not read rather than as no Domain Controller.

.NOTES
    Internal helper function
#>
function Get-RegisteredDomainControllerDN {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    $configNC = $Script:LDAPContext.ConfigurationNamingContext
    if (-not $configNC) { return $null }
    $sitesContainer = "CN=Sites,$configNC"

    try {
        # nTDSDSARO is a subclass of nTDSDSA, so one clause finds both kinds.
        $serversWithSettings = @{}
        foreach ($settings in @(Get-DomainObject -LDAPFilter '(objectClass=nTDSDSA)' -SearchBase $sitesContainer -Properties 'distinguishedName' @PSBoundParameters)) {
            # The NTDS Settings object's parent is the server object.
            if ([string]$settings.distinguishedName -match '^CN=(?:[^,\\]|\\.)+,(.+)$') {
                $serversWithSettings[$Matches[1]] = $true
            }
        }
        if ($serversWithSettings.Count -eq 0) { return $null }

        $registered = @{}
        foreach ($serverObject in @(Get-DomainObject -LDAPFilter '(&(objectClass=server)(serverReference=*))' -SearchBase $sitesContainer -Properties 'distinguishedName', 'serverReference' @PSBoundParameters)) {
            if ($serversWithSettings.ContainsKey([string]$serverObject.distinguishedName)) {
                $registered[[string]$serverObject.serverReference] = $true
            }
        }
        return $registered
    } catch {
        Write-Log "[Get-RegisteredDomainControllerDN] The configuration partition could not be read: $_"
        return $null
    }
}

function Get-InfrastructureServers {
    <#
    .SYNOPSIS
    Inventories the infrastructure servers of the domain.

    .DESCRIPTION
    Enumerates the servers worth knowing about before anything else is analysed. Each kind
    is looked up the way that kind actually records itself, which is not always an SPN.

    Detected Server Types:
    - Domain Controllers (the userAccountControl role bit, via Get-DomainComputer -DomainController,
      and a primary group of Domain Controllers), each checked against the NTDS Settings
      object a promotion creates - an account with the role and without that object holds
      the rights of a Domain Controller and is a finding
    - Exchange Servers (msExchExchangeServer objects in the Configuration partition,
      falling back to the exchangeAB/, exchangeRFR/, exchangeMDB/ SPNs)
    - MSSQL Servers (MSSQLSvc/)
    - SCCM/ConfigMgr (SMS*, CCM*)
    - SCOM (MSOMHSvc/, MSOMSdkSvc/)

    For the three SPN-based kinds the service accounts are reported too. An SPN sits on
    the identity the service authenticates as, so where SQL Server, SCCM or SCOM runs
    under a domain account - routine, and the precondition for Kerberos against the
    service - the SPN is on a user or gMSA object and a computer query sees none of it.
    The host part of the SPN names the system it runs on.

    The other error direction is named as well: a machine that was decommissioned
    without being disabled keeps its SPN and was reported as a live server of that kind.
    Those accounts are listed separately as showing no recent logon.
    - AD FS (the DKM container under CN=ADFS,CN=Microsoft,CN=Program Data, plus adfssrv/)
    - Entra ID Connect (MSOL_/ADSync/AAD_ accounts, azureadconnect SPN)

    Every section runs on its own, so one that cannot be read does not take the others with
    it and says so rather than reporting an empty result.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-InfrastructureServers

    .EXAMPLE
    Get-InfrastructureServers -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Computer
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
        Write-Log "[Get-InfrastructureServers] Starting check"
    }

    process {
        # Every section runs under its own try/catch. One try around all six meant the
        # first failure ended the check: an Exchange group that could not be read took
        # MSSQL, SCCM, SCOM and Entra ID Connect down with it, and the report showed
        # nothing for them - indistinguishable from a domain that has none of those.
        # A failed section now says so and the remaining ones still run.
        if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
            return
        }

        # ===== Domain Controllers =====
        Show-SubHeader "Searching for Domain Controllers..." -ObjectType "DomainController"

        try {
            # What counts as a domain controller is defined once, in Get-DomainComputer, so
            # this inventory and the delegation checks cannot drift apart on the question.
            $domainControllers = @(Get-DomainComputer -DomainController @PSBoundParameters | Test-AccountActivity -IsEnabled)

            # And the computers whose primary group is Domain Controllers without the role
            # flag: in the token they are Domain Controllers, to -DomainController not. The
            # query returns the real ones again; they are dropped by DN rather than by a
            # second spelling of the role flag here.
            $listedDNs = @{}
            foreach ($dc in $domainControllers) { $listedDNs[[string]$dc.distinguishedName] = $true }
            foreach ($primaryGroupHolder in @(Get-DomainComputer -LDAPFilter '(primaryGroupID=516)' @PSBoundParameters | Test-AccountActivity -IsEnabled)) {
                if (-not $listedDNs.ContainsKey([string]$primaryGroupHolder.distinguishedName)) {
                    $domainControllers += $primaryGroupHolder
                }
            }

            if ($domainControllers.Count -gt 0) {
                # Which of them a promotion actually made a Domain Controller. The role flag
                # can be set on any computer account by whoever holds DS-Install-Replica and
                # may write its userAccountControl, and gives it the replication rights of
                # Domain Controllers without a server ever being promoted.
                $registered = Get-RegisteredDomainControllerDN @PSBoundParameters
                $listedDCs = @()
                $unregisteredDCs = @()
                foreach ($dc in $domainControllers) {
                    $dc | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'DomainController' -Force
                    if ($null -ne $registered -and -not $registered.ContainsKey([string]$dc.distinguishedName)) {
                        $dc | Add-Member -NotePropertyName 'directoryRegistration' -NotePropertyValue 'NOT REGISTERED - no NTDS Settings object in the configuration partition, yet the account holds the rights of a Domain Controller' -Force
                        $unregisteredDCs += $dc
                    } else {
                        $listedDCs += $dc
                    }
                }

                if ($listedDCs.Count -gt 0) {
                    Show-Line "Found $($listedDCs.Count) Domain Controller(s):" -Class "Hint"
                    foreach ($dc in $listedDCs) { $dc | Show-Object -Class Hint }
                }
                if ($unregisteredDCs.Count -gt 0) {
                    Show-Line "$($unregisteredDCs.Count) computer account(s) carry the Domain Controller role without being registered as Domain Controllers:" -Class "Finding"
                    foreach ($dc in $unregisteredDCs) { $dc | Show-Object -Class Finding }
                }
                if ($null -eq $registered) {
                    Show-Line "The configuration partition could not be read - Domain Controllers were not checked against their NTDS Settings" -Class "Note"
                }
            } else {
                Show-Line "No Domain Controllers found (unexpected)" -Class "Note"
            }
        } catch {
            Write-Log "[Get-InfrastructureServers] Domain Controller enumeration failed: $_" -Level Error
            Show-Line "Domain Controller enumeration failed - result unknown, not empty" -Class "Note"
        }

        # ===== Exchange Servers =====
        Show-SubHeader "Searching for Exchange Servers..." -ObjectType "ExchangeServer"

        try {
            # Exchange records its own servers in the Configuration partition, one
            # msExchExchangeServer object each, and that list is authoritative.
            #
            # Detection used to read the membership of a group found by the literal name
            # "Exchange Servers": name-based, so it broke on a renamed or localized group,
            # and it cost one LDAP query per member. It also contradicted this function's
            # own documentation, which promised SPN-based detection that the code never did.
            $exchangeVersionByName = @{}
            $configNC = $Script:LDAPContext.ConfigurationNamingContext
            if ($configNC) {
                foreach ($exchObject in @(Get-DomainObject -LDAPFilter "(objectClass=msExchExchangeServer)" `
                        -SearchBase "CN=Services,$configNC" @PSBoundParameters)) {
                    $exchName = "$($exchObject.cn)"
                    if ([string]::IsNullOrWhiteSpace($exchName)) { continue }
                    # serialNumber carries the build, e.g. "Version 15.2 (Build 1544.4)" -
                    # the part that decides whether the server is still getting patches
                    $exchangeVersionByName[$exchName.ToLowerInvariant()] = "$($exchObject.serialNumber)"
                }
            } else {
                Write-Log "[Get-InfrastructureServers] No Configuration naming context - falling back to SPN detection for Exchange"
            }

            $exchangeServers = @()
            if ($exchangeVersionByName.Count -gt 0) {
                $clauses = ''
                foreach ($exchName in $exchangeVersionByName.Keys) {
                    $clauses += ('(sAMAccountName=' + (Escape-LDAPFilterValue -Value $exchName) + '$)')
                }
                $exchangeFilter = $(if ($exchangeVersionByName.Count -eq 1) { $clauses } else { '(|' + $clauses + ')' })
                $exchangeServers = @(Get-DomainComputer -LDAPFilter $exchangeFilter @PSBoundParameters | Test-AccountActivity -IsEnabled)
            } else {
                # No Exchange object in the Configuration partition, or it could not be read.
                # The SPN fallback is what the documentation always described; Domain
                # Controllers are excluded there because they carry Exchange SPNs for
                # Autodiscover without being Exchange servers.
                $exchangeServers = @(Get-DomainComputer -KnownSPN Exchange @PSBoundParameters | Test-AccountActivity -IsEnabled)
            }

            if ($exchangeServers.Count -gt 0) {
                Show-Line "Found $($exchangeServers.Count) Exchange Server(s):" -Class "Hint"
                foreach ($exch in $exchangeServers) {
                    $exchKey = "$($exch.sAMAccountName)".TrimEnd('$').ToLowerInvariant()
                    if ($exchangeVersionByName.ContainsKey($exchKey) -and $exchangeVersionByName[$exchKey]) {
                        $exch | Add-Member -NotePropertyName 'exchangeVersion' -NotePropertyValue $exchangeVersionByName[$exchKey] -Force
                    }
                    $exch | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'ExchangeServerBasic' -Force
                    $exch | Show-Object -Class Hint
                }
            } else {
                Show-Line "No Exchange Servers found" -Class "Note"
            }
        } catch {
            Write-Log "[Get-InfrastructureServers] Exchange Server enumeration failed: $_" -Level Error
            Show-Line "Exchange Server enumeration failed - result unknown, not empty" -Class "Note"
        }

        # ===== MSSQL Servers =====
        Show-SubHeader "Searching for MSSQL Servers..." -ObjectType "MSSQLServer"

        try {
            $mssqlServers = @(Get-DomainComputer -LDAPFilter "(servicePrincipalName=MSSQLSvc/*)" @PSBoundParameters | Test-AccountActivity -IsEnabled -IncludeDetails)

            if ($mssqlServers.Count -gt 0) {
                Show-Line "Found $($mssqlServers.Count) MSSQL Server(s):" -Class "Hint"
                foreach ($sql in $mssqlServers) {
                    $sql | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'MSSQLServer' -Force
                    $sql | Show-Object -Class Hint
                }

                Show-SPNIdleServers -ServiceName 'MSSQL' -Server $mssqlServers
            } else {
                Show-Line "No MSSQL Servers found via SPN" -Class "Note"
            }

            # The identity the service authenticates as may be a domain account rather
            # than the machine, and then the SPN is not on a computer object at all. Only
            # this call asks for the accounts' privileges: a sysadmin on the instance runs
            # operating system commands as the account. SCOM service accounts are judged
            # by Get-SCOMInfrastructure.
            Show-SPNServiceAccounts -ServiceName 'MSSQL' -SPNFilter "(servicePrincipalName=MSSQLSvc/*)" `
                -SPNPrefix @('MSSQLSvc/') -ConnectionParams $PSBoundParameters `
                -PrivilegedFindingId 'MSSQL_SERVICE_ACCOUNT_PRIVILEGED'
        } catch {
            Write-Log "[Get-InfrastructureServers] MSSQL Server enumeration failed: $_" -Level Error
            Show-Line "MSSQL Server enumeration failed - result unknown, not empty" -Class "Note"
        }

        # ===== SCCM/ConfigMgr Servers =====
        Show-SubHeader "Searching for SCCM/ConfigMgr Servers..." -ObjectType "SCCMServerBasic"

        try {
            # SCCM SPNs: SMS_Site_*, SMS_MP, SMS_DP, CCMSetup, etc.
            $sccmServers = @(Get-DomainComputer -LDAPFilter "(|(servicePrincipalName=SMS*)(servicePrincipalName=CCM*))" @PSBoundParameters | Test-AccountActivity -IsEnabled -IncludeDetails)

            if ($sccmServers.Count -gt 0) {
                Show-Line "Found $($sccmServers.Count) SCCM/ConfigMgr Server(s):" -Class "Hint"
                foreach ($sccm in $sccmServers) {
                    $sccm | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SCCMServerBasic' -Force
                    $sccm | Show-Object -Class Hint
                }

                Show-SPNIdleServers -ServiceName 'SCCM' -Server $sccmServers
            } else {
                Show-Line "No SCCM Servers found via SPN" -Class "Note"
            }

            # The identity the service authenticates as may be a domain account rather
            # than the machine, and then the SPN is not on a computer object at all.
            Show-SPNServiceAccounts -ServiceName 'SCCM' -SPNFilter "(|(servicePrincipalName=SMS*)(servicePrincipalName=CCM*))" `
                -SPNPrefix @('SMS_', 'CCM') -ConnectionParams $PSBoundParameters
        } catch {
            Write-Log "[Get-InfrastructureServers] SCCM Server enumeration failed: $_" -Level Error
            Show-Line "SCCM Server enumeration failed - result unknown, not empty" -Class "Note"
        }

        # ===== SCOM Servers =====
        Show-SubHeader "Searching for SCOM Servers..." -ObjectType "SCOMServerBasic"

        try {
            # SCOM SPNs: MSOMHSvc (Health Service), MSOMSdkSvc (SDK Service)
            $scomServers = @(Get-DomainComputer -LDAPFilter "(|(servicePrincipalName=MSOMHSvc/*)(servicePrincipalName=MSOMSdkSvc/*))" @PSBoundParameters | Test-AccountActivity -IsEnabled -IncludeDetails)

            if ($scomServers.Count -gt 0) {
                Show-Line "Found $($scomServers.Count) SCOM Server(s):" -Class "Hint"
                foreach ($scom in $scomServers) {
                    $scom | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SCOMServerBasic' -Force
                    $scom | Show-Object -Class Hint
                }

                Show-SPNIdleServers -ServiceName 'SCOM' -Server $scomServers
            } else {
                Show-Line "No SCOM Servers found via SPN" -Class "Note"
            }

            # The identity the service authenticates as may be a domain account rather
            # than the machine, and then the SPN is not on a computer object at all.
            Show-SPNServiceAccounts -ServiceName 'SCOM' -SPNFilter "(|(servicePrincipalName=MSOMHSvc/*)(servicePrincipalName=MSOMSdkSvc/*))" `
                -SPNPrefix @('MSOMHSvc/', 'MSOMSdkSvc/') -ConnectionParams $PSBoundParameters
        } catch {
            Write-Log "[Get-InfrastructureServers] SCOM Server enumeration failed: $_" -Level Error
            Show-Line "SCOM Server enumeration failed - result unknown, not empty" -Class "Note"
        }

        # ===== AD FS (Active Directory Federation Services) =====
        Show-SubHeader "Searching for AD FS..." -ObjectType "ADFSServer"

        try {
            $adfsIndicators = @()

            # The DKM container. AD FS stores the key that its token-signing certificate is
            # encrypted with as an attribute of a contact object under
            # CN=ADFS,CN=Microsoft,CN=Program Data,<domainDN>. Its existence is the one
            # domain-side fact that says AD FS is deployed here, independent of any SPN.
            #
            # It matters more than the inventory entry suggests: whoever reads that key,
            # together with the AD FS configuration database, can mint SAML tokens for any
            # user in the federation - Golden SAML - and that is authentication into the
            # cloud tenant that no on-premises password reset and no MFA on the IdP undoes.
            $domainDN = $Script:LDAPContext.DomainDN
            if ($domainDN) {
                $dkmBase = "CN=ADFS,CN=Microsoft,CN=Program Data,$domainDN"
                $dkmObjects = @()
                try {
                    $dkmObjects = @(Get-DomainObject -LDAPFilter "(objectClass=contact)" -SearchBase $dkmBase @PSBoundParameters)
                } catch {
                    # An absent container is the normal case in a domain without AD FS and
                    # must not read as an error
                    Write-Log "[Get-InfrastructureServers] No AD FS DKM container under $dkmBase : $_"
                }

                if ($dkmObjects.Count -gt 0) {
                    # This row is a place in the directory, not an account, and it is named
                    # like the other synthetic rows in the reports - the LAPS OU rows, the
                    # trust rows - after what it is rather than with a bare 'Name'.
                    $dkmObject = [PSCustomObject]@{
                        adfsContainer    = 'AD FS DKM container'
                        containerDN      = $dkmBase
                        dkmKeyObjects    = @($dkmObjects).Count
                        adfsDkmContainer = 'AD FS stores the decryption key for its token-signing certificate here. Whoever can read this key and reach the AD FS configuration database can sign SAML tokens for any federated user, which is authentication into the connected cloud tenant that changing on-premises passwords does not revoke.'
                    }
                    $dkmObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'ADFSServer' -Force
                    $adfsIndicators += $dkmObject
                }
            }

            # The servers themselves, by their service SPN. Under its own try for the same
            # reason the sections have one each: the two halves are independent evidence,
            # and a failing computer query must not discard a DKM container already found.
            try {
                foreach ($adfsServer in @(Get-DomainComputer -KnownSPN ADFS @PSBoundParameters | Test-AccountActivity -IsEnabled)) {
                    $adfsServer | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'ADFSServer' -Force
                    $adfsIndicators += $adfsServer
                }
            } catch {
                Write-Log "[Get-InfrastructureServers] AD FS server lookup failed: $_" -Level Error
                Show-Line "AD FS servers could not be enumerated - the DKM container below, if any, still stands" -Class "Note"
            }

            if ($adfsIndicators.Count -gt 0) {
                Show-Line "Found $($adfsIndicators.Count) AD FS indicator(s):" -Class "Hint"
                foreach ($adfsIndicator in $adfsIndicators) {
                    $adfsIndicator | Show-Object -Class Hint
                }
            } else {
                Show-Line "No AD FS deployment found" -Class "Note"
            }
        } catch {
            Write-Log "[Get-InfrastructureServers] AD FS enumeration failed: $_" -Level Error
            Show-Line "AD FS enumeration failed - result unknown, not empty" -Class "Note"
        }

        # ===== Entra ID Connect (Azure AD Connect) =====
        Show-SubHeader "Searching for Entra ID Connect..." -ObjectType "EntraConnect"

        try {
            $entraConnectIndicators = @()

            # Method 1: Look for MSOL_ accounts (service accounts created by Azure AD Connect)
            $msolAccounts = @(Get-DomainUser -LDAPFilter "(sAMAccountName=MSOL_*)" @PSBoundParameters)
            if ($msolAccounts.Count -gt 0) {
                $entraConnectIndicators += $msolAccounts
            }

            # Method 2: Look for ADSync service accounts
            $adsyncAccounts = @(Get-DomainUser -LDAPFilter "(|(sAMAccountName=ADSync*)(sAMAccountName=AAD_*))" @PSBoundParameters)
            if ($adsyncAccounts.Count -gt 0) {
                $entraConnectIndicators += $adsyncAccounts
            }

            # Method 3: Look for Entra Connect health agent SPN
            $entraHealthServers = @(Get-DomainComputer -LDAPFilter "(servicePrincipalName=*azureadconnect*)" @PSBoundParameters |
                Test-AccountActivity -IsEnabled)
            if ($entraHealthServers.Count -gt 0) {
                $entraConnectIndicators += $entraHealthServers
            }

            if ($entraConnectIndicators.Count -gt 0) {
                Show-Line "Found $($entraConnectIndicators.Count) Entra ID Connect indicator(s):" -Class "Hint"
                foreach ($indicator in $entraConnectIndicators) {
                    # Parse description to extract server name and tenant
                    # Pattern: "...running on computer SERVERNAME configured to synchronize to tenant TENANT.onmicrosoft.com..."
                    if ($indicator.description -match 'running on computer\s+(\S+)\s+configured to synchronize to tenant\s+(\S+)') {
                        $entraServerName = $Matches[1]

                        # TrimEnd('.'): the tenant name ends the sentence in the
                        # description - "...to tenant contoso.onmicrosoft.com. This account
                        # must..." - and \S+ swallows the full stop along with it, because a
                        # period is not whitespace. The server name is anchored by the
                        # "configured" that follows it and needs no such trim. A tenant name
                        # never legitimately ends in a dot, and the value is one a tester
                        # copies straight into another tool.
                        $entraTenant = ([string]$Matches[2]).TrimEnd('.')

                        # Add parsed information as NoteProperties
                        $indicator | Add-Member -NotePropertyName 'entraConnectServer' -NotePropertyValue $entraServerName -Force
                        $indicator | Add-Member -NotePropertyName 'entraM365Tenant' -NotePropertyValue $entraTenant -Force
                    }

                    $indicator | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'EntraConnect' -Force
                    $indicator | Show-Object -Class Hint
                }
            } else {
                Show-Line "No Entra ID Connect servers found" -Class "Note"
            }
        } catch {
            Write-Log "[Get-InfrastructureServers] Entra ID Connect enumeration failed: $_" -Level Error
            Show-Line "Entra ID Connect enumeration failed - result unknown, not empty" -Class "Note"
        }
    }

    end {
        Write-Log "[Get-InfrastructureServers] Check completed"
    }
}
