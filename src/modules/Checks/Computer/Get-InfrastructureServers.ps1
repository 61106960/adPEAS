function Get-InfrastructureServers {
    <#
    .SYNOPSIS
    Inventories the infrastructure servers of the domain.

    .DESCRIPTION
    Enumerates the servers worth knowing about before anything else is analysed. Each kind
    is looked up the way that kind actually records itself, which is not always an SPN.

    Detected Server Types:
    - Domain Controllers (the userAccountControl role bit, via Get-DomainComputer -DomainController)
    - Exchange Servers (msExchExchangeServer objects in the Configuration partition,
      falling back to the exchangeAB/, exchangeRFR/, exchangeMDB/ SPNs)
    - MSSQL Servers (MSSQLSvc/)
    - SCCM/ConfigMgr (SMS*, CCM*)
    - SCOM (MSOMHSvc/, MSOMSdkSvc/)
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

            if ($domainControllers.Count -gt 0) {
                Show-Line "Found $($domainControllers.Count) Domain Controller(s):" -Class "Hint"
                foreach ($dc in $domainControllers) {
                    $dc | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'DomainController' -Force
                    $dc | Show-Object
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
                    $exch | Show-Object
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
            $mssqlServers = @(Get-DomainComputer -LDAPFilter "(servicePrincipalName=MSSQLSvc/*)" @PSBoundParameters | Test-AccountActivity -IsEnabled)

            if ($mssqlServers.Count -gt 0) {
                Show-Line "Found $($mssqlServers.Count) MSSQL Server(s):" -Class "Hint"
                foreach ($sql in $mssqlServers) {
                    $sql | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'MSSQLServer' -Force
                    $sql | Show-Object
                }
            } else {
                Show-Line "No MSSQL Servers found via SPN" -Class "Note"
            }
        } catch {
            Write-Log "[Get-InfrastructureServers] MSSQL Server enumeration failed: $_" -Level Error
            Show-Line "MSSQL Server enumeration failed - result unknown, not empty" -Class "Note"
        }

        # ===== SCCM/ConfigMgr Servers =====
        Show-SubHeader "Searching for SCCM/ConfigMgr Servers..." -ObjectType "SCCMServerBasic"

        try {
            # SCCM SPNs: SMS_Site_*, SMS_MP, SMS_DP, CCMSetup, etc.
            $sccmServers = @(Get-DomainComputer -LDAPFilter "(|(servicePrincipalName=SMS*)(servicePrincipalName=CCM*))" @PSBoundParameters | Test-AccountActivity -IsEnabled)

            if ($sccmServers.Count -gt 0) {
                Show-Line "Found $($sccmServers.Count) SCCM/ConfigMgr Server(s):" -Class "Hint"
                foreach ($sccm in $sccmServers) {
                    $sccm | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SCCMServerBasic' -Force
                    $sccm | Show-Object
                }
            } else {
                Show-Line "No SCCM Servers found via SPN" -Class "Note"
            }
        } catch {
            Write-Log "[Get-InfrastructureServers] SCCM Server enumeration failed: $_" -Level Error
            Show-Line "SCCM Server enumeration failed - result unknown, not empty" -Class "Note"
        }

        # ===== SCOM Servers =====
        Show-SubHeader "Searching for SCOM Servers..." -ObjectType "SCOMServerBasic"

        try {
            # SCOM SPNs: MSOMHSvc (Health Service), MSOMSdkSvc (SDK Service)
            $scomServers = @(Get-DomainComputer -LDAPFilter "(|(servicePrincipalName=MSOMHSvc/*)(servicePrincipalName=MSOMSdkSvc/*))" @PSBoundParameters | Test-AccountActivity -IsEnabled)

            if ($scomServers.Count -gt 0) {
                Show-Line "Found $($scomServers.Count) SCOM Server(s):" -Class "Hint"
                foreach ($scom in $scomServers) {
                    $scom | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SCOMServerBasic' -Force
                    $scom | Show-Object
                }
            } else {
                Show-Line "No SCOM Servers found via SPN" -Class "Note"
            }
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
                    $adfsIndicator | Show-Object
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
                        $entraTenant = $Matches[2]

                        # Add parsed information as NoteProperties
                        $indicator | Add-Member -NotePropertyName 'entraConnectServer' -NotePropertyValue $entraServerName -Force
                        $indicator | Add-Member -NotePropertyName 'entraM365Tenant' -NotePropertyValue $entraTenant -Force
                    }

                    $indicator | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'EntraConnect' -Force
                    $indicator | Show-Object
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
