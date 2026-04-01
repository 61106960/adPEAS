function Get-InfrastructureServers {
    <#
    .SYNOPSIS
    Identifies infrastructure servers via SPN analysis.

    .DESCRIPTION
    Enumerates critical infrastructure servers by analyzing Service Principal Names (SPNs) registered on computer accounts.

    Detected Server Types:
    - Domain Controllers (ldap/, gc/, DNS/)
    - Exchange Servers (exchangeAB/, exchangeRFR/, exchangeMDB/)
    - MSSQL Servers (MSSQLSvc/)
    - SCCM/ConfigMgr (SMS*, CCM*)
    - SCOM (MSOMHSvc/, MSOMSdkSvc/)
    - Entra ID Connect (azureadconnect, ADSync)

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
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            # ===== Domain Controllers =====
            Show-SubHeader "Searching for Domain Controllers..." -ObjectType "DomainController"

            $domainControllers = @(Get-DomainComputer -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=8192))" @PSBoundParameters | Test-AccountActivity -IsEnabled)

            if ($domainControllers.Count -gt 0) {
                Show-Line "Found $($domainControllers.Count) Domain Controller(s):" -Class "Hint"
                foreach ($dc in $domainControllers) {
                    $dc | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'DomainController' -Force
                    $dc | Show-Object
                }
            } else {
                Show-Line "No Domain Controllers found (unexpected)" -Class "Note"
            }

            # ===== Exchange Servers =====
            Show-SubHeader "Searching for Exchange Servers..." -ObjectType "ExchangeServer"

            # Detect Exchange servers via "Exchange Servers" group membership
            $exchangeServers = @()
            $exchangeServersGroup = @(Get-DomainGroup -Identity "Exchange Servers" @PSBoundParameters)[0]
            if ($exchangeServersGroup -and $exchangeServersGroup.member) {
                foreach ($memberDN in @($exchangeServersGroup.member)) {
                    $memberObj = @(Get-DomainObject -Identity $memberDN @PSBoundParameters)[0]
                    if ($memberObj -and $memberObj.objectClass -icontains "computer") {
                        $exchangeServers += $memberObj
                    }
                }
            }
            # Filter for enabled servers only
            $exchangeServers = @($exchangeServers | Test-AccountActivity -IsEnabled)

            if ($exchangeServers.Count -gt 0) {
                Show-Line "Found $($exchangeServers.Count) Exchange Server(s):" -Class "Hint"
                foreach ($exch in $exchangeServers) {
                    $exch | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'ExchangeServerBasic' -Force
                    $exch | Show-Object
                }
            } else {
                Show-Line "No Exchange Servers found" -Class "Note"
            }

            # ===== MSSQL Servers =====
            Show-SubHeader "Searching for MSSQL Servers..." -ObjectType "MSSQLServer"

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

            # ===== SCCM/ConfigMgr Servers =====
            Show-SubHeader "Searching for SCCM/ConfigMgr Servers..." -ObjectType "SCCMServerBasic"

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

            # ===== SCOM Servers =====
            Show-SubHeader "Searching for SCOM Servers..." -ObjectType "SCOMServerBasic"

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

            # ===== Entra ID Connect (Azure AD Connect) =====
            Show-SubHeader "Searching for Entra ID Connect..." -ObjectType "EntraConnect"

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
            Write-Log "[Get-InfrastructureServers] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-InfrastructureServers] Check completed"
    }
}
