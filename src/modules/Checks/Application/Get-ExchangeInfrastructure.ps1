function Get-ExchangeInfrastructure {
    <#
    .SYNOPSIS
    Detects Microsoft Exchange Server infrastructure and security issues via LDAP.

    .DESCRIPTION
    Performs passive detection of Exchange Server infrastructure using LDAP queries only.
    Identifies Exchange organization, servers, versions, privileged groups (especially
    Exchange Trusted Subsystem with WriteDacl on Domain!), shared mailboxes, and service accounts.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-ExchangeInfrastructure
    Performs Exchange infrastructure detection and security analysis.

    .EXAMPLE
    Get-ExchangeInfrastructure -Domain "contoso.com" -Credential (Get-Credential)
    Performs Exchange detection with explicit credentials.

    .NOTES
    Category: Application
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
        Write-Log "[Get-ExchangeInfrastructure] Starting check"
    }

    process {
        function Convert-ExchangeBuildToVersion {
            param([string]$BuildNumber)

            if (-not $BuildNumber) { return $null }

            $normalizedVersion = Get-NormalizedExchangeVersion -BuildNumber $BuildNumber

            if ($normalizedVersion) {
                # Convert lifecycle key to display name (add "Server" for consistency)
                return $normalizedVersion -replace '^Exchange ', 'Exchange Server '
            }

            return "Unknown Exchange Version"
        }

        # Helper function to get version severity class
        function Get-ExchangeVersionClass {
            param([string]$BuildNumber)

            if (-not $BuildNumber) { return "Standard" }

            return Get-ExchangeSeverity -BuildNumber $BuildNumber
        }

        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            # Get Configuration DN from context
            $configDN = $Script:LDAPContext.ConfigurationNamingContext

            # ===== Step 1: Check for Exchange Organization (internal, no output) =====
            $exchangeOrgExists = $false
            $organizationName = $null

            try {
                # Use Get-DomainObject to check for Exchange Organization container
                $exchangeOrgs = Get-DomainObject -LDAPFilter "(objectClass=msExchOrganizationContainer)" -SearchBase "CN=Microsoft Exchange,CN=Services,$configDN" @PSBoundParameters

                if ($exchangeOrgs) {
                    $exchangeOrgExists = $true

                    if ($exchangeOrgs -is [Array]) {
                        $organizationName = $exchangeOrgs[0].cn
                    } else {
                        $organizationName = $exchangeOrgs.cn
                    }
                }
            }
            catch {
                Write-Log "[Get-ExchangeInfrastructure] Exchange Organization not Found: $_"
            }

            if (-not $exchangeOrgExists) {
                Show-SubHeader "Checking for Exchange Organization..." -ObjectType "ExchangeServer"
                Show-Line "No Exchange Organization detected" -Class Note
                return
            }

            # ===== Step 1b: Exchange Organization Overview (Config Partition - forest-wide) =====
            # Queries the Configuration partition which is visible from any domain in the forest.
            # Outputs: 1 global Organization card + 1 card per Exchange server with VDirs/Connectors.
            Show-SubHeader "Checking Exchange Organization..." -ObjectType "ExchangeOrganization"

            $exchangeBase = "CN=Microsoft Exchange,CN=Services,$configDN"

            # --- Phase 1: Query all Config Partition data upfront ---
            $realServers = @()
            $allVDirs = @()
            $allRecvConnectors = @()
            $allSendConnectors = @()
            $allAcceptedDomains = @()

            try {
                # Exchange Servers: msExchExchangeServer includes role containers (Mailbox, Frontend).
                # Real servers have DN: CN=<name>,CN=Servers,CN=... (direct children of CN=Servers)
                # Role containers have DN: CN=Mailbox,CN=Transport Configuration,CN=<name>,CN=Servers,...
                $configServers = @(Get-DomainObject -LDAPFilter "(objectClass=msExchExchangeServer)" -SearchBase $exchangeBase @PSBoundParameters)
                $realServers = @($configServers | Where-Object {
                    $_.distinguishedName -match "CN=$([regex]::Escape($_.name)),CN=Servers,"
                })
            } catch {
                Write-Log "[Get-ExchangeInfrastructure] Error querying Config partition servers: $_" -Level Error
            }

            try {
                $vdirParts = @(
                    "(objectClass=msExchOWAVirtualDirectory)", "(objectClass=msExchECPVirtualDirectory)",
                    "(objectClass=msExchWebServicesVirtualDirectory)", "(objectClass=msExchActiveSyncVirtualDirectory)",
                    "(objectClass=msExchAutoDiscoverVirtualDirectory)", "(objectClass=msExchMapiVirtualDirectory)",
                    "(objectClass=msExchPowerShellVirtualDirectory)", "(objectClass=msExchRpcHttpVirtualDirectory)"
                )
                $vdirFilter = '(|' + ($vdirParts -join '') + ')'
                $allVDirs = @(Get-DomainObject -LDAPFilter $vdirFilter -SearchBase $exchangeBase @PSBoundParameters)
            } catch {
                Write-Log "[Get-ExchangeInfrastructure] Error querying Virtual Directories: $_" -Level Error
            }

            try {
                $allRecvConnectors = @(Get-DomainObject -LDAPFilter "(objectClass=msExchSmtpReceiveConnector)" -SearchBase $exchangeBase @PSBoundParameters)
            } catch {
                Write-Log "[Get-ExchangeInfrastructure] Error querying SMTP Receive Connectors: $_" -Level Error
            }

            try {
                $allSendConnectors = @(Get-DomainObject -LDAPFilter "(objectClass=msExchRoutingSMTPConnector)" -SearchBase $exchangeBase @PSBoundParameters)
            } catch {
                Write-Log "[Get-ExchangeInfrastructure] Error querying SMTP Send Connectors: $_" -Level Error
            }

            try {
                $allAcceptedDomains = @(Get-DomainObject -LDAPFilter "(objectClass=msExchAcceptedDomain)" -SearchBase $exchangeBase @PSBoundParameters)
            } catch {
                Write-Log "[Get-ExchangeInfrastructure] Error querying Accepted Domains: $_" -Level Error
            }

            # --- Phase 2: Global Organization Card ---
            $orgObj = [PSCustomObject]@{
                Name = $organizationName
                OrganizationName = $organizationName
            }

            if ($realServers.Count -gt 0) {
                $orgObj | Add-Member -NotePropertyName 'ExchangeServerCount' -NotePropertyValue "$($realServers.Count) server(s)" -Force
            }

            if (@($allAcceptedDomains).Count -gt 0) {
                $typeMap = @{ 0 = "Authoritative"; 1 = "InternalRelay"; 2 = "ExternalRelay" }
                $adLines = @()
                foreach ($ad in $allAcceptedDomains) {
                    $domainType = $typeMap[[int]$ad.msExchAcceptedDomainType]
                    if (-not $domainType) { $domainType = "Unknown" }
                    $adLines += "$($ad.msExchAcceptedDomainName) ($domainType)"
                }
                $orgObj | Add-Member -NotePropertyName 'AcceptedDomains' -NotePropertyValue $adLines -Force
            }

            if (@($allSendConnectors).Count -gt 0) {
                $scLines = @()
                foreach ($sc in $allSendConnectors) {
                    $addrSpaces = $sc.msExchConnectorAddressSpaces
                    $addrInfo = if ($addrSpaces) { " ($addrSpaces)" } else { "" }
                    $scLines += "$($sc.name)$addrInfo"
                }
                $orgObj | Add-Member -NotePropertyName 'SMTPSendConnectors' -NotePropertyValue $scLines -Force
            }

            $orgObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'ExchangeOrganization' -Force
            Show-Line "Exchange Organization found in Configuration partition" -Class Hint
            Show-Object $orgObj

            # --- Phase 3: Per-Server Config Cards ---
            foreach ($srv in $realServers) {
                $srvName = $srv.name
                $srvDN = $srv.distinguishedName

                # Extract FQDN from networkAddress (ncacn_ip_tcp:srvex.sturz.org)
                $fqdn = $srvName
                $netAddr = $srv.networkAddress
                if ($netAddr) {
                    $addrStr = if ($netAddr -is [array]) { $netAddr -join ' ' } else { [string]$netAddr }
                    if ($addrStr -match 'ncacn_ip_tcp:([^\s]+)') { $fqdn = $Matches[1] }
                }

                # Extract Exchange version from serialNumber (e.g., "Version 15.2 (Build 32562.17)")
                # Note: The build number from Config partition reflects the schema version, not the actual installed CU/patch level
                $sn = $srv.serialNumber
                $exchVersion = if ($sn) { [string]$sn } else { "Unknown" }
                # Extract build number for EOL lifecycle check (e.g., "15.2.32562.17")
                $exchBuildNumber = $null
                if ($sn -match 'Version (\d+)\.(\d+).*Build (\d+)\.(\d+)') {
                    $exchBuildNumber = "$($Matches[1]).$($Matches[2]).$($Matches[3]).$($Matches[4])"
                }

                # Extract domain from Config DN (DC= components after CN=Configuration)
                $serverDomain = $null
                if ($srvDN -match 'CN=Configuration,(.+)$') {
                    $dcPart = $Matches[1]
                    $serverDomain = ($dcPart -replace 'DC=', '' -replace ',', '.')
                }

                $srvObj = [PSCustomObject]@{
                    Name = $srvName
                    dNSHostName = $fqdn
                    ExchangeVersion = $exchVersion
                }

                if ($exchBuildNumber) {
                    $srvObj | Add-Member -NotePropertyName 'ExchangeBuildNumber' -NotePropertyValue $exchBuildNumber -Force
                }
                if ($serverDomain) {
                    $srvObj | Add-Member -NotePropertyName 'forestRootDomain' -NotePropertyValue $serverDomain -Force
                }
                $srvObj | Add-Member -NotePropertyName 'distinguishedName' -NotePropertyValue $srvDN -Force

                # Map VDirs to this server (DN contains CN=<srvName>,CN=Servers)
                $escapedSrvName = [regex]::Escape($srvName)
                $srvVDirs = @($allVDirs | Where-Object {
                    $_.distinguishedName -match "CN=$escapedSrvName,CN=Servers,"
                })
                if ($srvVDirs.Count -gt 0) {
                    $vdirTypes = [ordered]@{}
                    $externalUrls = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                    foreach ($vdir in $srvVDirs) {
                        # Skip VDirs without any configured URL (e.g., "Exchange Back End" entries)
                        if (-not $vdir.msExchInternalHostName -and -not $vdir.msExchExternalHostName) { continue }
                        $vdirClass = if ($vdir.objectClass -is [array]) { $vdir.objectClass[-1] } else { $vdir.objectClass }
                        $shortType = $vdirClass -replace 'msExch|VirtualDirectory', ''
                        if (-not $vdirTypes.Contains($shortType)) { $vdirTypes[$shortType] = $true }
                        if ($vdir.msExchExternalHostName) {
                            try { [void]$externalUrls.Add(([uri]$vdir.msExchExternalHostName).Host) } catch {}
                        }
                    }
                    if ($vdirTypes.Count -gt 0) {
                        $srvObj | Add-Member -NotePropertyName 'VirtualDirectories' -NotePropertyValue (($vdirTypes.Keys | Sort-Object) -join ', ') -Force
                    }
                    if ($externalUrls.Count -gt 0) {
                        $srvObj | Add-Member -NotePropertyName 'ExternalHostnames' -NotePropertyValue ($externalUrls -join ', ') -Force
                    }
                }

                # Map SMTP Receive Connectors to this server
                $srvRecvConn = @($allRecvConnectors | Where-Object {
                    $_.distinguishedName -match "CN=$escapedSrvName,CN=Servers,"
                })
                if ($srvRecvConn.Count -gt 0) {
                    $srvObj | Add-Member -NotePropertyName 'SMTPReceiveConnectors' -NotePropertyValue "$($srvRecvConn.Count) connector(s)" -Force
                    $listeningPorts = [System.Collections.Generic.HashSet[string]]::new()
                    foreach ($rc in $srvRecvConn) {
                        $bindings = $rc.msExchSMTPReceiveBindings
                        if ($bindings) {
                            $bindStr = if ($bindings -is [array]) { $bindings -join ' ' } else { [string]$bindings }
                            $portMatches = [regex]::Matches($bindStr, ':(\d+)')
                            foreach ($pm in $portMatches) { [void]$listeningPorts.Add($pm.Groups[1].Value) }
                        }
                    }
                    if ($listeningPorts.Count -gt 0) {
                        $sortedPorts = $listeningPorts | Sort-Object { [int]$_ }
                        $srvObj | Add-Member -NotePropertyName 'SMTPListeningPorts' -NotePropertyValue ($sortedPorts -join ', ') -Force
                    }
                }

                $srvObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'ExchangeConfigServer' -Force
                Show-Object $srvObj
            }

            # ===== Step 2: Enumerate Exchange Servers (Domain Partition - detailed) =====
            Show-SubHeader "Searching for Exchange servers..." -ObjectType "ExchangeServer"

            $exchangeServers = @()

            try {
                # Filter requires msExchCurrentServerRoles to have a value > 0 (valid Exchange role)
                $servers = Get-DomainComputer -LDAPFilter "(msExchCurrentServerRoles>=1)" @PSBoundParameters

                # Also check for Exchange Servers group membership
                $groupMembers = @()
                $exchangeServersGroup = @(Get-DomainGroup -Identity "Exchange Servers" @PSBoundParameters)[0]

                if ($exchangeServersGroup -and $exchangeServersGroup.member) {
                    foreach ($memberDN in $exchangeServersGroup.member) {
                        $memberObj = @(Get-DomainObject -Identity $memberDN @PSBoundParameters)[0]
                        if ($memberObj -and $memberObj.objectClass -icontains "computer") {
                            $groupMembers += $memberObj
                        }
                    }
                }

                # Merge results: servers from attributes + servers from group membership
                # Group membership is authoritative - if a computer is in "Exchange Servers" group, it's an Exchange server
                $allServers = @{}

                # Add servers found via attributes
                foreach ($srv in $servers) {
                    $key = if ($srv.distinguishedName) { $srv.distinguishedName } else { $srv.cn }
                    if (-not $allServers.ContainsKey($key)) {
                        $allServers[$key] = $srv
                    }
                }

                # Add servers found via group membership (these are authoritative)
                foreach ($srv in $groupMembers) {
                    $key = if ($srv.distinguishedName) { $srv.distinguishedName } else { $srv.cn }
                    if (-not $allServers.ContainsKey($key)) {
                        $allServers[$key] = $srv
                    }
                }

                $validServers = @($allServers.Values)

                foreach ($rawServer in $validServers) {
                    $rolesValue = if ($rawServer.msExchCurrentServerRoles) {
                        [int]$rawServer.msExchCurrentServerRoles
                    } else { 0 }

                    $versionValue = if ($rawServer.msExchVersion) {
                        [long]$rawServer.msExchVersion
                    } else { 0 }

                    # Decode server roles (bitfield)
                    $roles = @()
                    if ($rolesValue -band 2) { $roles += "Mailbox" }
                    if ($rolesValue -band 4) { $roles += "ClientAccess" }
                    if ($rolesValue -band 16) { $roles += "UnifiedMessaging" }
                    if ($rolesValue -band 32) { $roles += "HubTransport" }
                    if ($rolesValue -band 64) { $roles += "EdgeTransport" }

                    # Decode Exchange version. Major.Minor.Build.Revision encoded in long integer
                    # High 4 bits = Major, next 6 bits = Minor
                    $major = ($versionValue -shr 22) -band 0x3F
                    $minor = ($versionValue -shr 16) -band 0x3F
                    $build = ($versionValue -shr 0) -band 0xFFFF

                    $versionString = "$major.$minor.$build.0"

                    # Use the same Convert function for LDAP fallback
                    $exchangeVersion = Convert-ExchangeBuildToVersion -BuildNumber $versionString
                    $versionClass = Get-ExchangeVersionClass -BuildNumber $versionString
                    $isEOL = ($versionClass -eq "Finding")

                    $serverObj = [PSCustomObject]@{
                        ComputerName = if ($rawServer.cn) { $rawServer.cn } else { "Unknown" }
                        DNSHostName = if ($rawServer.dNSHostName) { $rawServer.dNSHostName } else { "Unknown" }
                        OperatingSystem = if ($rawServer.operatingSystem) { $rawServer.operatingSystem } else { "Unknown" }
                        Roles = $roles
                        RolesValue = $rolesValue
                        ExchangeVersion = $exchangeVersion
                        VersionString = $versionString
                        VersionValue = $versionValue
                        IsEOL = $isEOL
                        SPNs = @($rawServer.servicePrincipalName | Where-Object { $_ -match 'exchange|SMTP|HTTP' })
                        RawObject = $rawServer  # Store original object for Show-Object display
                    }

                    $exchangeServers += $serverObj
                }
            }
            catch {
                Write-Log "[Get-ExchangeInfrastructure] Error enumerating Exchange servers: $_" -Level Error
            }

            if (@($exchangeServers).Count -gt 0) {
                Show-Line "Exchange Organization: $organizationName - Found $(@($exchangeServers).Count) Exchange Server(s)" -Class Hint

                foreach ($exServer in $exchangeServers) {
                    # Get the raw object to add Exchange-specific attributes
                    $serverObject = $exServer.RawObject

                    if ($serverObject) {
                        # ===== HTTP-based Version Detection and Web Endpoint Analysis =====
                        # Try to get exact build number via HTTP/S, detect available endpoints,
                        # authentication methods, and EPA status - skip inactive servers to avoid timeouts
                        $webEnrollmentResult = $null

                        if ($exServer.DNSHostName -and $exServer.DNSHostName -ne "Unknown") {
                            # Check if server is inactive using Test-AccountActivity helper (uses $Script:DefaultInactiveDays)
                            $isInactive = $null -ne ($serverObject | Test-AccountActivity -IsInactive)

                            if ($isInactive) {
                                Write-Log "[Get-ExchangeInfrastructure] Skipping HTTP check for $($exServer.DNSHostName) - server inactive"
                                $serverObject | Add-Member -NotePropertyName "HttpCheckSkipped" -NotePropertyValue "Server inactive (no recent logon)" -Force
                            } else {
                                # Fast TCP reachability check before expensive HTTP tests
                                # This avoids multiple 3-second timeouts for unreachable servers
                                $tcpReachable = $false
                                $tcpClient = $null
                                try {
                                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                                    $connectResult = $tcpClient.BeginConnect($exServer.DNSHostName, 443, $null, $null)
                                    $tcpReachable = $connectResult.AsyncWaitHandle.WaitOne(2000, $false)  # 2 second timeout
                                    if ($tcpReachable) {
                                        $tcpClient.EndConnect($connectResult)
                                    }
                                }
                                catch {
                                    Write-Log "[Get-ExchangeInfrastructure] TCP check failed for $($exServer.DNSHostName): $_"
                                    $tcpReachable = $false
                                }
                                finally {
                                    if ($tcpClient) {
                                        try { $tcpClient.Close() } catch { }
                                        try { $tcpClient.Dispose() } catch { }
                                    }
                                }

                                if (-not $tcpReachable) {
                                    Write-Log "[Get-ExchangeInfrastructure] Skipping HTTP check for $($exServer.DNSHostName) - TCP port 443 not reachable"
                                    $serverObject | Add-Member -NotePropertyName "HttpCheckSkipped" -NotePropertyValue "Server not reachable (TCP 443 timeout)" -Force
                                } else {
                                    Write-Log "[Get-ExchangeInfrastructure] Detecting Exchange endpoints and EPA for $($exServer.DNSHostName)..."

                                    try {
                                        # Request with -TestEPA to check Extended Protection for Authentication
                                        $httpResult = Invoke-HTTPRequest -ScanExchange -Uri $exServer.DNSHostName -TestEPA
                                        $webEnrollmentResult = $httpResult

                                        if ($httpResult.Success) {
                                            $httpBuildNumber = $httpResult.BuildNumber
                                            $httpVersion = Convert-ExchangeBuildToVersion -BuildNumber $httpBuildNumber
                                            Write-Log "[Get-ExchangeInfrastructure] HTTP detection successful: $httpBuildNumber"

                                            # Add ExchangeVersion and ExchangeBuildNumber as properties to the object
                                            if ($httpBuildNumber) {
                                                $serverObject | Add-Member -NotePropertyName "ExchangeVersion" -NotePropertyValue $httpVersion -Force
                                                $serverObject | Add-Member -NotePropertyName "ExchangeBuildNumber" -NotePropertyValue $httpBuildNumber -Force
                                            }

                                            # Log EPA detection result
                                            if ($null -ne $httpResult.EPAEnabled) {
                                                Write-Log "[Get-ExchangeInfrastructure] EPA detection: Enabled=$($httpResult.EPAEnabled), Confidence=$($httpResult.EPAConfidence)"
                                            }
                                        }
                                    }
                                    catch {
                                        Write-Log "[Get-ExchangeInfrastructure] HTTP detection failed: $_"
                                    }
                                }
                            }
                        }

                        # Add roles if available
                        if ($exServer.Roles -and @($exServer.Roles).Count -gt 0) {
                            $serverObject | Add-Member -NotePropertyName "ExchangeRoles" -NotePropertyValue ($exServer.Roles -join ', ') -Force
                        }

                        # Add protocol availability
                        if ($webEnrollmentResult) {
                            $serverObject | Add-Member -NotePropertyName "HttpAvailable" -NotePropertyValue $webEnrollmentResult.HttpAvailable -Force
                            $serverObject | Add-Member -NotePropertyName "HttpsAvailable" -NotePropertyValue $webEnrollmentResult.HttpsAvailable -Force

                            # Build WebEndpoints array with auth methods and EPA status
                            # Format: "OWA via HTTPS (NTLM, Negotiate) [EPA: Disabled]"
                            # Show HTTP and HTTPS as separate lines (EPA only relevant for HTTPS)
                            $activeEndpoints = @()
                            $endpointAuthMethods = @{}

                            foreach ($ep in @('OWA', 'ECP', 'EWS', 'Autodiscover', 'MAPI', 'RPC', 'PowerShell', 'ActiveSync')) {
                                if ($webEnrollmentResult.Endpoints.$ep.Available) {
                                    $activeEndpoints += $ep
                                    if ($webEnrollmentResult.Endpoints.$ep.AuthMethods) {
                                        $endpointAuthMethods[$ep] = $webEnrollmentResult.Endpoints.$ep.AuthMethods
                                    }
                                }
                            }

                            if (@($activeEndpoints).Count -gt 0) {
                                $endpointsWithAuth = @()
                                $httpAvailable = $webEnrollmentResult.HttpAvailable
                                $httpsAvailable = $webEnrollmentResult.HttpsAvailable

                                foreach ($ep in $activeEndpoints) {
                                    $authMethods = $endpointAuthMethods[$ep]
                                    $epData = $webEnrollmentResult.Endpoints.$ep

                                    # Show HTTP line if HTTP is available (no EPA - not applicable for HTTP)
                                    if ($httpAvailable) {
                                        $epString = "$ep via HTTP"
                                        if ($authMethods) {
                                            $epString += " ($authMethods)"
                                        }
                                        $endpointsWithAuth += $epString
                                    }

                                    # Show HTTPS line if HTTPS is available (with EPA status if tested)
                                    if ($httpsAvailable) {
                                        $epString = "$ep via HTTPS"
                                        if ($authMethods) {
                                            $epString += " ($authMethods)"
                                        }
                                        # Add EPA status only for HTTPS (EPA is TLS-based)
                                        if ($null -ne $epData.EPAEnabled) {
                                            $epaStatus = if ($epData.EPAEnabled -eq $true) { "Enabled" } else { "Disabled" }
                                            $epString += " [EPA: $epaStatus]"
                                        }
                                        $endpointsWithAuth += $epString
                                    }
                                }

                                $serverObject | Add-Member -NotePropertyName 'WebEndpoints' -NotePropertyValue $endpointsWithAuth -Force
                            }

                            # Add legacy EPA properties (for quick reference)
                            if ($null -ne $webEnrollmentResult.EPAEnabled) {
                                $serverObject | Add-Member -NotePropertyName 'EPAEnabled' -NotePropertyValue $webEnrollmentResult.EPAEnabled -Force
                                $serverObject | Add-Member -NotePropertyName 'EPAConfidence' -NotePropertyValue $webEnrollmentResult.EPAConfidence -Force
                            }
                        }

                        # Add type marker for reliable detection in HTML report
                        $serverObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'ExchangeServer' -Force
                        # Set ExchangeVersion/BuildNumber from LDAP fallback only if HTTP didn't detect them
                        # and only if we actually have a valid version (not "Unknown" or "0.0.0.0")
                        if (-not $serverObject.ExchangeVersion -and $exServer.ExchangeVersion -and $exServer.ExchangeVersion -ne "Unknown Exchange Version") {
                            $serverObject | Add-Member -NotePropertyName "ExchangeVersion" -NotePropertyValue $exServer.ExchangeVersion -Force
                        }
                        if (-not $serverObject.ExchangeBuildNumber -and $exServer.VersionString -and $exServer.VersionString -ne "0.0.0.0") {
                            $serverObject | Add-Member -NotePropertyName "ExchangeBuildNumber" -NotePropertyValue $exServer.VersionString -Force
                        }
                        $displayVersion = if ($serverObject.ExchangeVersion) { $serverObject.ExchangeVersion } else { $exServer.ExchangeVersion }
                        # Only set context if we have a valid version (not "Unknown Exchange Version")
                        if ($displayVersion -and $displayVersion -ne "Unknown Exchange Version") {
                            $serverObject | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue $displayVersion -Force
                        }

                        # Output the enriched server object via Show-Object
                        Show-Object $serverObject
                    } else {
                        # Fallback: show basic info if RawObject not available
                        Show-KeyValue "ComputerName" -Value $exServer.ComputerName
                        if ($exServer.DNSHostName -and $exServer.DNSHostName -ne "Unknown") {
                            Show-KeyValue "DNSHostName" -Value $exServer.DNSHostName
                        }
                    }
                }
            } else {
                Show-Line "Exchange Organization: $organizationName - No active Exchange Servers found" -Class Note
            }

            # ===== Step 3: Check Exchange Trusted Subsystem =====
            Show-SubHeader "Checking Exchange Trusted Subsystem group..." -ObjectType "ExchangeTrustedSubsystem"

            try {
                # Use Get-DomainGroup to find Exchange Trusted Subsystem
                $trustedSubsystem = @(Get-DomainGroup -Identity "Exchange Trusted Subsystem" @PSBoundParameters)[0]

                if ($trustedSubsystem) {
                    $members = @($trustedSubsystem.member)

                    if (@($members).Count -gt 0) {
                        Show-Line "Found $(@($members).Count) member(s) in Exchange Trusted Subsystem:" -Class Hint

                        foreach ($memberDN in $members) {
                            # Use Get-DomainObject to retrieve full member object
                            try {
                                $memberObj = @(Get-DomainObject -Identity $memberDN @PSBoundParameters)[0]

                                if ($memberObj) {
                                    # Add type marker for reliable detection in HTML report
                                    $memberObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'ExchangeTrustedSubsystem' -Force
                                    $memberObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'Exchange Trusted Subsystem' -Force
                                    Show-Object $memberObj
                                }
                            }
                            catch {
                                Write-Log "[Get-ExchangeInfrastructure] Error resolving member ${memberDN}: ${_}"
                                # Fallback: Extract CN from DN
                                if ($memberDN -match 'CN=([^,]+)') {
                                    Show-Line "$($matches[1])" -Class Note
                                }
                            }
                        }
                    } else {
                        Show-Line "Exchange Trusted Subsystem group exists but has no members (unusual)" -Class Note
                    }
                } else {
                    Write-Log "[Get-ExchangeInfrastructure] Exchange Trusted Subsystem group not Found"
                }
            }
            catch {
                Write-Log "[Get-ExchangeInfrastructure] Error checking Exchange Trusted Subsystem: $_" -Level Error
            }

            # ===== Step 4: Check Exchange Windows Permissions =====
            Show-SubHeader "Checking Exchange Windows Permissions group..." -ObjectType "ExchangeWindowsPermissions"

            try {
                # Use Get-DomainGroup
                $windowsPermissions = @(Get-DomainGroup -Identity "Exchange Windows Permissions" @PSBoundParameters)[0]

                if ($windowsPermissions) {
                    $members = @($windowsPermissions.member)

                    if (@($members).Count -gt 0) {
                        Show-Line "Found $(@($members).Count) member(s) in Exchange Windows Permissions:" -Class Hint

                        foreach ($memberDN in $members) {
                            try {
                                $memberObj = @(Get-DomainObject -Identity $memberDN @PSBoundParameters)[0]

                                if ($memberObj) {
                                    # Add type marker for reliable detection in HTML report
                                    $memberObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'ExchangeWindowsPermissions' -Force
                                    $memberObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'Exchange Windows Permissions' -Force
                                    Show-Object $memberObj
                                }
                            }
                            catch {
                                Write-Log "[Get-ExchangeInfrastructure] Error resolving member ${memberDN}: ${_}"
                                if ($memberDN -match 'CN=([^,]+)') {
                                    Show-Line "$($matches[1])" -Class Note
                                }
                            }
                        }
                    }
                } else {
                    Write-Log "[Get-ExchangeInfrastructure] Exchange Windows Permissions group not found"
                }
            }
            catch {
                Write-Log "[Get-ExchangeInfrastructure] Error checking Exchange Windows Permissions: $_" -Level Error
            }

            # ===== Step 5: Check Organization Management =====
            Show-SubHeader "Checking Organization Management group..." -ObjectType "ExchangeOrganizationManagement"

            try {
                # Use Get-DomainGroup
                $orgManagement = @(Get-DomainGroup -Identity "Organization Management" @PSBoundParameters)[0]

                if ($orgManagement) {
                    $members = @($orgManagement.member)

                    if (@($members).Count -gt 0) {
                        Show-Line "Found $(@($members).Count) member(s) in Organization Management:" -Class Hint

                        foreach ($memberDN in $members) {
                            try {
                                $memberObj = @(Get-DomainObject -Identity $memberDN @PSBoundParameters)[0]

                                if ($memberObj) {
                                    # Add type marker for reliable detection in HTML report
                                    $memberObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'ExchangeOrganizationManagement' -Force
                                    $memberObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'Organization Management' -Force
                                    Show-Object $memberObj
                                }
                            }
                            catch {
                                Write-Log "[Get-ExchangeInfrastructure] Error resolving member ${memberDN}: ${_}"
                                if ($memberDN -match 'CN=([^,]+)') {
                                    Show-Line "$($matches[1])" -Class Note
                                }
                            }
                        }
                    } else {
                        Show-Line "Organization Management group exists but has no members (unusual)" -Class Note
                    }
                }
            }
            catch {
                Write-Log "[Get-ExchangeInfrastructure] Error checking Organization Management: $_" -Level Error
            }

            # ===== Summary & Recommendations =====
            # No additional summary needed - org info is shown with server count in Step 2

        }
        catch {
            Write-Log "[Get-ExchangeInfrastructure] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-ExchangeInfrastructure] Check completed"
    }
}
