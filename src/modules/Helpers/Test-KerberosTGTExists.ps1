<#
.SYNOPSIS
    Checks if valid Kerberos tickets exist in the current session's ticket cache.

.DESCRIPTION
    Uses the LSA API to query the Kerberos ticket cache and verify TGT validity.

    Two-stage check:
    1. Quick count check (MessageType 1 - KerbQueryTicketCacheMessage)
    2. If tickets exist: Scan ALL tickets to find TGT (MessageType 14 - KerbQueryTicketCacheExMessage)

    Validates:
    - At least one ticket exists
    - TGT is present (ServerName starts with "krbtgt/")
    - TGT is not expired (EndTime > now)
    - Client matches authenticated user (optional, if LDAPContext available)

    The result is cached in $Script:LDAPContext for performance (60 second validity).

.PARAMETER Force
    Force a fresh check, ignoring any cached result.

.PARAMETER Detailed
    Return detailed ticket information instead of just $true/$false.

.EXAMPLE
    Test-KerberosTGTExists
    Returns $true if a valid TGT exists, $false otherwise.

.EXAMPLE
    Test-KerberosTGTExists -Detailed
    Returns a PSCustomObject with ticket details (ServerName, Realm, EndTime, etc.)

.EXAMPLE
    Test-KerberosTGTExists -Force
    Forces a fresh LSA query, ignoring cached results.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function Test-KerberosTGTExists {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [switch]$Force,

        [Parameter(Mandatory=$false)]
        [switch]$Detailed
    )

    # Check cache first (unless Force is specified)
    if (-not $Force -and $Script:LDAPContext) {
        $lastCheck = $Script:LDAPContext['KerberosLastCheck']
        if ($lastCheck -and ((Get-Date) - $lastCheck).TotalSeconds -lt 60) {
            $cachedValid = $Script:LDAPContext['KerberosValid']
            Write-Log "[Test-KerberosTGTExists] Using cached result: KerberosValid=$cachedValid"
            if ($Detailed) {
                return [PSCustomObject]@{
                    Valid = $cachedValid
                    TicketCount = $Script:LDAPContext['KerberosTicketCount']
                    TGTPresent = $Script:LDAPContext['KerberosTGTPresent']
                    ClientMatch = $Script:LDAPContext['KerberosClientMatch']
                    ServerName = $Script:LDAPContext['KerberosServerName']
                    Realm = $Script:LDAPContext['KerberosRealm']
                    ClientName = $Script:LDAPContext['KerberosClientName']
                    EndTime = $Script:LDAPContext['KerberosEndTime']
                    Expired = $Script:LDAPContext['KerberosExpired']
                    EncryptionType = $Script:LDAPContext['KerberosEncryptionType']
                    TicketFlags = $Script:LDAPContext['KerberosTicketFlags']
                    Cached = $true
                }
            }
            return $cachedValid
        }
    }

    Write-Log "[Test-KerberosTGTExists] Checking Kerberos ticket cache..."

    # Define P/Invoke signatures for LSA API
    $LsaSignatures = @'
        [DllImport("secur32.dll", SetLastError = true)]
        public static extern uint LsaConnectUntrusted(out IntPtr LsaHandle);

        [DllImport("secur32.dll", SetLastError = true)]
        public static extern uint LsaLookupAuthenticationPackage(
            IntPtr LsaHandle,
            ref LSA_STRING PackageName,
            out uint AuthenticationPackage);

        [DllImport("secur32.dll", SetLastError = true)]
        public static extern uint LsaCallAuthenticationPackage(
            IntPtr LsaHandle,
            uint AuthenticationPackage,
            IntPtr ProtocolSubmitBuffer,
            uint SubmitBufferLength,
            out IntPtr ProtocolReturnBuffer,
            out uint ReturnBufferLength,
            out int ProtocolStatus);

        [DllImport("secur32.dll", SetLastError = true)]
        public static extern uint LsaDeregisterLogonProcess(IntPtr LsaHandle);

        [DllImport("secur32.dll", SetLastError = true)]
        public static extern uint LsaFreeReturnBuffer(IntPtr Buffer);

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        // Request structure for both MessageType 1 and 14
        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_QUERY_TKT_CACHE_REQUEST
        {
            public int MessageType;
            public long LogonId;       // LUID - use 0 for current session
        }

        // Response header for MessageType 1 (simple count)
        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_QUERY_TKT_CACHE_RESPONSE
        {
            public int MessageType;
            public int CountOfTickets;
        }

        // Response header for MessageType 14 (extended info)
        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_QUERY_TKT_CACHE_EX_RESPONSE
        {
            public int MessageType;
            public int CountOfTickets;
            // Followed by KERB_TICKET_CACHE_INFO_EX array
        }

        // Single ticket cache entry (extended)
        // Size: 104 bytes on x64, 56 bytes on x86
        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_TICKET_CACHE_INFO_EX
        {
            public UNICODE_STRING ClientName;      // 16 bytes (x64) / 8 bytes (x86)
            public UNICODE_STRING ClientRealm;     // 16 bytes (x64) / 8 bytes (x86)
            public UNICODE_STRING ServerName;      // 16 bytes (x64) / 8 bytes (x86)
            public UNICODE_STRING ServerRealm;     // 16 bytes (x64) / 8 bytes (x86)
            public long StartTime;                 // 8 bytes - FILETIME
            public long EndTime;                   // 8 bytes - FILETIME
            public long RenewTime;                 // 8 bytes - FILETIME
            public int EncryptionType;             // 4 bytes
            public uint TicketFlags;               // 4 bytes
        }
'@

    try {
        # Add type if not already added
        if (-not ([System.Management.Automation.PSTypeName]'LSA.KerberosEx').Type) {
            Add-Type -MemberDefinition $LsaSignatures -Name 'KerberosEx' -Namespace 'LSA' -ErrorAction Stop
        }
    } catch {
        # Type might already exist from previous call
        if ($_.Exception.Message -notmatch 'already exists') {
            Write-Log "[Test-KerberosTGTExists] Failed to add LSA type: $_"
            # Return $false on type load failure - we cannot check tickets
            if ($Detailed) {
                return [PSCustomObject]@{
                    Valid = $false
                    Error = "Failed to load LSA types: $($_.Exception.Message)"
                    Cached = $false
                }
            }
            return $false
        }
    }

    $lsaHandle = [IntPtr]::Zero
    $returnBuffer = [IntPtr]::Zero
    $ticketCount = 0
    $ticketInfo = $null

    try {
        # Connect to LSA (untrusted - no special privileges needed)
        $status = [LSA.KerberosEx]::LsaConnectUntrusted([ref]$lsaHandle)
        if ($status -ne 0) {
            Write-Log "[Test-KerberosTGTExists] LsaConnectUntrusted failed: 0x$($status.ToString('X8'))"
            if ($Detailed) {
                return [PSCustomObject]@{ Valid = $false; Error = "LsaConnectUntrusted failed: 0x$($status.ToString('X8'))"; Cached = $false }
            }
            return $false
        }

        # Lookup Kerberos authentication package
        $kerberosName = "Kerberos"
        $lsaString = New-Object LSA.KerberosEx+LSA_STRING
        $lsaString.Length = [uint16]$kerberosName.Length
        $lsaString.MaximumLength = [uint16]($kerberosName.Length + 1)
        $lsaString.Buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($kerberosName)

        $authPackage = 0
        try {
            $status = [LSA.KerberosEx]::LsaLookupAuthenticationPackage($lsaHandle, [ref]$lsaString, [ref]$authPackage)
            if ($status -ne 0) {
                Write-Log "[Test-KerberosTGTExists] LsaLookupAuthenticationPackage failed: 0x$($status.ToString('X8'))"
                if ($Detailed) {
                    return [PSCustomObject]@{ Valid = $false; Error = "LsaLookupAuthenticationPackage failed: 0x$($status.ToString('X8'))"; Cached = $false }
                }
                return $false
            }
        } finally {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($lsaString.Buffer)
        }

        # Stage 1: Quick count check with MessageType 1
        $request = New-Object LSA.KerberosEx+KERB_QUERY_TKT_CACHE_REQUEST
        $request.MessageType = 1  # KerbQueryTicketCacheMessage
        $request.LogonId = 0

        $requestSize = [System.Runtime.InteropServices.Marshal]::SizeOf($request)
        $requestPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($requestSize)

        try {
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($request, $requestPtr, $false)

            $returnBufferLength = 0
            $protocolStatus = 0

            $status = [LSA.KerberosEx]::LsaCallAuthenticationPackage(
                $lsaHandle,
                $authPackage,
                $requestPtr,
                $requestSize,
                [ref]$returnBuffer,
                [ref]$returnBufferLength,
                [ref]$protocolStatus
            )

            if ($status -eq 0 -and $protocolStatus -eq 0 -and $returnBuffer -ne [IntPtr]::Zero) {
                $response = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
                    $returnBuffer,
                    [Type][LSA.KerberosEx+KERB_QUERY_TKT_CACHE_RESPONSE]
                )
                $ticketCount = $response.CountOfTickets
            }

            # Free buffer from Stage 1
            if ($returnBuffer -ne [IntPtr]::Zero) {
                [LSA.KerberosEx]::LsaFreeReturnBuffer($returnBuffer) | Out-Null
                $returnBuffer = [IntPtr]::Zero
            }
        } finally {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($requestPtr)
        }

        # If no tickets, we're done
        if ($ticketCount -eq 0) {
            Write-Log "[Test-KerberosTGTExists] No tickets in cache"
            $ticketInfo = [PSCustomObject]@{
                Valid = $false
                TicketCount = 0
                TGTPresent = $false
                ClientMatch = $null
                ServerName = $null
                Realm = $null
                ClientName = $null
                EndTime = $null
                Expired = $true
                EncryptionType = $null
                TicketFlags = $null
                Cached = $false
            }
        } else {
            # Stage 2: Scan ALL tickets to find TGT with MessageType 14
            $request.MessageType = 14  # KerbQueryTicketCacheExMessage
            $requestPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($requestSize)

            try {
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($request, $requestPtr, $false)

                $returnBufferLength = 0
                $protocolStatus = 0

                $status = [LSA.KerberosEx]::LsaCallAuthenticationPackage(
                    $lsaHandle,
                    $authPackage,
                    $requestPtr,
                    $requestSize,
                    [ref]$returnBuffer,
                    [ref]$returnBufferLength,
                    [ref]$protocolStatus
                )

                if ($status -eq 0 -and $protocolStatus -eq 0 -and $returnBuffer -ne [IntPtr]::Zero) {
                    # Read response header
                    $responseEx = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
                        $returnBuffer,
                        [Type][LSA.KerberosEx+KERB_QUERY_TKT_CACHE_EX_RESPONSE]
                    )

                    # Calculate struct size (architecture-dependent)
                    $ticketStructSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][LSA.KerberosEx+KERB_TICKET_CACHE_INFO_EX])

                    # Scan ALL tickets to find TGT
                    # IMPORTANT: Multiple krbtgt tickets may exist (e.g., expired + renewed).
                    # We prefer a valid (non-expired) TGT over an expired one.
                    $tgtFound = $false
                    $tgtServerName = $null
                    $tgtServerRealm = $null
                    $tgtClientName = $null
                    $tgtEndTime = $null
                    $tgtExpired = $true
                    $tgtEncType = $null
                    $tgtFlags = $null

                    for ($i = 0; $i -lt $responseEx.CountOfTickets; $i++) {
                        # Calculate offset: header (8 bytes) + (index * struct size)
                        $ticketOffset = 8 + ($i * $ticketStructSize)
                        $ticketPtr = [IntPtr]::Add($returnBuffer, $ticketOffset)

                        try {
                            $ticket = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
                                $ticketPtr,
                                [Type][LSA.KerberosEx+KERB_TICKET_CACHE_INFO_EX]
                            )

                            # Extract ServerName
                            $serverName = $null
                            if ($ticket.ServerName.Buffer -ne [IntPtr]::Zero -and $ticket.ServerName.Length -gt 0) {
                                $serverName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni(
                                    $ticket.ServerName.Buffer,
                                    $ticket.ServerName.Length / 2
                                )
                            }

                            # Check if this is a TGT (ServerName starts with "krbtgt/")
                            if ($serverName -and $serverName -imatch '^krbtgt/') {
                                # Parse EndTime for this TGT candidate
                                $candidateEndTime = $null
                                $candidateExpired = $true
                                if ($ticket.EndTime -gt 0) {
                                    try {
                                        $candidateEndTime = [DateTime]::FromFileTime($ticket.EndTime)
                                        $candidateExpired = $candidateEndTime -lt (Get-Date)
                                    } catch {
                                        Write-Log "[Test-KerberosTGTExists] Failed to parse TGT EndTime for ticket[$i]: $_"
                                    }
                                }

                                # Accept this TGT if: (a) first TGT found, or (b) this one is valid and previous was expired
                                if (-not $tgtFound -or ($tgtExpired -and -not $candidateExpired)) {
                                    $tgtFound = $true
                                    $tgtServerName = $serverName
                                    $tgtEndTime = $candidateEndTime
                                    $tgtExpired = $candidateExpired

                                    # Extract additional TGT details
                                    if ($ticket.ServerRealm.Buffer -ne [IntPtr]::Zero -and $ticket.ServerRealm.Length -gt 0) {
                                        $tgtServerRealm = [System.Runtime.InteropServices.Marshal]::PtrToStringUni(
                                            $ticket.ServerRealm.Buffer,
                                            $ticket.ServerRealm.Length / 2
                                        )
                                    }
                                    if ($ticket.ClientName.Buffer -ne [IntPtr]::Zero -and $ticket.ClientName.Length -gt 0) {
                                        $tgtClientName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni(
                                            $ticket.ClientName.Buffer,
                                            $ticket.ClientName.Length / 2
                                        )
                                    }

                                    $tgtEncType = $ticket.EncryptionType
                                    $tgtFlags = $ticket.TicketFlags

                                    # If this TGT is valid, no need to keep looking
                                    if (-not $candidateExpired) {
                                        break
                                    }
                                }
                            }
                        } catch {
                            Write-Log "[Test-KerberosTGTExists] Error reading ticket[$i]: $_"
                            # Continue to next ticket
                        }
                    }

                    # Determine client match (if TGT found and context available)
                    $clientMatch = $true
                    if ($tgtFound -and $tgtClientName -and $Script:LDAPContext -and $Script:LDAPContext.TGTInfo -and $Script:LDAPContext.TGTInfo.UserName) {
                        $expectedClient = $Script:LDAPContext.TGTInfo.UserName
                        $clientMatch = $tgtClientName -ieq $expectedClient
                        if (-not $clientMatch) {
                            Write-Log "[Test-KerberosTGTExists] Client mismatch: TGT=$tgtClientName, Expected=$expectedClient"
                        }
                    }

                    # Determine validity
                    # Valid if: TGT found AND not expired AND client matches
                    $isValid = $tgtFound -and (-not $tgtExpired) -and $clientMatch

                    # Only log the final result
                    if ($isValid) {
                        Write-Log "[Test-KerberosTGTExists] Valid TGT found: $tgtServerName (Client: $tgtClientName)"
                    } else {
                        Write-Log "[Test-KerberosTGTExists] No valid TGT: Found=$tgtFound, Expired=$tgtExpired, ClientMatch=$clientMatch"
                    }

                    $ticketInfo = [PSCustomObject]@{
                        Valid = $isValid
                        TicketCount = $ticketCount
                        TGTPresent = $tgtFound
                        ClientMatch = $clientMatch
                        ServerName = $tgtServerName
                        Realm = $tgtServerRealm
                        ClientName = $tgtClientName
                        EndTime = $tgtEndTime
                        Expired = $tgtExpired
                        EncryptionType = $tgtEncType
                        TicketFlags = $tgtFlags
                        Cached = $false
                    }
                } else {
                    Write-Log "[Test-KerberosTGTExists] Stage 2 failed: status=0x$($status.ToString('X8')), protocolStatus=0x$($protocolStatus.ToString('X8'))"
                    # Fallback: Stage 2 failed, but we know tickets exist from Stage 1
                    # Return conservative result (cannot verify TGT)
                    $ticketInfo = [PSCustomObject]@{
                        Valid = $false
                        TicketCount = $ticketCount
                        TGTPresent = $null
                        ClientMatch = $null
                        ServerName = $null
                        Realm = $null
                        ClientName = $null
                        EndTime = $null
                        Expired = $null
                        EncryptionType = $null
                        TicketFlags = $null
                        Error = "Stage 2 query failed: status=0x$($status.ToString('X8')), protocolStatus=0x$($protocolStatus.ToString('X8'))"
                        Cached = $false
                    }
                }
            } finally {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($requestPtr)
            }
        }
    } catch {
        Write-Log "[Test-KerberosTGTExists] Exception: $_"
        # Return $false on exception - we cannot verify tickets
        if ($Detailed) {
            return [PSCustomObject]@{
                Valid = $false
                Error = $_.Exception.Message
                Cached = $false
            }
        }
        return $false
    } finally {
        # Cleanup
        if ($returnBuffer -ne [IntPtr]::Zero) {
            [LSA.KerberosEx]::LsaFreeReturnBuffer($returnBuffer) | Out-Null
        }
        if ($lsaHandle -ne [IntPtr]::Zero) {
            [LSA.KerberosEx]::LsaDeregisterLogonProcess($lsaHandle) | Out-Null
        }
    }

    # Ensure ticketInfo is set (defensive)
    if (-not $ticketInfo) {
        $ticketInfo = [PSCustomObject]@{
            Valid = $false
            TicketCount = $ticketCount
            TGTPresent = $false
            ClientMatch = $null
            ServerName = $null
            Realm = $null
            ClientName = $null
            EndTime = $null
            Expired = $null
            EncryptionType = $null
            TicketFlags = $null
            Error = "Unknown error: ticketInfo not set"
            Cached = $false
        }
    }

    # Cache result in LDAPContext if it exists
    if ($Script:LDAPContext) {
        $Script:LDAPContext['KerberosTicketCount'] = $ticketInfo.TicketCount
        $Script:LDAPContext['KerberosLastCheck'] = Get-Date
        $Script:LDAPContext['KerberosValid'] = $ticketInfo.Valid
        $Script:LDAPContext['KerberosTGTPresent'] = $ticketInfo.TGTPresent
        $Script:LDAPContext['KerberosClientMatch'] = $ticketInfo.ClientMatch
        $Script:LDAPContext['KerberosServerName'] = $ticketInfo.ServerName
        $Script:LDAPContext['KerberosRealm'] = $ticketInfo.Realm
        $Script:LDAPContext['KerberosClientName'] = $ticketInfo.ClientName
        $Script:LDAPContext['KerberosEndTime'] = $ticketInfo.EndTime
        $Script:LDAPContext['KerberosExpired'] = $ticketInfo.Expired
        $Script:LDAPContext['KerberosEncryptionType'] = $ticketInfo.EncryptionType
        $Script:LDAPContext['KerberosTicketFlags'] = $ticketInfo.TicketFlags
    }

    if ($Detailed) {
        return $ticketInfo
    }

    return $ticketInfo.Valid
}
