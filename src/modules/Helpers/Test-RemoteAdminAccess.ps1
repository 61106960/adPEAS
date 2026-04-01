<#
.SYNOPSIS
    Tests if the current user has administrative access on remote Windows systems.

.DESCRIPTION
    Test-RemoteAdminAccess checks administrative access on remote computers using
    SMB (ADMIN$ share) with automatic WMI fallback.

    The function supports:
    - Pipeline input for computer names
    - Parallel execution using Runspaces for performance
    - Configurable timeout and thread pool size
    - Alternate credentials
    - Automatic WMI fallback when SMB fails (configurable)

    Test Methods:
    - SMB (Primary): Tests ADMIN$ share access - most reliable, requires port 445
    - WMI (Fallback): Tests WMI registry access (HKLM) - requires port 135

.PARAMETER ComputerName
    One or more computer names to test. Accepts pipeline input.
    Can be hostname, FQDN, or IP address.

.PARAMETER Credential
    Optional PSCredential for authentication. If not specified, uses current user context.

.PARAMETER Timeout
    Connection timeout in milliseconds. Default: 2000ms (2 seconds).

.PARAMETER ThrottleLimit
    Maximum number of concurrent connections. Default: 32.
    Adjust based on network capacity and target environment.

.PARAMETER Method
    The method to use for testing admin access. Default: SMB.
    - SMB: Tests ADMIN$ share access (most reliable, port 445)
    - WMI: Tests WMI registry access only (port 135)
    - All: Tries SMB first, then WMI as fallback

.PARAMETER NoFallback
    Disables automatic WMI fallback when SMB fails.
    By default, if SMB fails due to port/connectivity issues, WMI is tried.

.EXAMPLE
    Test-RemoteAdminAccess -ComputerName "SERVER01"
    Tests admin access on a single server using SMB (with WMI fallback).

.EXAMPLE
    "SERVER01", "SERVER02", "SERVER03" | Test-RemoteAdminAccess
    Tests admin access on multiple servers via pipeline.

.EXAMPLE
    Get-DomainComputer -OperatingSystem "*Server*" | Select-Object -ExpandProperty dNSHostName | Test-RemoteAdminAccess -ThrottleLimit 50
    Tests admin access on all domain servers with increased parallelism.

.EXAMPLE
    $cred = Get-Credential
    Get-Content servers.txt | Test-RemoteAdminAccess -Credential $cred -Timeout 5000
    Tests admin access using alternate credentials with extended timeout.

.EXAMPLE
    Test-RemoteAdminAccess -ComputerName "SERVER01" -Method WMI
    Tests admin access using WMI only (useful when SMB is blocked).

.EXAMPLE
    Test-RemoteAdminAccess -ComputerName "SERVER01" -NoFallback
    Tests admin access using SMB only, without WMI fallback.

.OUTPUTS
    PSCustomObject with properties:
    - ComputerName: Target computer name
    - IsAdmin: Boolean indicating admin access
    - Method: Test method that succeeded (SMB or WMI)
    - ResponseTime: Time taken for the test in milliseconds
    - Error: Error message if test failed, otherwise $null

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function Test-RemoteAdminAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('DNSHostName', 'Name', 'CN', 'IPAddress')]
        [string[]]$ComputerName,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [ValidateRange(500, 30000)]
        [int]$Timeout = 2000,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1, 100)]
        [int]$ThrottleLimit = 32,

        [Parameter(Mandatory=$false)]
        [ValidateSet('SMB', 'WMI', 'All')]
        [string]$Method = 'SMB',

        [Parameter(Mandatory=$false)]
        [switch]$NoFallback
    )

    begin {
        Write-Log "[Test-RemoteAdminAccess] Starting remote admin access check (Method=$Method, Fallback=$(-not $NoFallback))"

        # Collect all computer names from pipeline (HashSet for deduplication)
        $allComputers = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        # Detect Kerberos/PTT session - Runspaces don't inherit Kerberos ticket context from LSA cache
        # If Kerberos was used AND no explicit credentials provided, we must use sequential execution
        $forceSequential = $false
        $kerberosSession = $Script:LDAPContext -and $Script:LDAPContext['KerberosUsed']

        if ($kerberosSession -and -not $Credential) {
            $forceSequential = $true
            Write-Log "[Test-RemoteAdminAccess] Kerberos/PTT session detected without explicit credentials - switching to sequential execution"
            Write-Warning "Kerberos session detected: Parallel execution disabled (Runspaces don't inherit Kerberos ticket context). Use -Credential for parallel execution."
        }

        # Combined test script block with SMB and WMI support
        $testScriptBlock = {
            param(
                [string]$Computer,
                [int]$TimeoutMs,
                [System.Management.Automation.PSCredential]$Cred,
                [string]$TestMethod,
                [bool]$AllowFallback
            )

            $result = [PSCustomObject]@{
                ComputerName = $Computer
                IsAdmin      = $false
                Method       = $null
                ResponseTime = 0
                Error        = $null
            }

            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

            # ===== Helper: Convert Exception to Error Info =====
            # NOTE: This is a local copy of the error handling logic because Runspaces
            # run in isolation and don't have access to adPEAS-ErrorCodes.ps1 functions.
            # See adPEAS-ErrorCodes.ps1 for the central implementation.
            function Get-Win32ErrorInfo {
                param(
                    [Parameter(Mandatory=$true)]
                    [System.Exception]$Exception,
                    [string]$Context = "Operation"
                )

                $errorInfo = @{
                    Message = $null
                    ShouldFallback = $false
                    IsAccessDenied = $false
                }

                $hresult = $Exception.HResult
                $win32Code = if ($hresult) { $hresult -band 0xFFFF } else { 0 }

                # Win32 Error Codes (language-independent):
                # 5    = ERROR_ACCESS_DENIED
                # 1326 = ERROR_LOGON_FAILURE (bad username/password)
                # 1219 = ERROR_SESSION_CREDENTIAL_CONFLICT (multiple connections)
                # 53   = ERROR_BAD_NETPATH (network path not found)
                # 67   = ERROR_BAD_NET_NAME (network name not found)
                # 1311 = ERROR_NO_LOGON_SERVERS (no logon servers available)

                # WMI/RPC HRESULT values:
                # 0x800706BA = RPC server unavailable
                # 0x80070005 = Access denied (HRESULT form)
                # 0x80041003 = WBEM_E_ACCESS_DENIED

                switch ($win32Code) {
                    5 {
                        $errorInfo.Message = "Access denied"
                        $errorInfo.IsAccessDenied = $true
                    }
                    1326 {
                        $errorInfo.Message = "Invalid credentials"
                        $errorInfo.IsAccessDenied = $true
                    }
                    1219 {
                        $errorInfo.Message = "Session credential conflict"
                        $errorInfo.IsAccessDenied = $true
                    }
                    { $_ -in @(53, 67) } {
                        $errorInfo.Message = "Network path not found"
                        $errorInfo.ShouldFallback = $true
                    }
                    1311 {
                        $errorInfo.Message = "No logon servers available"
                        $errorInfo.ShouldFallback = $true
                    }
                    1722 {
                        # RPC server unavailable (Win32 code form)
                        $errorInfo.Message = "RPC server unavailable"
                        $errorInfo.ShouldFallback = $true
                    }
                    default {
                        # Check full HRESULT for WMI-specific errors
                        switch ($hresult) {
                            0x800706BA {
                                $errorInfo.Message = "RPC server unavailable"
                                $errorInfo.ShouldFallback = $true
                            }
                            { $_ -in @(0x80070005, 0x80041003) } {
                                $errorInfo.Message = "Access denied"
                                $errorInfo.IsAccessDenied = $true
                            }
                            default {
                                # Unknown error - include details
                                if ($hresult) {
                                    $errorInfo.Message = "$Context error (0x{0:X8}): {1}" -f $hresult, $Exception.Message
                                } else {
                                    $errorInfo.Message = "$Context error: $($Exception.Message)"
                                }
                            }
                        }
                    }
                }

                return $errorInfo
            }

            # ===== Helper: Safe TCP Port Check =====
            function Test-TcpPort {
                param($TargetHost, $Port, $TimeoutMs)

                $tcpResult = @{
                    Success = $false
                    Error = $null
                }

                $tcpClient = $null
                try {
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $connectTask = $tcpClient.BeginConnect($TargetHost, $Port, $null, $null)
                    $connected = $connectTask.AsyncWaitHandle.WaitOne($TimeoutMs, $false)

                    if (-not $connected) {
                        $tcpResult.Error = "Connection timeout (port $Port)"
                        return $tcpResult
                    }

                    try {
                        $tcpClient.EndConnect($connectTask)
                        $tcpResult.Success = $true
                    } catch {
                        $tcpResult.Error = "Port $Port refused"
                    }
                } catch {
                    if ($_.Exception.Message -match "No such host is known") {
                        $tcpResult.Error = "DNS resolution failed"
                    } else {
                        $tcpResult.Error = "Connection error: $($_.Exception.Message)"
                    }
                } finally {
                    if ($tcpClient) {
                        try { $tcpClient.Close() } catch { }
                        try { $tcpClient.Dispose() } catch { }
                    }
                }

                return $tcpResult
            }

            # ===== SMB Test Function =====
            function Test-SMBAdmin {
                param($TargetComputer, $TimeoutMs, $Cred)

                $smbResult = @{
                    Success = $false
                    Error = $null
                    ShouldFallback = $false
                }

                try {
                    # Validate computer name (prevent injection)
                    if ($TargetComputer -match '[<>:"|?*\\\/]' -or $TargetComputer -match '^\s*$') {
                        $smbResult.Error = "Invalid computer name"
                        return $smbResult
                    }

                    # Quick TCP connectivity check on port 445
                    $tcpCheck = Test-TcpPort -TargetHost $TargetComputer -Port 445 -TimeoutMs $TimeoutMs
                    if (-not $tcpCheck.Success) {
                        $smbResult.Error = $tcpCheck.Error
                        $smbResult.ShouldFallback = $true
                        return $smbResult
                    }

                    # Test ADMIN$ share access
                    $adminShare = "\\$TargetComputer\ADMIN$"

                    if ($Cred) {
                        $driveName = "adPEAS_$([guid]::NewGuid().ToString('N').Substring(0,8))"
                        $psDrive = $null

                        try {
                            # Create temporary PSDrive with credentials
                            $psDrive = New-PSDrive -Name $driveName -PSProvider FileSystem -Root $adminShare -Credential $Cred -ErrorAction Stop
                            $smbResult.Success = $true
                        } catch {
                            $errInfo = Get-Win32ErrorInfo -Exception $_.Exception -Context "SMB"
                            $smbResult.Error = $errInfo.Message
                            $smbResult.ShouldFallback = $errInfo.ShouldFallback

                            # Special handling for credential conflict - try existing session
                            $win32Code = if ($_.Exception.HResult) { $_.Exception.HResult -band 0xFFFF } else { 0 }
                            if ($win32Code -eq 1219) {
                                $testPathResult = Test-Path -Path $adminShare -ErrorAction SilentlyContinue
                                if ($testPathResult) {
                                    $smbResult.Success = $true
                                    $smbResult.Error = $null
                                }
                            }
                        } finally {
                            # Always remove PSDrive
                            if ($psDrive) {
                                try { Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue } catch { }
                            }
                        }
                    } else {
                        # No credentials - use current context with proper error handling
                        try {
                            $null = Get-Item -Path $adminShare -ErrorAction Stop
                            $smbResult.Success = $true
                        } catch {
                            $errInfo = Get-Win32ErrorInfo -Exception $_.Exception -Context "SMB"
                            $smbResult.Error = $errInfo.Message
                            $smbResult.ShouldFallback = $errInfo.ShouldFallback
                        }
                    }
                } catch {
                    # Outer catch for unexpected errors
                    $errInfo = Get-Win32ErrorInfo -Exception $_.Exception -Context "SMB"
                    $smbResult.Error = $errInfo.Message
                    $smbResult.ShouldFallback = $true
                }

                return $smbResult
            }

            # ===== WMI Test Function =====
            function Test-WMIAdmin {
                param($TargetComputer, $TimeoutMs, $Cred)

                $wmiResult = @{
                    Success = $false
                    Error = $null
                }

                $wmiScope = $null
                $searcher = $null
                $wmiResultSet = $null

                try {
                    # Validate computer name
                    if ($TargetComputer -match '[<>:"|?*]' -or $TargetComputer -match '^\s*$') {
                        $wmiResult.Error = "Invalid computer name"
                        return $wmiResult
                    }

                    # Quick TCP connectivity check on port 135 (RPC)
                    $tcpCheck = Test-TcpPort -TargetHost $TargetComputer -Port 135 -TimeoutMs $TimeoutMs
                    if (-not $tcpCheck.Success) {
                        $wmiResult.Error = $tcpCheck.Error
                        return $wmiResult
                    }

                    # Build WMI connection options
                    $wmiOptions = New-Object System.Management.ConnectionOptions
                    $wmiOptions.Timeout = [TimeSpan]::FromMilliseconds($TimeoutMs)

                    if ($Cred) {
                        $wmiOptions.Username = $Cred.UserName
                        $wmiOptions.Password = $Cred.GetNetworkCredential().Password
                        # Handle both DOMAIN\user and user@domain formats
                        $netCred = $Cred.GetNetworkCredential()
                        if (-not [string]::IsNullOrEmpty($netCred.Domain)) {
                            $wmiOptions.Authority = "ntlmdomain:$($netCred.Domain)"
                        }
                    }

                    # Connect to WMI StdRegProv (Registry Provider) - requires admin for HKLM\SYSTEM
                    $wmiScope = New-Object System.Management.ManagementScope("\\$TargetComputer\root\default", $wmiOptions)

                    try {
                        $wmiScope.Connect()

                        if ($wmiScope.IsConnected) {
                            # Use StdRegProv to check if we can read HKLM\SYSTEM\CurrentControlSet
                            # This requires admin privileges
                            $regPath = New-Object System.Management.ManagementPath("StdRegProv")
                            $regClass = New-Object System.Management.ManagementClass($wmiScope, $regPath, $null)

                            # Try to enumerate subkeys of HKLM\SYSTEM\CurrentControlSet\Control
                            # HKEY_LOCAL_MACHINE = 2147483650
                            $inParams = $regClass.GetMethodParameters("EnumKey")
                            $inParams["hDefKey"] = [uint32]2147483650
                            $inParams["sSubKeyName"] = "SYSTEM\CurrentControlSet\Control"

                            $outParams = $regClass.InvokeMethod("EnumKey", $inParams, $null)

                            # Return value 0 = success, 5 = access denied
                            if ($outParams["ReturnValue"] -eq 0) {
                                $wmiResult.Success = $true
                            } elseif ($outParams["ReturnValue"] -eq 5) {
                                $wmiResult.Error = "Access denied (WMI)"
                            } else {
                                $wmiResult.Error = "WMI registry access failed (code: $($outParams["ReturnValue"]))"
                            }

                            $regClass.Dispose()
                        } else {
                            $wmiResult.Error = "WMI connection failed"
                        }
                    } catch [System.UnauthorizedAccessException] {
                        $wmiResult.Error = "Access denied (WMI)"
                    } catch [System.Runtime.InteropServices.COMException] {
                        $errInfo = Get-Win32ErrorInfo -Exception $_.Exception -Context "WMI"
                        $wmiResult.Error = $errInfo.Message
                    }
                } catch {
                    $errInfo = Get-Win32ErrorInfo -Exception $_.Exception -Context "WMI"
                    $wmiResult.Error = $errInfo.Message
                } finally {
                    # Dispose WMI objects
                    if ($wmiResultSet) {
                        try { $wmiResultSet.Dispose() } catch { }
                    }
                    if ($searcher) {
                        try { $searcher.Dispose() } catch { }
                    }
                    if ($wmiScope) {
                        # ManagementScope doesn't implement IDisposable directly
                        # but we should clear references
                        $wmiScope = $null
                    }
                }

                return $wmiResult
            }

            # ===== Main Test Logic =====
            try {
                # Test based on method selection
                if ($TestMethod -eq 'SMB' -or $TestMethod -eq 'All') {
                    $smbResult = Test-SMBAdmin -TargetComputer $Computer -TimeoutMs $TimeoutMs -Cred $Cred

                    if ($smbResult.Success) {
                        $result.IsAdmin = $true
                        $result.Method = 'SMB'
                    } elseif ($TestMethod -eq 'SMB' -and -not $AllowFallback) {
                        # SMB only, no fallback
                        $result.Error = $smbResult.Error
                        $result.Method = 'SMB'
                    } elseif ($smbResult.ShouldFallback -and $AllowFallback) {
                        # SMB failed with connectivity issue, try WMI fallback
                        $wmiResult = Test-WMIAdmin -TargetComputer $Computer -TimeoutMs $TimeoutMs -Cred $Cred

                        if ($wmiResult.Success) {
                            $result.IsAdmin = $true
                            $result.Method = 'WMI'
                        } else {
                            $result.Error = "SMB: $($smbResult.Error); WMI: $($wmiResult.Error)"
                            $result.Method = 'SMB+WMI'
                        }
                    } elseif ($TestMethod -eq 'All' -and -not $smbResult.Success) {
                        # For 'All' method, always try WMI if SMB failed
                        $wmiResult = Test-WMIAdmin -TargetComputer $Computer -TimeoutMs $TimeoutMs -Cred $Cred

                        if ($wmiResult.Success) {
                            $result.IsAdmin = $true
                            $result.Method = 'WMI'
                        } else {
                            $result.Error = "SMB: $($smbResult.Error); WMI: $($wmiResult.Error)"
                            $result.Method = 'SMB+WMI'
                        }
                    } else {
                        # SMB failed with access denied (not connectivity), no fallback needed
                        $result.Error = $smbResult.Error
                        $result.Method = 'SMB'
                    }
                }

                if ($TestMethod -eq 'WMI') {
                    $wmiResult = Test-WMIAdmin -TargetComputer $Computer -TimeoutMs $TimeoutMs -Cred $Cred

                    if ($wmiResult.Success) {
                        $result.IsAdmin = $true
                        $result.Method = 'WMI'
                    } else {
                        $result.Error = $wmiResult.Error
                        $result.Method = 'WMI'
                    }
                }

            } catch {
                $result.Error = $_.Exception.Message
                if (-not $result.Method) {
                    $result.Method = $TestMethod
                }
            }

            $stopwatch.Stop()
            $result.ResponseTime = $stopwatch.ElapsedMilliseconds

            return $result
        }
    }

    process {
        # Collect computer names from pipeline (HashSet handles deduplication)
        foreach ($computer in $ComputerName) {
            if (-not [string]::IsNullOrWhiteSpace($computer)) {
                $trimmedName = $computer.Trim()

                # Validate computer name using central validation function
                if (-not (Test-ValidComputerName -ComputerName $trimmedName -AllowFQDN -AllowIPAddress)) {
                    Write-Log "[Test-RemoteAdminAccess] Security: Rejected invalid/malicious computer name: '$trimmedName'"
                    # Return error result for this computer
                    [PSCustomObject]@{
                        ComputerName = $trimmedName
                        IsAdmin      = $false
                        Method       = $null
                        ResponseTime = 0
                        Error        = "Invalid computer name - rejected for security"
                    }
                    continue
                }

                [void]$allComputers.Add($trimmedName)
            }
        }
    }

    end {
        if ($allComputers.Count -eq 0) {
            Write-Log "[Test-RemoteAdminAccess] No computers to test"
            return
        }

        # Determine fallback behavior
        $allowFallback = (-not $NoFallback) -and ($Method -eq 'SMB')

        # Results collection
        $results = [System.Collections.ArrayList]::new()
        $adminCount = 0

        # ===== Sequential Execution (for Kerberos/PTT sessions) =====
        if ($forceSequential) {
            Write-Log "[Test-RemoteAdminAccess] Testing $($allComputers.Count) unique computer(s) SEQUENTIALLY (Kerberos session)"

            $completedCount = 0
            foreach ($computer in $allComputers) {
                $completedCount++

                # Progress indicator
                if ($allComputers.Count -gt 10) {
                    Write-Progress -Activity "Testing Remote Admin Access (Sequential)" `
                                   -Status "Testing $computer ($completedCount of $($allComputers.Count))" `
                                   -PercentComplete (($completedCount / $allComputers.Count) * 100)
                }

                # Execute test script block directly in main process (preserves Kerberos ticket context)
                $testResult = & $testScriptBlock -Computer $computer `
                                                 -TimeoutMs $Timeout `
                                                 -Cred $Credential `
                                                 -TestMethod $Method `
                                                 -AllowFallback $allowFallback

                if ($testResult) {
                    [void]$results.Add($testResult)
                    if ($testResult.IsAdmin) {
                        $adminCount++
                    }
                }

                # Progress logging for large scans
                if ($allComputers.Count -gt 100 -and $completedCount % 50 -eq 0) {
                    Write-Log "[Test-RemoteAdminAccess] Progress: $completedCount/$($allComputers.Count) completed"
                }
            }

            # Clear progress bar
            if ($allComputers.Count -gt 10) {
                Write-Progress -Activity "Testing Remote Admin Access (Sequential)" -Completed
            }
        }
        # ===== Parallel Execution (default - using RunspacePool) =====
        else {
            Write-Log "[Test-RemoteAdminAccess] Testing $($allComputers.Count) unique computer(s) with ThrottleLimit=$ThrottleLimit"

            # Create RunspacePool
            $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            $runspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit, $sessionState, $Host)
            $runspacePool.ApartmentState = [System.Threading.ApartmentState]::MTA
            $runspacePool.Open()

            # Create runspaces for each computer
            $runspaces = [System.Collections.ArrayList]::new()

            try {
                foreach ($computer in $allComputers) {
                    $ps = [PowerShell]::Create()
                    $ps.RunspacePool = $runspacePool

                    [void]$ps.AddScript($testScriptBlock)
                    [void]$ps.AddParameter('Computer', $computer)
                    [void]$ps.AddParameter('TimeoutMs', $Timeout)
                    [void]$ps.AddParameter('TestMethod', $Method)
                    [void]$ps.AddParameter('AllowFallback', $allowFallback)
                    if ($Credential) {
                        [void]$ps.AddParameter('Cred', $Credential)
                    }

                    $runspaceInfo = [PSCustomObject]@{
                        PowerShell = $ps
                        Handle     = $ps.BeginInvoke()
                        Computer   = $computer
                    }

                    [void]$runspaces.Add($runspaceInfo)
                }

                # Collect results
                $completedCount = 0

                foreach ($rs in $runspaces) {
                    try {
                        # Wait for completion with overall timeout (TimeoutMs * 2 to allow for retries)
                        $completed = $rs.Handle.AsyncWaitHandle.WaitOne($Timeout * 3)

                        if ($completed) {
                            $output = $rs.PowerShell.EndInvoke($rs.Handle)
                            if ($output) {
                                foreach ($item in $output) {
                                    [void]$results.Add($item)
                                    if ($item.IsAdmin) {
                                        $adminCount++
                                    }
                                }
                            }
                        } else {
                            # Timeout - create error result
                            $errorResult = [PSCustomObject]@{
                                ComputerName = $rs.Computer
                                IsAdmin      = $false
                                Method       = $Method
                                ResponseTime = $Timeout * 3
                                Error        = "Operation timeout"
                            }
                            [void]$results.Add($errorResult)
                        }
                    } catch {
                        # Create error result for failed runspace
                        $errorResult = [PSCustomObject]@{
                            ComputerName = $rs.Computer
                            IsAdmin      = $false
                            Method       = $Method
                            ResponseTime = 0
                            Error        = $_.Exception.Message
                        }
                        [void]$results.Add($errorResult)
                    } finally {
                        # Always dispose PowerShell instance
                        if ($rs.PowerShell) {
                            try {
                                $rs.PowerShell.Stop()
                                $rs.PowerShell.Dispose()
                            } catch { }
                        }
                    }
                    $completedCount++

                    # Progress indicator for large scans
                    if ($allComputers.Count -gt 100 -and $completedCount % 50 -eq 0) {
                        Write-Log "[Test-RemoteAdminAccess] Progress: $completedCount/$($allComputers.Count) completed"
                    }
                }
            } finally {
                # Cleanup RunspacePool (even on Ctrl+C)
                if ($runspacePool) {
                    try {
                        $runspacePool.Close()
                        $runspacePool.Dispose()
                    } catch { }
                }
            }
        }

        Write-Log "[Test-RemoteAdminAccess] Completed: $adminCount/$($allComputers.Count) systems with admin access"

        # Output results
        # CRITICAL: Use comma operator to prevent PowerShell array unwrapping
        # Without comma, PowerShell unwraps single-element arrays to scalar objects
        return ,$results
    }
}
