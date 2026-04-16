function Disconnect-adPEAS {
<#
.SYNOPSIS
    Terminates the current adPEAS session and cleans up resources.

.DESCRIPTION
    Closes the current LDAP connection, disposes connection objects and clears all global session variables and caches.

    This function:
    - Reverts NTLM impersonation if active (RevertToSelf + CloseHandle)
    - Disposes $Script:LdapConnection (System.DirectoryServices.Protocols.LdapConnection)
    - Disposes $Script:GCConnection (Global Catalog connection for cross-domain SID resolution)
    - Clears all session state variables ($Script:LDAPContext, $Script:LDAPCredential, $Script:ConnectionState, etc.)
    - Clears all session caches (SID resolution, privileged check, completion, SMB, LAPS, etc.)
    - Removes hosts file entries added by Connect-adPEAS (requires Admin)

.PARAMETER Force
    Forces disconnect even if errors occur during cleanup.

.EXAMPLE
    Disconnect-adPEAS
    Terminates the current session cleanly.

.EXAMPLE
    Disconnect-adPEAS -Force
    Forces disconnect even with cleanup errors.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )

    begin {
        # Helper: Safe dispose of IDisposable objects (LdapConnection, etc.)
        function Invoke-SafeDispose {
            param(
                [Parameter(Mandatory)]
                [string]$Name,
                [Parameter(Mandatory)]
                [AllowNull()]
                $Object
            )
            if (-not $Object) { return $null }
            try {
                Write-Log "[Disconnect-adPEAS] Disposing $Name..."
                $Object.Dispose()
                Write-Log "[Disconnect-adPEAS] $Name disposed successfully"
                return $null
            }
            catch {
                if ($_.Exception.InnerException -is [System.ObjectDisposedException] -or
                    $_.Exception -is [System.ObjectDisposedException]) {
                    Write-Log "[Disconnect-adPEAS] $Name already disposed - continuing cleanup"
                    return $null
                }
                Write-Log "[Disconnect-adPEAS] Error disposing ${Name}: $_"
                return "$Name disposal failed: $_"
            }
        }
    }

    process {
        try {
            # Check if a real session exists (LDAPContext with Domain set, or active connection)
            $hasSession = ($Script:LDAPContext -and $Script:LDAPContext['Domain']) -or $Script:LdapConnection
            if (-not $hasSession) {
                Show-NoSessionError -Context "Disconnect-adPEAS"
                # Still clean up any partial state (e.g. empty LDAPContext from failed connect)
                if ($Script:LDAPContext) { Clear-SessionState }
                return
            }

            # Display current session before disconnect
            Show-SubHeader "Disconnecting session..."

            if ($Script:LDAPContext -and $Script:LDAPContext['Domain']) {
                Show-Line "Current Session:" -Class Hint
                Show-KeyValue "Domain:" $Script:LDAPContext.Domain
                # Display authenticated user
                if ($Script:LDAPContext.AuthenticatedUser) {
                    Show-KeyValue "Authenticated as:" $Script:LDAPContext.AuthenticatedUser
                } elseif ($Script:LDAPContext.Credential) {
                    Show-KeyValue "Authenticated as:" $Script:LDAPContext.Credential.UserName
                } else {
                    Show-KeyValue "Authenticated as:" "$env:USERDOMAIN\$env:USERNAME"
                }

                # Calculate session duration if available
                if ($Script:LDAPContext.SessionStartTime) {
                    $sessionDuration = (Get-Date) - $Script:LDAPContext.SessionStartTime
                    Show-KeyValue "Session Duration:" $sessionDuration.ToString('hh\:mm\:ss')
                }
            }

            $cleanupErrors = @()

            # Step 1: Revert NTLM impersonation (MUST be done BEFORE disposing connections)
            if ($Script:NTLMTokenHandle -and $Script:NTLMTokenHandle -ne [IntPtr]::Zero) {
                Write-Log "[Disconnect-adPEAS] Reverting NTLM impersonation..."
                try {
                    Invoke-RevertToSelf -TokenHandle $Script:NTLMTokenHandle
                    Write-Log "[Disconnect-adPEAS] NTLM impersonation reverted successfully"
                    Show-KeyValue "NTLM Impersonation:" "Reverted to original context"
                }
                catch {
                    $cleanupErrors += "NTLM revert failed: $_"
                    Write-Log "[Disconnect-adPEAS] Error reverting NTLM impersonation: $_"
                    if (-not $Force) {
                        Write-Warning "[Disconnect-adPEAS] Failed to revert NTLM impersonation: $_"
                    }
                }
                $Script:NTLMTokenHandle = [IntPtr]::Zero
            }

            # Step 2: Dispose connections
            $err = Invoke-SafeDispose -Name "LdapConnection" -Object $Script:LdapConnection
            if ($err) { $cleanupErrors += $err }

            $err = Invoke-SafeDispose -Name "GCConnection" -Object $Script:GCConnection
            if ($err) { $cleanupErrors += $err }

            # Step 3: Clean up hosts file entries (if patched during connect)
            if ($Script:LDAPContext -and $Script:LDAPContext['HostsEntries'] -and $Script:LDAPContext['HostsEntries'].Count -gt 0) {
                Write-Log "[Disconnect-adPEAS] Cleaning up hosts file entries..."
                try {
                    $hostsResult = Remove-adPEASHostsEntry
                    if ($hostsResult.Success -and $hostsResult.RemovedCount -gt 0) {
                        Write-Log "[Disconnect-adPEAS] Removed $($hostsResult.RemovedCount) hosts file entries"
                        Show-KeyValue "Hosts File:" "Cleaned ($($hostsResult.RemovedCount) entries removed)"
                    }
                    elseif ($hostsResult.RequiresElevation) {
                        Write-Warning "[Disconnect-adPEAS] Cannot clean hosts file - Administrator privileges required"
                        Write-Warning "[Disconnect-adPEAS] Manually remove adPEAS entries from: $env:SystemRoot\System32\drivers\etc\hosts"
                        Show-KeyValue "Hosts File:" "Cleanup requires Admin (manual removal needed)" -Class Hint
                    }
                }
                catch {
                    $cleanupErrors += "Hosts file cleanup failed: $_"
                    Write-Log "[Disconnect-adPEAS] Error cleaning hosts file: $_"
                    if (-not $Force) {
                        Write-Warning "[Disconnect-adPEAS] Hosts file cleanup failed: $_"
                    }
                }
            }

            # Step 4: Clear all session variables and caches
            Clear-SessionState
            Write-Log "[Disconnect-adPEAS] All session variables and caches cleared"

            # Success output
            Show-EmptyLine
            Show-Line "Cleanup:" -Class Hint
            Show-KeyValue "Connection:" "Closed" -Class Note
            Show-KeyValue "Variables:" "Cleared" -Class Note
            Show-EmptyLine

            if ($cleanupErrors.Count -gt 0 -and $Force) {
                Show-Line "Cleanup errors (forced disconnect):" -Class Hint
                foreach ($err in $cleanupErrors) {
                    Show-Line "- $err"
                }
            }
        }
        catch {
            # Use centralized error message
            Show-DisconnectError -ErrorMessage $_.Exception.Message

            # If Force is specified, clear variables anyway
            if ($Force) {
                Show-Line "Force mode enabled - clearing variables anyway..." -Class Hint
                # Revert NTLM impersonation even in force mode
                if ($Script:NTLMTokenHandle -and $Script:NTLMTokenHandle -ne [IntPtr]::Zero) {
                    try { Invoke-RevertToSelf -TokenHandle $Script:NTLMTokenHandle } catch {}
                    $Script:NTLMTokenHandle = [IntPtr]::Zero
                }
                # Dispose connections silently
                try { if ($Script:LdapConnection) { $Script:LdapConnection.Dispose() } } catch {}
                try { if ($Script:GCConnection) { $Script:GCConnection.Dispose() } } catch {}
                # Clear all state
                Clear-SessionState
                Show-Line "Session variables and caches force-cleared" -Class Note
            }
        }
    }
}

function Clear-SessionState {
    <#
    .SYNOPSIS
        Clears all session-specific $Script: variables and caches.
    .DESCRIPTION
        Internal helper used by Disconnect-adPEAS (normal and force path).
        Only clears session state - does NOT dispose connections or revert impersonation.
    #>

    # Connection references (already disposed at this point)
    $Script:LdapConnection = $null
    $Script:GCConnection = $null

    # Core session state
    $Script:LDAPContext = $null
    $Script:LDAPCredential = $null
    $Script:ConnectionState = $null
    $Script:LastLDAPErrorCode = $null
    $Script:LastLDAPErrorDetails = $null
    $Script:AuthInfo = $null
    $Script:NTLMTokenHandle = [IntPtr]::Zero

    # Anonymous access detection (Connect-LDAP)
    $Script:AnonymousAccessEnabled = $null
    $Script:AnonymousAccessDetails = $null

    # License (runtime-provided via -License parameter)
    $Script:RuntimeLicense = $null
    $Script:adPEASDisclaimer = $null

    # Kerberos ticket metadata
    $Script:KirbiMetadata = $null
    $Script:CcacheMetadata = $null

    # SID resolution caches (ConvertFrom-SID / ConvertTo-SID)
    $Script:SIDResolutionCache = @{}
    $Script:SIDVerboseCache = @{}
    $Script:NameToSIDCache = @{}

    # Privileged check cache (Test-IsPrivileged)
    $Script:PrivilegedCheckCache = @{}
    $Script:GroupMembershipCache = @{}

    # Token groups cache (Get-CurrentUserTokenGroups)
    $Script:CurrentUserTokenGroups = $null

    # Foreign domain cache (ConvertFrom-SID)
    $Script:ForeignDomainCache = @{}

    # Collector caches (Invoke-adPEASCollector)
    $Script:ComputerHostnameCache = @{}
    $Script:DNToIdentityCache = @{}
    $Script:ConfigContainerGuidCache = $null

    # Tab-completion cache (Register-adPEASCompleters)
    if ($Script:CompletionCache) { Clear-CompletionCache }
    $Script:CompletionCacheAttempted = $null

    # SMB share access cache (Invoke-SMBAccess)
    if ($Script:SMBShareAccessCache -and $Script:SMBShareAccessCache.Count -gt 0) {
        Reset-SMBShareAccessCache
    } else {
        $Script:SMBShareAccessCache = @{}
    }

    # SYSVOL file listing cache
    if ($null -ne $Script:SYSVOLFileCache) {
        Reset-SYSVOLFileCache
    }

    # SYSVOL content cache (on-demand file content, e.g., GptTmpl.inf)
    $Script:SYSVOLContentCache = $null

    # Findings collection (adPEAS-Messages / HTML export)
    $Script:adPEAS_FindingsCollection = $null
    $Script:adPEAS_FindingsCollectionEnabled = $false
    $Script:adPEAS_CurrentCheckContext = $null

    # LDAP Statistics tracking (set by Invoke-adPEAS -Statistics)
    $Script:LDAPStatistics = $null

    # Runtime configuration (set by Invoke-adPEAS)
    $Script:DefaultInactiveDays = $null
    $Script:IncludePrivilegedMode = $null
    $Script:adPEAS_OutputColor = $true
    $Script:adPEAS_VerboseLogging = $false
    $Script:StartTime = $null
    $Script:ModuleCategoryHeaders = $null

    # Output file (set by Invoke-adPEAS -Outputfile)
    $Script:adPEAS_Outputfile = $null
    $Script:HTMLOutputPath = $null
    $Script:JSONOutputPath = $null

    # ACE Inheritance source cache (parent ACL cache for Get-OUPermissions)
    $Script:InheritanceACLCache = $null

    # Exchange service group check cache (Test-IsExchangeServiceGroup)
    $Script:ExchangeGroupCache = $null

    # OU Permissions result cache (cross-module: DangerousOU, LAPS, PasswordReset)
    $Script:OUPermissionsCache = $null

    # Check module caches
    $Script:LAPSSchemaInfo = $null
    $Script:lapsGPOResults = $null
    $Script:AllForeignMembers = $null
    $Script:PrivilegedGroupSIDs = $null
    $Script:PrivilegedGroupRIDs = $null
    $Script:DynamicPrivilegedGroups = $null
    $Script:FilterAccountExpired = $null

    # GPO caches (Get-DomainGPO and Get-GPOLinkage)
    $Script:CachedAllGPOs = $null
    $Script:CachedGPOLinkage = $null

    # Collector metadata (Invoke-adPEASCollector)
    $Script:CollectorVersion = $null
    $Script:JsonVersion = $null
    $Script:CollectionTimestamp = $null
    $Script:CollectedParts = $null
    $Script:ProgressPadWidth = $null
    $Script:CursorUp = $null
    $Script:CursorDown = $null
    $Script:WriteCollectionStatus = $null
}
