function Get-GPOUserRightsAssignment {
    <#
    .SYNOPSIS
    Detects dangerous Windows user rights / privileges assigned to non-privileged
    principals via Group Policy.

    .DESCRIPTION
    Parses the [Privilege Rights] section of GptTmpl.inf in every GPO's SYSVOL folder
    and flags assignments of sensitive user rights to non-privileged principals.

    User Rights Assignment via GPO is a classic, often-overlooked privilege-escalation and
    lateral-movement vector: a single GPO can grant rights like "Debug programs"
    (SeDebugPrivilege), "Back up files and directories" (SeBackupPrivilege) or
    "Allow log on through Remote Desktop Services" to a low-privileged principal across
    every computer the GPO applies to.

    Covered rights (two tiers):
    - Finding (direct SYSTEM / credential / domain compromise): SeDebug, SeTcb,
      SeImpersonate, SeAssignPrimaryToken, SeCreateToken, SeLoadDriver, SeBackup, SeRestore,
      SeTakeOwnership, SeEnableDelegation, SeSyncAgent, SeManageVolume, SeSecurity,
      SeRelabel, SeTrustedCredManAccess.
    - Hint (lateral movement / lower direct impact): SeRemoteInteractiveLogonRight (RDP),
      SeServiceLogonRight, SeBatchLogonRight, SeInteractiveLogonRight, SeSystemtime,
      SeRemoteShutdown, SeShutdown.

    Any right granted to a broad principal (Everyone, Authenticated Users, Domain Users,
    Users) is escalated to Finding regardless of tier.

    Note: SeMachineAccountPrivilege ("Add workstations to domain") is intentionally NOT
    reported here - it is covered by Get-AddComputerRights. Protective Se*Deny* rights are
    ignored.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .PARAMETER IncludePrivileged
    Also report rights granted to privileged principals (Domain Admins, Administrators,
    etc.). By default these are hidden as expected.

    .EXAMPLE
    Get-GPOUserRightsAssignment

    .EXAMPLE
    Get-GPOUserRightsAssignment -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Rights
    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$IncludePrivileged
    )

    begin {
        Write-Log "[Get-GPOUserRightsAssignment] Starting check"
    }

    process {
        try {
            # Build connection parameters (exclude IncludePrivileged - not a connection parameter)
            $CredParams = @{}
            if ($Domain) { $CredParams['Domain'] = $Domain }
            if ($Server) { $CredParams['Server'] = $Server }
            if ($Credential) { $CredParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @CredParams)) {
                return
            }

            Show-SubHeader "Searching for dangerous user rights assigned via GPO..." -ObjectType "GPOUserRights"

            # Dangerous user rights -> friendly name + severity tier.
            # The attack-vector context lives in the GPO_DANGEROUS_USER_RIGHT finding definition
            # and is surfaced as an HTML tooltip (triggered on the 'userRight' attribute).
            $dangerousRights = [ordered]@{
                'SeDebugPrivilege'                = @{ Name = 'Debug programs';                                  Tier = 'Finding' }
                'SeTcbPrivilege'                  = @{ Name = 'Act as part of the operating system';              Tier = 'Finding' }
                'SeImpersonatePrivilege'          = @{ Name = 'Impersonate a client after authentication';       Tier = 'Finding' }
                'SeAssignPrimaryTokenPrivilege'   = @{ Name = 'Replace a process level token';                   Tier = 'Finding' }
                'SeCreateTokenPrivilege'          = @{ Name = 'Create a token object';                           Tier = 'Finding' }
                'SeLoadDriverPrivilege'           = @{ Name = 'Load and unload device drivers';                  Tier = 'Finding' }
                'SeBackupPrivilege'               = @{ Name = 'Back up files and directories';                   Tier = 'Finding' }
                'SeRestorePrivilege'              = @{ Name = 'Restore files and directories';                   Tier = 'Finding' }
                'SeTakeOwnershipPrivilege'        = @{ Name = 'Take ownership of files or other objects';        Tier = 'Finding' }
                'SeEnableDelegationPrivilege'     = @{ Name = 'Enable computer/user accounts to be trusted for delegation'; Tier = 'Finding' }
                'SeSyncAgentPrivilege'            = @{ Name = 'Synchronize directory service data';              Tier = 'Finding' }
                'SeManageVolumePrivilege'         = @{ Name = 'Perform volume maintenance tasks';                Tier = 'Finding' }
                'SeSecurityPrivilege'             = @{ Name = 'Manage auditing and security log';                Tier = 'Finding' }
                'SeRelabelPrivilege'              = @{ Name = 'Modify an object label';                          Tier = 'Finding' }
                'SeTrustedCredManAccessPrivilege' = @{ Name = 'Access Credential Manager as a trusted caller';   Tier = 'Finding' }
                'SeRemoteInteractiveLogonRight'   = @{ Name = 'Allow log on through Remote Desktop Services';    Tier = 'Hint' }
                'SeServiceLogonRight'             = @{ Name = 'Log on as a service';                             Tier = 'Hint' }
                'SeBatchLogonRight'               = @{ Name = 'Log on as a batch job';                           Tier = 'Hint' }
                'SeInteractiveLogonRight'         = @{ Name = 'Allow log on locally';                            Tier = 'Hint' }
                'SeSystemtimePrivilege'           = @{ Name = 'Change the system time';                          Tier = 'Hint' }
                'SeRemoteShutdownPrivilege'       = @{ Name = 'Force shutdown from a remote system';             Tier = 'Hint' }
                'SeShutdownPrivilege'             = @{ Name = 'Shut down the system';                            Tier = 'Hint' }
            }

            # Broad principals (Everyone, Authenticated Users, Domain Users, etc.) use the central
            # definitions in adPEAS-SIDs.ps1 ($Script:BroadGroupSIDs / $Script:BroadGroupRIDSuffixes)
            # via Test-IsBroadGroupSID / Test-IsBroadGroupRID. A sensitive right granted to one of
            # these is always escalated to Finding.

            # Enumerate GPOs and linkage once
            $gpos = @(Get-DomainGPO @CredParams)
            if ($gpos.Count -eq 0) {
                Show-Line "No GPOs found" -Class "Note"
                return
            }

            $gpoLinkage = Get-GPOLinkage
            $domainFQDN = $Script:LDAPContext.Domain
            $dcServer = $Script:LDAPContext.Server

            # Closure-visible state
            $includePriv = [bool]$IncludePrivileged
            $rightsMap = $dangerousRights
            $linkage = $gpoLinkage
            $Script:gpoUserRightsFindings = @()

            Invoke-SMBAccess -Description "Scanning GPO user rights assignments" -ScriptBlock {
                $sysvolPath = "\\$dcServer\SYSVOL\$domainFQDN\Policies"
                if (-not (Test-Path $sysvolPath)) {
                    Write-Log "[Get-GPOUserRightsAssignment] SYSVOL path not accessible: $sysvolPath"
                    return
                }

                $totalGPOs = @($gpos).Count
                $currentGPOIndex = 0
                foreach ($gpo in $gpos) {
                    $currentGPOIndex++
                    if ($totalGPOs -gt $Script:ProgressThreshold) {
                        Show-Progress -Activity "Scanning GPO user rights assignments" -Current $currentGPOIndex -Total $totalGPOs -ObjectName $gpo.displayName
                    }

                    $gptTmplPath = Join-Path $sysvolPath "$($gpo.Name)\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
                    $content = Get-CachedSYSVOLContent -Path $gptTmplPath
                    if (-not $content) { continue }
                    if ($content -notmatch '(?is)\[Privilege Rights\](.*?)(\[|$)') { continue }
                    $section = $Matches[1]

                    # Resolve linkage scope once per GPO
                    $gpoGUIDKey = $gpo.Name.ToUpper()
                    $links = if ($linkage) { $linkage[$gpoGUIDKey] } else { $null }
                    $activeLinks = @()
                    $isDomainWide = $false
                    if ($links) {
                        $activeLinks = @($links | Where-Object { $_.LinkStatus -ne "Disabled" })
                        $isDomainWide = ($null -ne ($activeLinks | Where-Object { $_.Scope -eq "Domain" }))
                    }
                    if (@($activeLinks).Count -gt 0) {
                        $linkedOUs = @($activeLinks | ForEach-Object { $_.DistinguishedName })
                        $scopeInfo = if ($isDomainWide) { "Domain-wide ($(@($activeLinks).Count) link(s))" } else { "$(@($activeLinks).Count) OU(s)" }
                    } else {
                        $linkedOUs = @()
                        $scopeInfo = "NOT LINKED"
                    }

                    foreach ($right in $rightsMap.Keys) {
                        $pattern = '(?im)^\s*' + [regex]::Escape($right) + '\s*=\s*(.+)$'
                        $m = [regex]::Match($section, $pattern)
                        if (-not $m.Success) { continue }

                        $tokens = $m.Groups[1].Value -split ',' | ForEach-Object { $_.Trim() }
                        $keptNames = @()
                        $anyBroad = $false

                        foreach ($token in $tokens) {
                            $raw = $token.TrimStart('*')
                            if ([string]::IsNullOrWhiteSpace($raw)) { continue }

                            # Resolve literal account names to a SID for consistent classification
                            # (GptTmpl.inf almost always uses *SID, but names can appear).
                            $sid = $raw
                            if ($raw -notmatch '^S-1-') {
                                $resolved = $null
                                try { $resolved = ConvertTo-SID -Identity $raw } catch { }
                                if ($resolved) { $sid = $resolved }
                            }

                            if ($sid -match '^S-1-') {
                                # Skip principals that are expected to hold user rights by default:
                                #  - privileged SIDs/RIDs (Administrators, Domain Admins, SYSTEM, ...)
                                #  - built-in operator groups (Account/Server/Print/Backup Operators) - the
                                #    Default Domain Controllers Policy grants these to them by design
                                #  - well-known service / builtin-support identities (SERVICE, IIS_IUSRS,
                                #    Performance Log Users, ...) - default holders, not privesc targets
                                $isPriv = (Test-IsPrivilegedSID -SID $sid) -or
                                          [bool](Test-IsPrivilegedRID -SID $sid) -or
                                          ($Script:OperatorSIDs -contains $sid) -or
                                          (Test-IsWellKnownServiceSID -SID $sid)
                                if ($isPriv -and -not $includePriv) { continue }
                                if ((Test-IsBroadGroupSID -SID $sid) -or [bool](Test-IsBroadGroupRID -SID $sid)) { $anyBroad = $true }
                                $keptNames += (ConvertFrom-SID -SID $sid)
                            } else {
                                # Unresolvable literal - include as-is (cannot classify)
                                $keptNames += $raw
                            }
                        }

                        if ($keptNames.Count -eq 0) { continue }

                        $info = $rightsMap[$right]
                        $severity = if ($anyBroad) { 'Finding' } else { $info.Tier }

                        $finding = [PSCustomObject]@{
                            gpoName       = $gpo.displayName
                            gpoGuid       = $gpo.Name
                            userRight     = $right
                            userRightName = $info.Name
                            principals    = $keptNames
                            scope         = $scopeInfo
                            linkedOUs     = $linkedOUs
                            _severity     = $severity
                        }
                        $Script:gpoUserRightsFindings += $finding
                    }
                }

                if ($totalGPOs -gt $Script:ProgressThreshold) {
                    Show-Progress -Activity "Scanning GPO user rights assignments" -Completed
                }
            }

            $findings = @($Script:gpoUserRightsFindings)
            $Script:gpoUserRightsFindings = $null

            if ($findings.Count -gt 0) {
                # Header severity reflects the highest finding severity (red only if a real Finding exists)
                $hasFinding = @($findings | Where-Object { $_._severity -eq 'Finding' }).Count -gt 0
                $headerClass = if ($hasFinding) { "Finding" } else { "Hint" }
                Show-Line "Found $($findings.Count) dangerous user right assignment(s) via GPO:" -Class $headerClass
                # Findings first, then hints (severity order)
                $ordered = @($findings | Sort-Object @{Expression={ if ($_._severity -eq 'Finding') { 0 } else { 1 } }}, gpoName, userRight)
                foreach ($finding in $ordered) {
                    $finding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPOUserRights' -Force
                    Show-Object $finding -Class $finding._severity
                }
            } elseif ((Test-SysvolAccessible) -eq $false) {
                # SYSVOL could not be read - report honestly instead of implying a clean result
                Show-Line "SYSVOL is not accessible - GPO user rights could not be evaluated" -Class "Note"
            } else {
                Show-Line "No dangerous user rights assigned via GPO to non-privileged principals" -Class "Secure"
            }

        } catch {
            Write-Log "[Get-GPOUserRightsAssignment] Error: $_" -Level Error
            Show-Line "Error during check: $_" -Class "Finding"
        } finally {
            $Script:gpoUserRightsFindings = $null
        }
    }

    end {
        Write-Log "[Get-GPOUserRightsAssignment] Check completed"
    }
}
