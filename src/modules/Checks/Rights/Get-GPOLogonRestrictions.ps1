function Get-GPOLogonRestrictions {
    <#
    .SYNOPSIS
    Reports which logons Group Policy denies, to whom and on which machines - and what no
    policy denies.

    .DESCRIPTION
    The five deny rights of [Privilege Rights] in GptTmpl.inf - Deny access to this computer
    from the network, Deny log on locally, Deny log on through Remote Desktop Services,
    Deny log on as a batch job, Deny log on as a service - take one kind of logon away from
    the principals they name, and win over every right that would allow it (Microsoft,
    Deny access to this computer from the network). They grant nothing, so the question
    Get-GPOUserRightsAssignment asks - a holder beyond the Windows default - does not fit
    them. Their presence is the hardening, and their absence the gap.

    Per policy that sets one, the principals denied each logon on the machines the policy
    reaches, read three ways:

    - Domain Admins, or a group Domain Admins is a member of, denied a logon on member
      computers: their credentials stay off those machines (Microsoft, Best Practices for
      Securing Active Directory, Appendix F).
    - Local administrator accounts denied on member computers - Local account and member of
      Administrators group (S-1-5-114), Local account (S-1-5-113), or the local
      Administrator account written by its name, which is how Appendix H enters it: a local
      administrator's credentials stop working from one machine to the next.
    - A broad group denied - Everyone, Authenticated Users, Users, Domain Users, Domain
      Computers, NETWORK, INTERACTIVE - locks out every account in it, administrators
      included; and Domain Admins denied a logon on domain controllers locks them out of
      the domain's own servers. Both are reported as a Hint.

    Across the policies that apply: whether any denies Domain Admins the local or Remote
    Desktop logon on member computers, and whether any denies local administrator accounts
    the network logon there. Neither is the Windows default, which denies the Guest account
    alone. Over SYSVOL folders the account could not read, an absence is not claimed.

    Not evaluated: which of several policies that set the same right wins on a machine, and
    settings made in a machine's own local policy.

    Requires SMB access to SYSVOL.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .PARAMETER IncludeInactive
    Also list the policies that are not linked or whose computer configuration is disabled.

    .EXAMPLE
    Get-GPOLogonRestrictions

    .NOTES
    Category: Rights
    Author: Alexander Sturz (@_61106960_)
    Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-f--securing-domain-admins-groups-in-active-directory
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
        [switch]$IncludeInactive
    )

    begin {
        Write-Log "[Get-GPOLogonRestrictions] Starting check"
    }

    process {
        try {
            $CredParams = @{}
            if ($Domain) { $CredParams['Domain'] = $Domain }
            if ($Server) { $CredParams['Server'] = $Server }
            if ($Credential) { $CredParams['Credential'] = $Credential }

            if (-not (Ensure-LDAPConnection @CredParams)) {
                return
            }

            Show-SubHeader "Checking which logons Group Policy denies..." -ObjectType "GPOLogonRestriction"

            $gpos = @(Get-DomainGPO @CredParams)
            if ($gpos.Count -eq 0) {
                Show-Line "No GPOs found" -Class "Note"
                return
            }

            $gpoLinkage = Get-GPOLinkage
            $gpoStatusMap = Get-GPOStatusMap -GPO $gpos
            $domainFQDN = $Script:LDAPContext.Domain
            $dcServer = $Script:LDAPContext.Server
            $domainDN = $Script:LDAPContext.DomainDN
            $domainSID = [string]$Script:LDAPContext.DomainSID

            # Closure-visible state: Invoke-SMBAccess resolves the block's variables from here.
            $linkage = $gpoLinkage
            $statusMap = $gpoStatusMap
            $dcOU = if ($domainDN) { "OU=Domain Controllers,$domainDN" } else { $null }

            # Domain Admins, and every group Domain Admins is a member of: a deny entry that
            # names any of them denies Domain Admins. Not the BUILTIN groups among them -
            # Domain Admins is a member of the domain's Administrators, but S-1-5-32-544 on a
            # member computer is that machine's own Administrators group, and denying it
            # says something about every local administrator, not about Domain Admins.
            $tier0SIDs = @{}
            if ($domainSID) {
                $domainAdminsSID = "$domainSID-512"
                $tier0SIDs[$domainAdminsSID] = $true
                foreach ($groupSID in @(Get-RecursiveGroupMembership -IdentitySID $domainAdminsSID)) {
                    if ($groupSID -and -not ([string]$groupSID).StartsWith('S-1-5-32-')) { $tier0SIDs[[string]$groupSID] = $true }
                }
            }

            $Script:gpoLogonRestrictions = @()
            # Whether the Policies path was read at all - without it a scan that never ran
            # would read as a domain that denies nothing.
            $Script:gpoLogonRestrictionsScanned = $false

            Invoke-SMBAccess -Description "Scanning GPO logon restrictions" -ScriptBlock {
                $sysvolPath = "\\$dcServer\SYSVOL\$domainFQDN\Policies"
                if (-not (Test-Path $sysvolPath)) {
                    Write-Log "[Get-GPOLogonRestrictions] SYSVOL path not accessible: $sysvolPath"
                    return
                }
                $Script:gpoLogonRestrictionsScanned = $true

                $gpoByGuid = @{}
                foreach ($g in $gpos) {
                    if ($g.Name) { $gpoByGuid[([string]$g.Name).ToUpper()] = $g }
                }

                foreach ($file in @(Get-CachedSYSVOLFiles -Filter "GptTmpl.inf")) {
                    if ($file.FullName -notmatch '\\Policies\\(\{[^}]+\})\\') { continue }
                    $gpoGUIDKey = $Matches[1].ToUpper()
                    $gpo = $gpoByGuid[$gpoGUIDKey]
                    if (-not $gpo) { continue }
                    # [Privilege Rights] is a Computer Configuration section; a GptTmpl.inf
                    # under USER has no meaning for it.
                    if ($file.FullName -notmatch '(?i)\\Policies\\\{[^}]+\}\\MACHINE\\') { continue }

                    $content = Get-CachedSYSVOLContent -Path $file.FullName
                    if (-not $content) { continue }
                    if ($content -notmatch '(?is)\[Privilege Rights\](.*?)(\[|$)') { continue }
                    $section = $Matches[1]

                    # Each deny right the section sets, and whom it names. An emptied right is
                    # a statement as well: it removes the Guest account the default denies.
                    $denials = [ordered]@{}
                    foreach ($right in $Script:LogonDenyRights.Keys) {
                        $m = [regex]::Match($section, '(?im)^[ \t]*' + [regex]::Escape($right) + '[ \t]*=[ \t]*([^\r\n]*)')
                        if ($m.Success) { $denials[$right] = @(ConvertFrom-GPOLogonDenyValue -Value $m.Groups[1].Value) }
                    }
                    if ($denials.Count -eq 0) { continue }

                    # Where the policy applies. $null only when the linkage was never
                    # resolved; a GUID absent from a resolved map has no links, @().
                    $links = $null
                    if ($linkage) {
                        $links = @()
                        if ($linkage.ContainsKey($gpoGUIDKey)) { $links = @($linkage[$gpoGUIDKey]) }
                    }
                    $activeLinks = @()
                    if ($links) { $activeLinks = @($links | Where-Object { $_.LinkStatus -ne 'Disabled' }) }
                    $reach = Get-GPOMachineScope -GPOGUID $gpoGUIDKey -ActiveLink $activeLinks -DomainControllersOU $dcOU

                    $verdict = Get-GPOLogonDenialVerdict -Denial $denials -Reach $reach -Tier0SID $tier0SIDs

                    $restriction = [ordered]@{
                        GPOName    = $gpo.displayName
                        GPOGUID    = $gpo.Name
                        GPOPath    = $gpo.gPCFileSysPath
                        SourceFile = Get-GPORelativePath -Path $file.FullName
                        AppliesTo  = $reach.Text
                    }
                    foreach ($right in $Script:LogonDenyRights.Keys) {
                        if (-not $denials.Contains($right)) { continue }
                        $names = @($denials[$right] | ForEach-Object { $_.Name })
                        $restriction[$Script:LogonDenyRights[$right].Property] = $(if ($names.Count -gt 0) { $names } else { '(nobody)' })
                    }
                    if (@($verdict.Text).Count -gt 0) { $restriction['LogonVerdict'] = @($verdict.Text) }
                    $object = [PSCustomObject]$restriction

                    $object | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $(if ($null -eq $links) { 'Unknown - linkage could not be resolved' } else { $links }) -Force
                    Add-GPODomainControllerReach -Object $object -Reach (Get-GPODomainControllerReachDetail -Link $links -GPOGUID $gpo.Name)
                    Add-GPOConditionRow -Object $object -GPOGUID $gpo.Name

                    $gpoStatus = Get-GPOEffectiveStatus -StatusEntry $statusMap[$gpoGUIDKey] `
                        -Scope 'Machine' -Link $(if ($null -eq $linkage) { $null } else { $links })
                    if ($gpoStatus) { $object | Add-Member -NotePropertyName 'GPOStatus' -NotePropertyValue $gpoStatus -Force }

                    # Off the display - the type is strict - and read by the conclusions below.
                    $object | Add-Member -NotePropertyName '_severity' -NotePropertyValue $verdict.Severity -Force
                    $object | Add-Member -NotePropertyName '_tier0Logons' -NotePropertyValue @($verdict.Tier0Logons) -Force
                    $object | Add-Member -NotePropertyName '_localAdminLogons' -NotePropertyValue @($verdict.LocalAdminLogons) -Force

                    $Script:gpoLogonRestrictions += $object
                }
            }

            $restrictions = @($Script:gpoLogonRestrictions)
            $scanned = [bool]$Script:gpoLogonRestrictionsScanned
            $Script:gpoLogonRestrictions = $null
            $Script:gpoLogonRestrictionsScanned = $null

            if (-not $scanned) {
                if ((Test-SysvolAccessible) -eq $false) {
                    Show-Line "SYSVOL is not accessible - GPO logon restrictions could not be evaluated" -Class "Note"
                } else {
                    Show-Line "SYSVOL access failed - GPO logon restrictions could not be evaluated - SMB access failed (authentication/network issue)" -Class "Finding"
                }
                return
            }

            # A policy that reaches no machine denies nothing today: it is named in the
            # dampening line and does not count towards the conclusions.
            $split = Split-GPOFindingByReach -Finding $restrictions -GPOStatusMap $gpoStatusMap `
                -GPOLinkage $gpoLinkage -Scope 'Machine'
            $active = @($split.Active)
            Show-GPOInactiveSummary -Unlinked $split.Unlinked -Disabled $split.Disabled `
                -Dormant $split.Dormant -Listed:$IncludeInactive

            # What was read decides what may be claimed: an absence over folders the account
            # could not read is not an absence.
            $partial = [bool](Show-SYSVOLCoverageNote -FileFilter @('GptTmpl.inf'))

            # Domain Admins on member computers - the logons that leave credentials behind.
            $tier0Policies = @($active | Where-Object { @($_._tier0Logons | Where-Object { @('local', 'remote desktop') -contains $_ }).Count -gt 0 })
            if ($tier0Policies.Count -gt 0) {
                $logons = @($tier0Policies | ForEach-Object { $_._tier0Logons } | Select-Object -Unique)
                Show-Line "Domain Admins are denied the $($logons -join ', ') logon on member computers by $($tier0Policies.Count) policy(s)" -Class Secure
            } elseif ($partial) {
                Show-Line "No readable policy denies Domain Admins the local or Remote Desktop logon on member computers" -Class Note
            } else {
                Show-Line "No policy denies Domain Admins the local or Remote Desktop logon on member computers" -Class Hint -FindingId 'GPO_TIER0_LOGON_NOT_DENIED'
            }

            # Local administrator accounts and the network logon - the reuse of one machine's
            # local administrator on the next.
            $localPolicies = @($active | Where-Object { @($_._localAdminLogons) -contains 'network' })
            if ($localPolicies.Count -gt 0) {
                Show-Line "Local administrator accounts are denied the network logon on member computers by $($localPolicies.Count) policy(s)" -Class Secure
            } elseif ($partial) {
                Show-Line "No readable policy denies local administrator accounts the network logon on member computers" -Class Note
            } else {
                Show-Line "No policy denies local administrator accounts the network logon on member computers" -Class Hint -FindingId 'GPO_LOCAL_ADMIN_NETWORK_NOT_DENIED'
            }

            $shown = if ($IncludeInactive) { @($restrictions) } else { $active }
            if (@($shown).Count -eq 0) { return }

            $hasHint = @($shown | Where-Object { $_._severity -eq 'Hint' }).Count -gt 0
            Show-Line "Found $(@($shown).Count) policy(s) that deny a logon:" -Class $(if ($hasHint) { 'Hint' } else { 'Note' })
            $ordered = @($shown | Sort-Object @{ Expression = {
                switch ($_._severity) { 'Hint' { 0 } 'Secure' { 1 } default { 2 } }
            } }, GPOName)
            foreach ($restriction in $ordered) {
                $restriction | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPOLogonRestriction' -Force
                # One that reaches no machine is printed as a note whatever it denies.
                $class = if (@($split.Inactive) -contains $restriction) { 'Note' } else { $restriction._severity }
                Show-Object $restriction -Class $class
            }

        } catch {
            Write-Log "[Get-GPOLogonRestrictions] Error: $_" -Level Error
            Show-Line "Error during check - the logon restrictions of the GPOs could not be evaluated: $_" -Class "Finding"
        } finally {
            $Script:gpoLogonRestrictions = $null
            $Script:gpoLogonRestrictionsScanned = $null
        }
    }

    end {
        Write-Log "[Get-GPOLogonRestrictions] Check completed"
    }
}

<#
.SYNOPSIS
    The principals one deny right of a GptTmpl.inf names, each with its SID where it has one.

.DESCRIPTION
    GptTmpl.inf writes a principal as *SID. A name with a domain - CONTOSO\Helpdesk - is a
    directory principal and resolved to its SID. A bare name is an account of each machine
    the policy reaches: that is how Microsoft's Appendix H enters the local Administrator
    account, and resolving it in the domain would turn it into the domain's Administrator.
    It keeps no SID and is marked Local.

.OUTPUTS
    PSCustomObject per principal: SID ('' where there is none), Name, RawName, Local.

.NOTES
    Internal helper function
#>
function ConvertFrom-GPOLogonDenyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [AllowEmptyString()]
        [string]$Value
    )

    foreach ($token in ($Value -split ',')) {
        $raw = $token.Trim()
        $isSidForm = $raw.StartsWith('*')
        $raw = $raw.TrimStart('*').Trim()
        if (-not $raw) { continue }

        if ($raw -match '^S-1-') {
            $name = $null
            try { $name = ConvertFrom-SID -SID $raw } catch { }
            [PSCustomObject]@{ SID = $raw; Name = $(if ($name) { [string]$name } else { $raw }); RawName = $raw; Local = $false }
            continue
        }

        # A domain-qualified name - the separator built from its code point, so that no
        # literal can lose it on the way into the file.
        if ($isSidForm -or $raw.IndexOf([char]92) -ge 0) {
            $resolved = $null
            try { $resolved = ConvertTo-SID -Identity $raw } catch { }
            [PSCustomObject]@{ SID = $(if ($resolved) { [string]$resolved } else { '' }); Name = $raw; RawName = $raw; Local = $false }
            continue
        }

        [PSCustomObject]@{ SID = ''; Name = "$raw (local account)"; RawName = $raw; Local = $true }
    }
}

<#
.SYNOPSIS
    Whether a SID denies a logon to so many accounts that it locks out the ones that need it.

.DESCRIPTION
    Everyone, Authenticated Users, Users, NETWORK and INTERACTIVE, and the domain-relative
    Domain Users and Domain Computers. Guests and Anonymous Logon are not among them - those
    are what a deny right is for.

.NOTES
    Internal helper function
#>
function Test-GPOLogonLockoutSID {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory=$false)]
        [AllowEmptyString()]
        [string]$SID
    )

    if (-not $SID) { return $false }
    if (@('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-2', 'S-1-5-4') -contains $SID) { return $true }
    return ($SID -match '^S-1-5-21-\d+-\d+-\d+-(513|515)$')
}

<#
.SYNOPSIS
    What one policy's deny rights amount to on the machines it reaches.

.DESCRIPTION
    Closed verdict strings, one per statement, each starting with its own words so that
    no two finding triggers can match the same one:

    - "Locks out every account of ..." - a broad group denied a logon
    - "Locks out Domain Admins on domain controllers ..." - the policy reaches a domain
      controller and denies Domain Admins a logon there
    - "Keeps Domain Admins off member computers ..." - denied on member computers
    - "Keeps local administrators off member computers ..." - S-1-5-114, S-1-5-113 or the
      local Administrator account by name, denied on member computers

    A lockout is a Hint, the other two Secure; a policy that only denies anyone else -
    Guests, a service account - carries no verdict.

.OUTPUTS
    PSCustomObject: Text (verdict strings), Severity, Tier0Logons, LocalAdminLogons.

.NOTES
    Internal helper function
#>
function Get-GPOLogonDenialVerdict {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] $Denial,
        [Parameter(Mandatory=$true)] $Reach,
        [Parameter(Mandatory=$false)] [hashtable]$Tier0SID = @{}
    )

    $lockouts = @()
    $tier0OnMembers = @()
    $tier0OnDCs = @()
    $localAdmin = @()

    foreach ($right in $Denial.Keys) {
        $logon = $Script:LogonDenyRights[$right].Logon
        foreach ($entry in @($Denial[$right])) {
            $sid = [string]$entry.SID
            if (Test-GPOLogonLockoutSID -SID $sid) { $lockouts += "$($entry.Name) ($logon)" }
            if ($sid -and $Tier0SID.ContainsKey($sid)) {
                if ($Reach.ReachesMember) { $tier0OnMembers += $logon }
                if ($Reach.ReachesDC) { $tier0OnDCs += $logon }
            }
            $isLocalAdmin = ($sid -eq 'S-1-5-114') -or ($sid -eq 'S-1-5-113') -or ($entry.Local -and [string]$entry.RawName -eq 'Administrator')
            if ($isLocalAdmin -and $Reach.ReachesMember) { $localAdmin += $logon }
        }
    }

    $tier0OnMembers = @($tier0OnMembers | Select-Object -Unique)
    $tier0OnDCs = @($tier0OnDCs | Select-Object -Unique)
    $localAdmin = @($localAdmin | Select-Object -Unique)

    $text = @()
    if ($lockouts.Count -gt 0) { $text += "Locks out every account of $(@($lockouts | Select-Object -Unique) -join ', ')" }
    if ($tier0OnDCs.Count -gt 0) { $text += "Locks out Domain Admins on domain controllers: $($tier0OnDCs -join ', ')" }
    if ($tier0OnMembers.Count -gt 0) { $text += "Keeps Domain Admins off member computers: $($tier0OnMembers -join ', ')" }
    if ($localAdmin.Count -gt 0) { $text += "Keeps local administrators off member computers: $($localAdmin -join ', ')" }

    $severity = 'Standard'
    if ($tier0OnMembers.Count -gt 0 -or $localAdmin.Count -gt 0) { $severity = 'Secure' }
    if ($lockouts.Count -gt 0 -or $tier0OnDCs.Count -gt 0) { $severity = 'Hint' }

    return [PSCustomObject]@{
        Text             = $text
        Severity         = $severity
        Tier0Logons      = $tier0OnMembers
        LocalAdminLogons = $localAdmin
    }
}
