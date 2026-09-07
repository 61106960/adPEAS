function Test-GPOCoversDomainControllers {
    <#
    .SYNOPSIS
    Decides whether a set of GPO links reaches the domain controllers.

    .DESCRIPTION
    LDAP signing and channel binding are settings on the DCs themselves, so a GPO that
    configures them only matters if it actually applies to a DC. A domain-wide link does,
    and so does a link at or above the OU each DC sits in - which is where the Default
    Domain Controllers Policy lives, and where an admin hardening LDAP normally puts it.

    .PARAMETER ActiveLink
    The links of one GPO, already filtered to the enabled ones.

    .PARAMETER DomainController
    The domain controller objects, used for their distinguishedName.

    .OUTPUTS
    Boolean.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [object[]]$ActiveLink,

        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [object[]]$DomainController
    )

    $links = @($ActiveLink | Where-Object { $_ })
    if ($links.Count -eq 0) { return $false }

    if ($null -ne ($links | Where-Object { $_.Scope -eq "Domain" })) { return $true }

    foreach ($dc in @($DomainController | Where-Object { $_ })) {
        if ("$($dc.distinguishedName)" -notmatch '^CN=[^,]+,(.+)$') { continue }
        $dcParentDN = $Matches[1]
        foreach ($link in $links) {
            $linkDN = "$($link.DistinguishedName)"
            if ($linkDN.Length -eq 0) { continue }

            # The link DN is an ancestor of the DC's parent OU when it is a suffix of it,
            # and the comma keeps the suffix on an RDN boundary.
            #
            # EndsWith rather than -like on purpose: -like reads [ and ] as a character
            # class, and an OU named "[Tier 0] Domain Controllers" is an ordinary way to
            # name one. The pattern then matches nothing and the GPO that hardens the
            # domain controllers is reported as not reaching them.
            $cmp = [System.StringComparison]::OrdinalIgnoreCase
            if ($dcParentDN.Equals($linkDN, $cmp) -or $dcParentDN.EndsWith(',' + $linkDN, $cmp)) {
                return $true
            }
        }
    }

    return $false
}

function Get-LDAPConfiguration {
    <#
    .SYNOPSIS
    Checks LDAP Security Configuration (Signing + Channel Binding + Anonymous Binding).

    .DESCRIPTION
    Analyzes LDAP security configuration on Domain Controllers:

    1. LDAP Signing: Protects against LDAP Relay attacks
       - None (0): Insecure
       - Optional (1): Partially Secure
       - Required (2): Secure

    2. LDAP Channel Binding: Protection against Man-in-the-Middle
       - Never (0): Insecure
       - When Supported (1): Partially Secure
       - Always (2): Secure

    3. Anonymous LDAP Binding: Prevents unauthenticated AD enumeration
       - Allowed: Insecure
       - Restricted: Secure

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-LDAPConfiguration

    .EXAMPLE
    Get-LDAPConfiguration -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Domain
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
        Write-Log "[Get-LDAPConfiguration] Starting check"
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            Show-SubHeader "Analyzing LDAP Signing/Channel Binding via GPO (SYSVOL)..." -ObjectType "LDAPConfigGPO"

            $domainFQDN = $Script:LDAPContext.Domain
            $dcServer = $Script:LDAPContext.Server

            $allGPOs = Get-DomainGPO @PSBoundParameters

            if (-not $allGPOs) {
                Show-Line "No GPOs found" -Class Hint
                return
            }

            # Indexed once for the whole check: every finding below reports the state of its
            # policy as GPOStatus, the way the other GPO checks do.
            $gpoStatusMap = Get-GPOStatusMap -GPO $allGPOs

            # Get Domain Controllers
            # -DomainController rather than the SERVER_TRUST_ACCOUNT bit written out: an
            # RODC does not carry that bit and answers LDAP just the same, so the count
            # below was short and the configuration of every read-only DC went unexamined.
            $domainControllers = @(Get-DomainComputer -DomainController @PSBoundParameters)

            $dcCount = $domainControllers.Count

            # Use Invoke-SMBAccess for SYSVOL access (handles SimpleBind credentials)
            $Script:gpoFindings = @()
            $Script:sysvolAccessible = $false

            Invoke-SMBAccess -Description "Scanning SYSVOL for LDAP configuration GPOs" -ScriptBlock {
                $sysvolPath = "\\$dcServer\SYSVOL\$domainFQDN\Policies"

                # Test SYSVOL access
                if (-not (Test-Path $sysvolPath)) {
                    Write-Log "[Get-LDAPConfiguration] SYSVOL path not accessible: $sysvolPath"
                    return
                }

                $Script:sysvolAccessible = $true

                # Iterate the cached SYSVOL listing instead of probing a constructed path per GPO:
                # most GPOs have no GptTmpl.inf, so per-GPO probing costs one SMB round-trip each
                # for a file that usually does not exist.
                $gptTmplFiles = @(Get-CachedSYSVOLFiles -Filter "GptTmpl.inf")

                # GPO GUID -> GPO object, to resolve the file back to its GPO
                $gpoByGuid = @{}
                foreach ($g in $allGPOs) {
                    if ($g.Name) { $gpoByGuid[$g.Name.ToUpper()] = $g }
                }

                # ----- Channel binding, which does not live in GptTmpl.inf -----
                #
                # LDAPServerIntegrity is a Security Option and lands in GptTmpl.inf, so the
                # parser below finds it. LdapEnforceChannelBinding has no Security Option
                # UI at all: it is a plain registry value, and Group Policy carries it in
                # Registry.pol instead. Reading only GptTmpl.inf meant a domain that
                # enforces channel binding correctly was told every one of its domain
                # controllers was potentially vulnerable - a false alarm aimed precisely at
                # the domains that had done the right thing.
                $channelBindingByGpo = @{}
                foreach ($polFile in @(Get-CachedSYSVOLFiles -Filter "Registry.pol")) {
                    if ($polFile.FullName -notmatch '\\Policies\\(\{[^}]+\})\\') { continue }
                    # Read the capture out before the next comparison, which overwrites
                    # $Matches even when it is a -notmatch that comes out false
                    $polGuid = $Matches[1].ToUpper()

                    # Machine\Registry.pol only. The value lives under HKLM and a user-side
                    # policy cannot set it.
                    if ($polFile.FullName -notmatch '\\Machine\\') { continue }

                    try {
                        foreach ($record in @(Parse-PRegRecords -PolFilePath $polFile.FullName -Hive 'HKLM')) {
                            if ($record.ValueName -ine 'LdapEnforceChannelBinding') { continue }
                            if ("$($record.Key)" -notmatch 'Services\\NTDS\\Parameters$') { continue }
                            # REG_DWORD (4) only - the value is a number, and anything else
                            # written under this name is not the setting we are reading
                            if ($record.Type -ne 4) { continue }
                            if ($null -eq $record.ValueInt) { continue }

                            $channelBindingByGpo[$polGuid] = [int]$record.ValueInt
                            Write-Log "[Get-LDAPConfiguration] Channel binding $($record.ValueInt) from Registry.pol of $polGuid"
                        }
                    } catch {
                        Write-Log "[Get-LDAPConfiguration] Could not read $($polFile.FullName): $($_.Exception.Message)"
                    }
                }

                # Parse GPOs for LDAP Security settings
                $totalGPOs = $gptTmplFiles.Count
                $currentGPOIndex = 0
                foreach ($file in $gptTmplFiles) {
                    # Extract GPO GUID from path: ...\Policies\{GUID}\Machine\...
                    if ($file.FullName -notmatch '\\Policies\\(\{[^}]+\})\\') { continue }
                    $gpo = $gpoByGuid[$Matches[1].ToUpper()]
                    if (-not $gpo) { continue }

                    $currentGPOIndex++
                    if ($totalGPOs -gt $Script:ProgressThreshold) {
                        Show-Progress -Activity "Scanning LDAP configuration GPO settings" -Current $currentGPOIndex -Total $totalGPOs -ObjectName $gpo.DisplayName
                    }

                    $content = Get-CachedSYSVOLContent -Path $file.FullName
                    if ($content) {
                        # Initialize values
                        $ldapSigningValue = $null
                        $ldapChannelBindingValue = $null
                        $restrictAnonymous = $null
                        $lsaAnonymousNameLookup = $null

                        # Parse Registry Values section
                        if ($content -match '(?s)\[Registry Values\](.*?)(\[|$)') {
                            $registrySection = $Matches[1]

                            # GptTmpl.inf format: MACHINE\...\LDAPServerIntegrity=4,<value> (4 = REG_DWORD)
                            #
                            # The value name is anchored with \s*=\s* instead of .*?=.*? on purpose.
                            # The loose form also matched a LONGER value name sharing the same prefix:
                            # 'RestrictAnonymous' matched 'RestrictAnonymousSAM=4,1', and since that
                            # line comes first in a normal DC baseline, the check read the wrong value
                            # and reported anonymous binding as restricted while it was allowed.
                            if ($registrySection -match 'MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity\s*=\s*4\s*,\s*(\d+)') {
                                $ldapSigningValue = [int]$Matches[1]
                            }
                            if ($registrySection -match 'MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LdapEnforceChannelBinding\s*=\s*4\s*,\s*(\d+)') {
                                $ldapChannelBindingValue = [int]$Matches[1]
                            }
                            if ($registrySection -match 'MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous\s*=\s*4\s*,\s*(\d+)') {
                                $restrictAnonymous = [int]$Matches[1]
                            }
                        }

                        # A hand-written GptTmpl.inf can carry channel binding, but Group
                        # Policy normally puts it in Registry.pol. Consumed here so the pass
                        # after the loop does not report the same GPO a second time.
                        $gpoGuidKey = ([string]$gpo.Name).ToUpper()
                        if ($null -eq $ldapChannelBindingValue -and $channelBindingByGpo.ContainsKey($gpoGuidKey)) {
                            $ldapChannelBindingValue = $channelBindingByGpo[$gpoGuidKey]
                            $channelBindingByGpo.Remove($gpoGuidKey)
                        }

                        # Parse System Access section
                        if ($content -match '(?s)\[System Access\](.*?)(\[|$)') {
                            $systemAccessSection = $Matches[1]
                            if ($systemAccessSection -match 'LSAAnonymousNameLookup\s*=\s*(\d+)') {
                                $lsaAnonymousNameLookup = [int]$Matches[1]
                            }
                        }

                        # If any LDAP security settings found
                        if ($null -ne $ldapSigningValue -or $null -ne $ldapChannelBindingValue -or
                            $null -ne $restrictAnonymous -or $null -ne $lsaAnonymousNameLookup) {

                            $signingLevel = if ($null -ne $ldapSigningValue) {
                                switch ($ldapSigningValue) {
                                    0 { "None" }
                                    1 { "Optional" }
                                    2 { "Required" }
                                    default { "Unknown" }
                                }
                            } else { "Not Configured" }

                            $channelBindingLevel = if ($null -ne $ldapChannelBindingValue) {
                                switch ($ldapChannelBindingValue) {
                                    0 { "Never" }
                                    1 { "When Supported" }
                                    2 { "Always" }
                                    default { "Unknown" }
                                }
                            } else { "Not Configured" }

                            $anonymousBindingStatus = "Not Configured"
                            if ($null -ne $restrictAnonymous) {
                                $anonymousBindingStatus = if ($restrictAnonymous -eq 0) { "Allowed" } else { "Restricted" }
                            } elseif ($null -ne $lsaAnonymousNameLookup) {
                                $anonymousBindingStatus = if ($lsaAnonymousNameLookup -eq 1) { "Allowed" } else { "Restricted" }
                            }

                            # Get GPO linkage
                            $gpoLinkage = Get-GPOLinkage
                            # Normalize GUID to uppercase for hashtable lookup (Get-GPOLinkage uses uppercase keys)
                            $gpoNameUpper = $gpo.Name.ToUpper()
                            $links = $gpoLinkage[$gpoNameUpper]
                            $activeLinks = @()
                            $isDomainWide = $false
                            $coversDCs = $false

                            if ($links) {
                                $activeLinks = @($links | Where-Object { $_.LinkStatus -ne "Disabled" })
                                $domainWide = $activeLinks | Where-Object { $_.Scope -eq "Domain" }
                                $isDomainWide = ($null -ne $domainWide)
                                $coversDCs = Test-GPOCoversDomainControllers -ActiveLink $activeLinks -DomainController $domainControllers
                            }

                            # Enrich the native GPO object with LDAP security attributes
                            $gpo | Add-Member -NotePropertyName "LDAPSigning" -NotePropertyValue $signingLevel -Force
                            $gpo | Add-Member -NotePropertyName "ChannelBinding" -NotePropertyValue $channelBindingLevel -Force
                            $gpo | Add-Member -NotePropertyName "AnonymousBinding" -NotePropertyValue $anonymousBindingStatus -Force
                            $gpo | Add-Member -NotePropertyName "CoversDCs" -NotePropertyValue $coversDCs -Force

                            # Where the policy applies. The full link records, disabled ones
                            # included - the LinkedOUs transformer marks those and renders an
                            # empty list as "Not linked". The Scope attribute this replaces
                            # said the same thing in a second vocabulary and a count that was
                            # the length of the list beside it.
                            $gpo | Add-Member -NotePropertyName "LinkedOUs" -NotePropertyValue @($links | Where-Object { $_ }) -Force

                            $gpoStatus = Get-GPOEffectiveStatus -StatusEntry $gpoStatusMap[$gpoNameUpper] `
                                -Scope 'Machine' -Link @($links | Where-Object { $_ })
                            if ($gpoStatus) {
                                $gpo | Add-Member -NotePropertyName "GPOStatus" -NotePropertyValue $gpoStatus -Force
                            }

                            $Script:gpoFindings += $gpo
                        }
                    }
                }
                if ($totalGPOs -gt $Script:ProgressThreshold) {
                    Show-Progress -Activity "Scanning LDAP configuration GPO settings" -Completed
                }

                # Whatever is left in the map belongs to a GPO that sets channel binding in
                # Registry.pol and has no GptTmpl.inf at all - a perfectly ordinary way to
                # deploy it, and one the loop above never reaches because it walks
                # GptTmpl.inf files. Without this the value would be found and then dropped.
                foreach ($leftoverGuid in @($channelBindingByGpo.Keys)) {
                    $gpo = $gpoByGuid[$leftoverGuid]
                    if (-not $gpo) { continue }

                    $channelBindingLevel = switch ($channelBindingByGpo[$leftoverGuid]) {
                        0 { "Never" }
                        1 { "When Supported" }
                        2 { "Always" }
                        default { "Unknown" }
                    }

                    $links = $null
                    $gpoLinkage = Get-GPOLinkage
                    if ($gpoLinkage) { $links = $gpoLinkage[$leftoverGuid] }
                    $activeLinks = @($links | Where-Object { $_ -and $_.LinkStatus -ne "Disabled" })
                    $isDomainWide = ($null -ne ($activeLinks | Where-Object { $_.Scope -eq "Domain" }))

                    $gpo | Add-Member -NotePropertyName "LDAPSigning" -NotePropertyValue "Not Configured" -Force
                    $gpo | Add-Member -NotePropertyName "ChannelBinding" -NotePropertyValue $channelBindingLevel -Force
                    $gpo | Add-Member -NotePropertyName "AnonymousBinding" -NotePropertyValue "Not Configured" -Force
                    # Same rule as the GptTmpl.inf loop: a link at or above the DC's own OU
                    # reaches it, which is where a policy hardening LDAP normally sits.
                    $gpo | Add-Member -NotePropertyName "CoversDCs" -NotePropertyValue (
                        Test-GPOCoversDomainControllers -ActiveLink $activeLinks -DomainController $domainControllers) -Force

                    $gpo | Add-Member -NotePropertyName "LinkedOUs" -NotePropertyValue @($links | Where-Object { $_ }) -Force

                    $gpoStatus = Get-GPOEffectiveStatus -StatusEntry $gpoStatusMap[$leftoverGuid] `
                        -Scope 'Machine' -Link @($links | Where-Object { $_ })
                    if ($gpoStatus) {
                        $gpo | Add-Member -NotePropertyName "GPOStatus" -NotePropertyValue $gpoStatus -Force
                    }

                    $Script:gpoFindings += $gpo
                }
            }

            # Copy findings from script scope
            $gpoFindings = $Script:gpoFindings
            $Script:gpoFindings = $null
            $sysvolAccessible = $Script:sysvolAccessible
            $Script:sysvolAccessible = $null

            # Check if SYSVOL was accessible
            if (-not $sysvolAccessible) {
                if ((Test-SysvolAccessible) -eq $false) {
                    Show-Line "Skipped - SYSVOL not accessible" -Class Hint
                } else {
                    Show-Line "SYSVOL access failed - cannot analyze GPO configuration for LDAP Security - SMB access failed (authentication/network issue)" -Class Finding
                }
                return
            }

            if ($gpoFindings -and $gpoFindings.Count -gt 0) {
                # Determine effective GPO per scope:
                # - DC OU / Domain scope: GPO with lowest LinkOrder (= highest priority) wins
                # - Other OUs: GPO is always effective for its own OU
                $gpoLinkage = Get-GPOLinkage
                $scopePriorityEff = @{ "DomainControllers" = 1; "Domain" = 2; "NotLinked" = 3 }

                foreach ($gpoFinding in $gpoFindings) {
                    $guid = $gpoFinding.Name.ToUpper()
                    $linksEff = if ($gpoLinkage) { $gpoLinkage[$guid] } else { $null }
                    $precScope = "NotLinked"; $precOrder = 999

                    if ($linksEff) {
                        $activeLinksEff = @($linksEff | Where-Object { -not $_.IsDisabled })
                        $dcLink  = $activeLinksEff | Where-Object { $_.DistinguishedName -match 'OU=Domain Controllers' } | Sort-Object { if ($_.LinkOrder) { [int]$_.LinkOrder } else { 999 } } | Select-Object -First 1
                        $domLink = $activeLinksEff | Where-Object { $_.Scope -eq "Domain" } | Sort-Object { if ($_.LinkOrder) { [int]$_.LinkOrder } else { 999 } } | Select-Object -First 1
                        if ($dcLink)      { $precScope = "DomainControllers"; $precOrder = if ($dcLink.LinkOrder)  { [int]$dcLink.LinkOrder }  else { 999 } }
                        elseif ($domLink) { $precScope = "Domain";            $precOrder = if ($domLink.LinkOrder) { [int]$domLink.LinkOrder } else { 999 } }
                    }

                    $gpoFinding | Add-Member -NotePropertyName '_PrecedenceScope' -NotePropertyValue $precScope -Force
                    $gpoFinding | Add-Member -NotePropertyName '_PrecedenceOrder' -NotePropertyValue $precOrder -Force
                    $gpoFinding | Add-Member -NotePropertyName 'IsEffectiveSetting' -NotePropertyValue $false -Force
                }

                # For DC OU / Domain scope: mark the single highest-priority GPO as effective
                $dcDomainGPOs = @($gpoFindings | Where-Object { $_._PrecedenceScope -ne "NotLinked" })
                if ($dcDomainGPOs.Count -gt 0) {
                    $effectiveDC = $dcDomainGPOs | Sort-Object @{Expression={$scopePriorityEff[$_._PrecedenceScope]}}, _PrecedenceOrder | Select-Object -First 1
                    if ($effectiveDC) { $effectiveDC.IsEffectiveSetting = $true }
                }

                # For other OUs: each GPO is effective for its own OU
                foreach ($gpoFinding in ($gpoFindings | Where-Object { $_._PrecedenceScope -eq "NotLinked" })) {
                    $gpoFinding.IsEffectiveSetting = $true
                }

                # Show Found message BEFORE data
                Show-Line "Found LDAP security configuration in $($gpoFindings.Count) GPO(s):" -Class Hint
                foreach ($gpoFinding in $gpoFindings) {
                    $gpoFinding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LDAPConfigGPO' -Force
                    Show-Object $gpoFinding
                }

            } else {
                Show-Line "No LDAP Security configuration found in any GPO - all $dcCount DC(s) potentially vulnerable" -Class Finding
            }

        } catch {
            Write-Log "[Get-LDAPConfiguration] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-LDAPConfiguration] Check completed"
    }
}
