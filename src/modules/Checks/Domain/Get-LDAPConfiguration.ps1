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
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeInactive
    )

    begin {
        Write-Log "[Get-LDAPConfiguration] Starting check"
    }

    process {
        try {
            # Connection parameters only. -IncludeInactive belongs to this check and none
            # of the callees below has a parameter by that name, so splatting
            # $PSBoundParameters failed to bind - a terminating error before any output.
            $connectionParams = @{}
            if ($Domain)     { $connectionParams['Domain']     = $Domain }
            if ($Server)     { $connectionParams['Server']     = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            # ===== Anonymous LDAP operations, read where they are actually configured =====
            #
            # dsHeuristics on CN=Directory Service, character 7 of the first group, is
            # fLDAPBlockAnonOps: the value 2 lets an anonymous client do more than read
            # rootDSE, anything else leaves it blocked. This question used to be answered
            # from two GPO settings that govern SMB null sessions instead - see the note at
            # the GPO loop below - so the report could carry a red "Anonymous LDAP Binding
            # Allowed" for a domain where it was blocked, and a green one for a domain
            # where it was open.
            Show-SubHeader "Checking anonymous LDAP operations (dsHeuristics)..." -ObjectType "LDAPConfigGPO"

            $configDN = $Script:LDAPContext.ConfigurationNamingContext
            if ($configDN) {
                $dirServiceDN = "CN=Directory Service,CN=Windows NT,CN=Services,$configDN"
                try {
                    $dirService = @(Get-DomainObject -Identity $dirServiceDN -Properties 'dSHeuristics' @connectionParams)[0]
                    $dsHeuristics = if ($dirService) { [string]$dirService.dSHeuristics } else { '' }

                    if (-not $dirService) {
                        Show-Line "The Directory Service object could not be read - whether anonymous LDAP operations are allowed is unknown" -Class Note
                    } elseif ([string]::IsNullOrWhiteSpace($dsHeuristics)) {
                        # An unset attribute is the default, and the default blocks
                        # anonymous operations beyond rootDSE.
                        Show-Line "Anonymous LDAP operations are blocked - dsHeuristics is not set, which is the secure default" -Class Secure
                    } else {
                        $anonChar = if ($dsHeuristics.Length -ge 7) { $dsHeuristics.Substring(6, 1) } else { '0' }
                        if ($anonChar -eq '2') {
                            # What an unauthenticated client can then do is the card's job.
                            Show-Line "Anonymous LDAP operations are ENABLED - dsHeuristics character 7 is 2" -Class Finding -FindingId 'LDAP_ANONYMOUS_BINDING_ALLOWED'
                        } else {
                            Show-Line "Anonymous LDAP operations are blocked - dsHeuristics character 7 is '$anonChar', not 2" -Class Secure
                        }

                        $heuristicsObj = [PSCustomObject]@{
                            dSHeuristics        = $dsHeuristics
                            anonymousLDAPAccess = if ($anonChar -eq '2') { 'ENABLED - Security Risk!' } else { 'Restricted' }
                        }
                        $heuristicsObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LDAPConfigGPO' -Force
                        Show-Object $heuristicsObj -Class $(if ($anonChar -eq '2') { 'Finding' } else { 'Secure' })
                    }
                } catch {
                    Write-Log "[Get-LDAPConfiguration] Could not read dsHeuristics: $_" -Level Warning
                    Show-Line "The Directory Service object could not be read - whether anonymous LDAP operations are allowed is unknown" -Class Note
                }
            } else {
                Show-Line "The configuration partition is unknown - whether anonymous LDAP operations are allowed could not be checked" -Class Note
            }

            Show-SubHeader "Analyzing LDAP Signing/Channel Binding via GPO (SYSVOL)..." -ObjectType "LDAPConfigGPO"

            $domainFQDN = $Script:LDAPContext.Domain
            $dcServer = $Script:LDAPContext.Server

            $allGPOs = Get-DomainGPO @connectionParams

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
            $domainControllers = @(Get-DomainComputer -DomainController @connectionParams)

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

                # ----- The values Group Policy delivers through Registry.pol -----
                #
                # LdapEnforceChannelBinding has no Security Option UI at all: it is a plain
                # registry value, and Group Policy carries it in Registry.pol. Reading only
                # GptTmpl.inf meant a domain that enforces channel binding correctly was
                # told every one of its domain controllers was potentially vulnerable - a
                # false alarm aimed precisely at the domains that had done the right thing.
                #
                # LDAPServerIntegrity used to be read from GptTmpl.inf alone, because it
                # does have a Security Option. But it sits in the same registry key, and a
                # hardening baseline from a third-party tool deploys it as a registry
                # policy like any other value - at which point this check said "No LDAP
                # Security configuration found in any GPO - all N DC(s) potentially
                # vulnerable". The same false alarm as above, on the setting that matters
                # most, and again aimed at the domains that had hardened.
                $ldapRegPolValueNames = @('LdapEnforceChannelBinding', 'LDAPServerIntegrity')
                $regPolValuesByGpo = @{}
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
                            if ("$($record.ValueName)" -notin $ldapRegPolValueNames) { continue }
                            if ("$($record.Key)" -notmatch 'Services\\NTDS\\Parameters$') { continue }
                            # REG_DWORD (4) only - both values are numbers, and anything
                            # else written under these names is not the setting
                            if ($record.Type -ne 4) { continue }
                            if ($null -eq $record.ValueInt) { continue }

                            if (-not $regPolValuesByGpo.ContainsKey($polGuid)) {
                                $regPolValuesByGpo[$polGuid] = @{}
                            }
                            # Keyed by the documented value name, not by the shape it is
                            # read in: the two merge points below ask for one of them.
                            $regPolValuesByGpo[$polGuid]["$($record.ValueName)"] = [int]$record.ValueInt
                            Write-Log "[Get-LDAPConfiguration] $($record.ValueName) = $($record.ValueInt) from Registry.pol of $polGuid"
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

                        # Parse Registry Values section.
                        # Get-GptTmplRegistrySection ends the section at the next line
                        # beginning with '[' rather than at the next '[' character. The
                        # pattern here was '(?s)\[Registry Values\](.*?)(\[|$)', and the
                        # section is sorted by key: a logon banner containing a bracket
                        # sits under MACHINE\Software\... and truncated the section before
                        # the three MACHINE\System\... values read below.
                        $registrySection = Get-GptTmplRegistrySection -Content $content
                        if ($registrySection) {

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

                        # A hand-written GptTmpl.inf can carry either value, but Group
                        # Policy normally puts them in Registry.pol. Consumed here so the
                        # pass after the loop does not report the same GPO a second time.
                        #
                        # GptTmpl.inf wins where a GPO somehow carries both: that is what
                        # this check did for channel binding before, and a GPO setting one
                        # value twice is a question about that GPO, not about the reading.
                        $gpoGuidKey = ([string]$gpo.Name).ToUpper()
                        if ($regPolValuesByGpo.ContainsKey($gpoGuidKey)) {
                            $regPolValues = $regPolValuesByGpo[$gpoGuidKey]
                            if ($null -eq $ldapChannelBindingValue -and $regPolValues.ContainsKey('LdapEnforceChannelBinding')) {
                                $ldapChannelBindingValue = $regPolValues['LdapEnforceChannelBinding']
                            }
                            if ($null -eq $ldapSigningValue -and $regPolValues.ContainsKey('LDAPServerIntegrity')) {
                                $ldapSigningValue = $regPolValues['LDAPServerIntegrity']
                            }
                            $regPolValuesByGpo.Remove($gpoGuidKey)
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

                            # Two settings, two statements, and neither of them is about
                            # LDAP. RestrictAnonymous is "Network access: Do not allow
                            # anonymous enumeration of SAM accounts and shares" and
                            # LSAAnonymousNameLookup is "Network access: Allow anonymous
                            # SID/Name translation" - both null-session controls over SMB.
                            # They used to be folded into one attribute called
                            # AnonymousBinding, which reached a definition titled
                            # "Anonymous LDAP Binding Allowed": a GPO setting
                            # RestrictAnonymous=0, which is the OS default and appears in
                            # baselines, produced a red finding about an attack path it
                            # does not open, and the Default Domain Controllers Policy's
                            # LSAAnonymousNameLookup=0 produced a green "Unauthenticated
                            # LDAP enumeration is blocked" - in the same report as the
                            # result of the real anonymous bind test from
                            # Get-DomainInformation. Two checks, one question, opposite
                            # answers, and the wrong one was the green one.
                            #
                            # What actually governs anonymous LDAP is dsHeuristics, read
                            # below at domain level.
                            $samEnumerationStatus = "Not Configured"
                            if ($null -ne $restrictAnonymous) {
                                $samEnumerationStatus = if ($restrictAnonymous -eq 0) { "Allowed" } else { "Restricted" }
                            }

                            $sidNameTranslationStatus = "Not Configured"
                            if ($null -ne $lsaAnonymousNameLookup) {
                                $sidNameTranslationStatus = if ($lsaAnonymousNameLookup -eq 1) { "Allowed" } else { "Restricted" }
                            }

                            # Get GPO linkage
                            $gpoLinkage = Get-GPOLinkage
                            # Normalize GUID to uppercase for hashtable lookup (Get-GPOLinkage uses uppercase keys)
                            $gpoNameUpper = $gpo.Name.ToUpper()

                            # Three-valued. A bare $gpoLinkage[$key] answers $null both when
                            # the map could not be built and when the map is fine but holds no
                            # entry for this GPO - and those two have to be reported as
                            # opposites: the second means "linked nowhere", which is knowledge.
                            # On a $null map the bare index also emits a "Cannot index into a
                            # null array" error record into the host.
                            $links = $null
                            if ($null -ne $gpoLinkage) {
                                $links = @()
                                if ($gpoLinkage.ContainsKey($gpoNameUpper)) {
                                    $links = @($gpoLinkage[$gpoNameUpper])
                                }
                            }
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
                            $gpo | Add-Member -NotePropertyName "anonymousSamEnumeration" -NotePropertyValue $samEnumerationStatus -Force
                            $gpo | Add-Member -NotePropertyName "anonymousSidNameTranslation" -NotePropertyValue $sidNameTranslationStatus -Force
                            $gpo | Add-Member -NotePropertyName "CoversDCs" -NotePropertyValue $coversDCs -Force

                            # Where the policy applies. The full link records, disabled ones
                            # included - the LinkedOUs transformer marks those and renders an
                            # empty list as "Not linked". The Scope attribute this replaces
                            # said the same thing in a second vocabulary and a count that was
                            # the length of the list beside it.
                            # Only the unresolved case needs a string: "Not linked" would be a
                            # claim the failed lookup cannot support. Plain assignment, then an
                            # override - an "if" whose branch yields @() writes nothing to the
                            # output stream and would land the variable as $null.
                            $linkedOUsDisplay = $links
                            if ($null -eq $links) {
                                $linkedOUsDisplay = 'Unknown - linkage could not be resolved'
                            }
                            $gpo | Add-Member -NotePropertyName "LinkedOUs" -NotePropertyValue $linkedOUsDisplay -Force

                            $gpoStatus = Get-GPOEffectiveStatus -StatusEntry $gpoStatusMap[$gpoNameUpper] `
                                -Scope 'Machine' -Link $links
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

                # Whatever is left in the map belongs to a GPO that sets these values in
                # Registry.pol and has no GptTmpl.inf at all - a perfectly ordinary way to
                # deploy them, and one the loop above never reaches because it walks
                # GptTmpl.inf files. Without this the value would be found and then dropped.
                foreach ($leftoverGuid in @($regPolValuesByGpo.Keys)) {
                    $gpo = $gpoByGuid[$leftoverGuid]
                    if (-not $gpo) { continue }

                    $leftoverValues = $regPolValuesByGpo[$leftoverGuid]

                    $channelBindingLevel = "Not Configured"
                    if ($leftoverValues.ContainsKey('LdapEnforceChannelBinding')) {
                        $channelBindingLevel = switch ($leftoverValues['LdapEnforceChannelBinding']) {
                            0 { "Never" }
                            1 { "When Supported" }
                            2 { "Always" }
                            default { "Unknown" }
                        }
                    }

                    # The same decode the GptTmpl.inf loop uses, so one setting reads the
                    # same way whichever file it arrived in.
                    $signingLevel = "Not Configured"
                    if ($leftoverValues.ContainsKey('LDAPServerIntegrity')) {
                        $signingLevel = switch ($leftoverValues['LDAPServerIntegrity']) {
                            0 { "None" }
                            1 { "Optional" }
                            2 { "Required" }
                            default { "Unknown" }
                        }
                    }

                    # Three-valued, same as the GptTmpl.inf loop: $null for an unresolved map,
                    # @() for a resolved one that holds no entry for this GPO.
                    $links = $null
                    $gpoLinkage = Get-GPOLinkage
                    if ($null -ne $gpoLinkage) {
                        $links = @()
                        if ($gpoLinkage.ContainsKey($leftoverGuid)) {
                            $links = @($gpoLinkage[$leftoverGuid])
                        }
                    }
                    $activeLinks = @($links | Where-Object { $_ -and $_.LinkStatus -ne "Disabled" })
                    $isDomainWide = ($null -ne ($activeLinks | Where-Object { $_.Scope -eq "Domain" }))

                    $gpo | Add-Member -NotePropertyName "LDAPSigning" -NotePropertyValue $signingLevel -Force
                    $gpo | Add-Member -NotePropertyName "ChannelBinding" -NotePropertyValue $channelBindingLevel -Force
                    $gpo | Add-Member -NotePropertyName "anonymousSamEnumeration" -NotePropertyValue "Not Configured" -Force
                    $gpo | Add-Member -NotePropertyName "anonymousSidNameTranslation" -NotePropertyValue "Not Configured" -Force
                    # Same rule as the GptTmpl.inf loop: a link at or above the DC's own OU
                    # reaches it, which is where a policy hardening LDAP normally sits.
                    $gpo | Add-Member -NotePropertyName "CoversDCs" -NotePropertyValue (
                        Test-GPOCoversDomainControllers -ActiveLink $activeLinks -DomainController $domainControllers) -Force

                    $linkedOUsDisplay = $links
                    if ($null -eq $links) {
                        $linkedOUsDisplay = 'Unknown - linkage could not be resolved'
                    }
                    $gpo | Add-Member -NotePropertyName "LinkedOUs" -NotePropertyValue $linkedOUsDisplay -Force

                    $gpoStatus = Get-GPOEffectiveStatus -StatusEntry $gpoStatusMap[$leftoverGuid] `
                        -Scope 'Machine' -Link $links
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
                    Show-Line "SYSVOL access failed - the GPO configuration for LDAP Security was not analyzed" -Class Finding
                }
                return
            }

            if ($gpoFindings -and $gpoFindings.Count -gt 0) {
                $gpoLinkage = Get-GPOLinkage

                # Where each policy sits in the contest for the domain controllers, and how
                # it ranks there - see Get-GPODCPrecedence for the five scopes, including
                # why Unknown and NotLinked have to stay apart.
                foreach ($gpoFinding in $gpoFindings) {
                    $guid = $gpoFinding.Name.ToUpper()
                    $linksEff = $null
                    if ($null -ne $gpoLinkage) {
                        $linksEff = @()
                        if ($gpoLinkage.ContainsKey($guid)) { $linksEff = @($gpoLinkage[$guid]) }
                    }
                    $precedence = Get-GPODCPrecedence -Link $linksEff

                    $gpoFinding | Add-Member -NotePropertyName '_PrecedenceScope' -NotePropertyValue $precedence.Scope -Force
                    $gpoFinding | Add-Member -NotePropertyName '_PrecedenceRank' -NotePropertyValue $precedence.Rank -Force
                    $gpoFinding | Add-Member -NotePropertyName '_PrecedenceOrder' -NotePropertyValue $precedence.Order -Force
                    $gpoFinding | Add-Member -NotePropertyName '_HasAnyLink' -NotePropertyValue $precedence.HasAnyLink -Force
                    $gpoFinding | Add-Member -NotePropertyName '_IsEffective' -NotePropertyValue $false -Force
                }

                # Precedence is per setting, not per policy. The contest used to elect one
                # policy and call every other one overridden - so a Default Domain Policy
                # that alone sets channel binding was "overridden" by a Domain Controllers
                # policy that only sets LDAP signing, while its value was the one in force.
                # Each value comes from the highest-ranked policy that sets it.
                $ldapSettings = @(
                    @{ Property = 'LDAPSigning';                 Label = 'LDAP signing' }
                    @{ Property = 'ChannelBinding';              Label = 'channel binding' }
                    @{ Property = 'anonymousSamEnumeration';     Label = 'anonymous SAM enumeration' }
                    @{ Property = 'anonymousSidNameTranslation'; Label = 'anonymous SID/name translation' }
                )
                $settingWinners = Resolve-GPOSettingPrecedence -Finding $gpoFindings -Setting $ldapSettings

                # The verdict goes out as a sentence. In the contest it names which of the
                # policy's settings are in force and who overrides the rest; elsewhere it
                # keeps the wording that tells "applies on its OUs", "linked nowhere" and
                # "every link disabled" apart. A policy that reaches no machine is never in
                # force, however its settings read.
                foreach ($gpoFinding in $gpoFindings) {
                    if ($gpoFinding._PrecedenceScope -in @('DomainControllers', 'Domain')) {
                        $winsSomething = @($ldapSettings | Where-Object {
                            [object]::ReferenceEquals($settingWinners[$_.Property], $gpoFinding)
                        }).Count -gt 0
                        $gpoFinding._IsEffective = $winsSomething
                        $effectiveText = Get-GPOSettingPrecedenceText -Finding $gpoFinding -Setting $ldapSettings -Winner $settingWinners
                    } else {
                        $gpoFinding._IsEffective = ($gpoFinding._PrecedenceScope -eq 'OtherOU')
                        $effectiveText = Get-GPOEffectiveSettingText -Scope $gpoFinding._PrecedenceScope `
                            -IsEffective $gpoFinding._IsEffective -HasAnyLink $gpoFinding._HasAnyLink
                    }
                    $gpoFinding | Add-Member -NotePropertyName 'EffectiveSetting' -NotePropertyValue $effectiveText -Force
                }

                # A signing setting in a policy that is not linked or not enabled reaches no
                # domain controller. Held back rather than dropped - see
                # Show-GPOInactiveSummary. GuidProperty is Name, because these are native
                # GPO objects and that is what a GPO's GUID is called in the directory.
                #
                # The reach predicate overlaps with EffectiveSetting above and does not
                # replace it: that one says which policy wins the precedence contest, this
                # one whether the policy applies at all. A policy can reach the DCs and
                # still lose to another.
                $split = Split-GPOFindingByReach -Finding $gpoFindings -GPOStatusMap $gpoStatusMap `
                    -GPOLinkage $gpoLinkage -Scope 'Machine' -GuidProperty 'Name'

                $shown = if ($IncludeInactive) { @($gpoFindings) } else { @($split.Active) }

                # Held-back policies first, then the headline for the active ones, then the
                # active ones. The "Found ..." line is the heading for the finding objects, so
                # it belongs directly above them - not above the dampening block, which is a
                # separate statement about what was left out.
                Show-GPOInactiveSummary -Unlinked $split.Unlinked -Disabled $split.Disabled `
                    -Dormant $split.Dormant -Listed:$IncludeInactive

                if (@($shown).Count -gt 0) {
                    Show-Line "Found LDAP security configuration in $(@($shown).Count) GPO(s):" -Class Hint
                } else {
                    # Every policy that configures it is dormant, which leaves the DCs on
                    # whatever the OS defaults to - the same exposure as configuring nothing.
                    Show-Line "No LDAP security configuration is deployed by a policy that is linked and enabled - all $dcCount DC(s) potentially vulnerable" -Class Finding
                }

                foreach ($gpoFinding in $shown) {
                    $gpoFinding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LDAPConfigGPO' -Force

                    if (@($split.Inactive) -contains $gpoFinding) {
                        Show-Object $gpoFinding -Class Note
                    } else {
                        Show-Object $gpoFinding -Class Hint
                    }
                }

                # What is in force on the domain controllers, value by value, and which
                # policy each comes from - the question a reader otherwise works out by
                # hand from the rows above. Not without the linkage: every policy is then
                # Unknown, nobody enters the contest, and "Not Configured" across the board
                # would be a claim the failed lookup cannot support.
                if ($null -ne $gpoLinkage) {
                    $posture = [PSCustomObject]@{
                        LDAPSigning                 = $(if ($settingWinners['LDAPSigning']) { $settingWinners['LDAPSigning'].LDAPSigning } else { 'Not Configured' })
                        ChannelBinding              = $(if ($settingWinners['ChannelBinding']) { $settingWinners['ChannelBinding'].ChannelBinding } else { 'Not Configured' })
                        anonymousSamEnumeration     = $(if ($settingWinners['anonymousSamEnumeration']) { $settingWinners['anonymousSamEnumeration'].anonymousSamEnumeration } else { 'Not Configured' })
                        anonymousSidNameTranslation = $(if ($settingWinners['anonymousSidNameTranslation']) { $settingWinners['anonymousSidNameTranslation'].anonymousSidNameTranslation } else { 'Not Configured' })
                        decidedBy                   = Get-GPOSettingPostureSource -Setting $ldapSettings -Winner $settingWinners
                        basis                       = Get-GPOPostureBasisNote
                    }
                    $posture | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'EffectiveLDAPConfig' -Force

                    # The class of the worst value in force, on the scale the value
                    # triggers use. The two anonymous settings, unset, claim nothing.
                    $postureClasses = @(
                        $(switch ($posture.LDAPSigning) { 'Required' { 'Secure' } 'Optional' { 'Hint' } 'Not Configured' { 'Hint' } default { 'Finding' } })
                        $(switch ($posture.ChannelBinding) { 'Always' { 'Secure' } 'When Supported' { 'Hint' } 'Not Configured' { 'Hint' } default { 'Finding' } })
                        $(if ($posture.anonymousSamEnumeration -eq 'Allowed') { 'Hint' } else { 'Secure' })
                        $(if ($posture.anonymousSidNameTranslation -eq 'Allowed') { 'Hint' } else { 'Secure' })
                    )
                    $postureClass = if ($postureClasses -contains 'Finding') { 'Finding' } elseif ($postureClasses -contains 'Hint') { 'Hint' } else { 'Secure' }

                    Show-Line "In force on the domain controllers, by policy precedence:" -Class $postureClass
                    Show-Object $posture -Class $postureClass
                }

            } else {
                Show-Line "No LDAP Security configuration found in any GPO - all $dcCount DC(s) potentially vulnerable" -Class Finding
            }

        } catch {
            Write-Log "[Get-LDAPConfiguration] Error: $_" -Level Error
            Show-Line "Error during check - the LDAP signing and channel binding configuration could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-LDAPConfiguration] Check completed"
    }
}
