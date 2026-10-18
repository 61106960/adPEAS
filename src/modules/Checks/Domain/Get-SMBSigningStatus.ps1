function Get-SMBSigningStatus {
    <#
    .SYNOPSIS
    Checks SMB Signing configuration status via GPO analysis.

    .DESCRIPTION
    Reads the four SMB signing values out of every GPO in SYSVOL - from GptTmpl.inf and from
    Registry.pol - and works out which policy reaches a machine: its links, their status, the
    GPO status, and per scope which link wins. SMB signing is what makes an NTLM relay to SMB
    fail.

    It asks no computer object anything, and there is no coverage figure here. Which machines
    a policy covers is answered from the links. The .DESCRIPTION used to claim it was
    "calculating coverage across all computer accounts", which nothing in the module did.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-SMBSigningStatus

    .EXAMPLE
    Get-SMBSigningStatus -Domain "contoso.com" -Credential (Get-Credential)

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
        Write-Log "[Get-SMBSigningStatus] Starting check"
    }

    process {
        try {
            # Connection parameters only. -IncludeInactive belongs to this check and
            # neither callee has a parameter by that name, so splatting $PSBoundParameters
            # failed to bind - a terminating error before any output.
            $connectionParams = @{}
            if ($Domain)     { $connectionParams['Domain']     = $Domain }
            if ($Server)     { $connectionParams['Server']     = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            Show-SubHeader "Analyzing SMB Signing configuration via GPO (SYSVOL)..." -ObjectType "SMBSigning"

            $domainFQDN = $Script:LDAPContext.Domain
            $dcServer = $Script:LDAPContext.Server

            $allGPOs = Get-DomainGPO @connectionParams

            if (-not $allGPOs -or @($allGPOs).Count -eq 0) {
                Show-Line "No GPOs found" -Class Note
                return
            }

            # Indexed once for the whole check: every finding below reports the state of its
            # policy as GPOStatus, the way the other GPO checks do.
            $gpoStatusMap = Get-GPOStatusMap -GPO $allGPOs

            # Use Invoke-SMBAccess for SYSVOL access (handles SimpleBind credentials)
            $Script:smbGpoFindings = @()
            $Script:sysvolAccessible = $false

            Invoke-SMBAccess -Description "Scanning SYSVOL for SMB Signing GPOs" -ScriptBlock {
                $sysvolPath = "\\$dcServer\SYSVOL\$domainFQDN\Policies"

                if (-not (Test-Path $sysvolPath)) {
                    Write-Log "[Get-SMBSigningStatus] SYSVOL path not accessible: $sysvolPath"
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

                # GPO GUID -> its GptTmpl.inf, so the loop below can walk the GPOs that
                # carry these settings in EITHER file rather than only those with an .inf.
                $gptTmplByGuid = @{}
                foreach ($file in $gptTmplFiles) {
                    if ($file.FullName -notmatch '\\Policies\\(\{[^}]+\})\\') { continue }
                    $gptTmplByGuid[$Matches[1].ToUpper()] = $file
                }

                # ----- The same four values, delivered as a registry policy -----
                #
                # SMB signing has Security Options, so the Group Policy editor writes it
                # into GptTmpl.inf and the parser below finds it. A hardening baseline from
                # a third-party tool sets the registry values directly instead, which is an
                # ordinary way to deploy them - and then this check found nothing at all
                # and said "No SMB Signing configuration found in any GPO" as a Finding.
                # The same false alarm that was fixed for LDAP channel binding, aimed again
                # at the domains that had hardened.
                $smbRegPolValueNames = @('RequireSecuritySignature', 'EnableSecuritySignature')
                $smbRegPolByGpo = @{}
                foreach ($polFile in @(Get-CachedSYSVOLFiles -Filter "Registry.pol")) {
                    if ($polFile.FullName -notmatch '\\Policies\\(\{[^}]+\})\\') { continue }
                    # Read the capture out before the next comparison, which overwrites
                    # $Matches even when it is a -notmatch that comes out false
                    $polGuid = $Matches[1].ToUpper()

                    # Machine-side only: both keys live under HKLM, and a user policy
                    # cannot set them.
                    if ($polFile.FullName -notmatch '\\Machine\\') { continue }

                    try {
                        foreach ($record in @(Parse-PRegRecords -PolFilePath $polFile.FullName -Hive 'HKLM')) {
                            $valueName = "$($record.ValueName)"
                            if ($valueName -notin $smbRegPolValueNames) { continue }

                            # The same value name exists on both sides, and which key it
                            # sits under is the entire difference between "this machine
                            # signs what it serves" and "this machine insists on signing
                            # what it consumes".
                            $recordKey = "$($record.Key)"
                            $side = $null
                            if ($recordKey -match 'Services\\LanmanServer\\Parameters$') { $side = 'Server' }
                            elseif ($recordKey -match 'Services\\LanmanWorkstation\\Parameters$') { $side = 'Client' }
                            if (-not $side) { continue }

                            # REG_DWORD (4) only - all four values are numbers
                            if ($record.Type -ne 4) { continue }
                            if ($null -eq $record.ValueInt) { continue }

                            if (-not $smbRegPolByGpo.ContainsKey($polGuid)) {
                                $smbRegPolByGpo[$polGuid] = @{}
                            }
                            $smbRegPolByGpo[$polGuid]["$side$valueName"] = [int]$record.ValueInt
                            Write-Log "[Get-SMBSigningStatus] $side $valueName = $($record.ValueInt) from Registry.pol of $polGuid"
                        }
                    } catch {
                        Write-Log "[Get-SMBSigningStatus] Could not read $($polFile.FullName): $($_.Exception.Message)"
                    }
                }

                # Parse GPOs for SMB Signing settings. The union of both sources: a GPO
                # that sets them only as a registry policy has no GptTmpl.inf at all, and
                # a loop over .inf files never reaches it.
                $candidateGuids = @(@($gptTmplByGuid.Keys) + @($smbRegPolByGpo.Keys) | Select-Object -Unique)
                $totalGPOs = $candidateGuids.Count
                $currentGPOIndex = 0
                foreach ($gpoGUID in $candidateGuids) {
                    $gpo = $gpoByGuid[$gpoGUID]
                    if (-not $gpo) { continue }

                    $currentGPOIndex++
                    if ($totalGPOs -gt $Script:ProgressThreshold) {
                        Show-Progress -Activity "Scanning SMB signing GPO settings" -Current $currentGPOIndex -Total $totalGPOs -ObjectName $gpo.DisplayName
                    }

                    $content = $null
                    if ($gptTmplByGuid.ContainsKey($gpoGUID)) {
                        $content = Get-CachedSYSVOLContent -Path $gptTmplByGuid[$gpoGUID].FullName
                    }
                    # Either source is enough to reach the construction below: a GPO that
                    # sets these values as a registry policy has no GptTmpl.inf at all.
                    if ($content -or $smbRegPolByGpo.ContainsKey($gpoGUID)) {
                        # Look for SMB Signing settings in [Registry Values] section.
                        # Get-GptTmplRegistrySection ends the section at the next line
                        # beginning with '[' rather than at the next '[' character. The
                        # pattern here was '(?s)\[Registry Values\](.*?)(\[|$)', and the
                        # section is sorted by key: a logon banner containing a bracket
                        # sits under MACHINE\Software\... and truncated the section before
                        # the four MACHINE\System\...\Lanman* values read below.
                        $registrySection = $null
                        if ($content) {
                            $registrySection = Get-GptTmplRegistrySection -Content $content
                        }
                        # The four reads below are -match against $null when there is no
                        # section, which is false rather than an error, so one path serves
                        # both sources and the finding is built in one place.
                        if ($registrySection -or $smbRegPolByGpo.ContainsKey($gpoGUID)) {

                            $serverRequire = $null
                            $serverEnable = $null
                            $clientRequire = $null
                            $clientEnable = $null

                            # Server Settings
                            if ($registrySection -match 'MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\RequireSecuritySignature.*?=.*?4,(\d+)') {
                                $serverRequire = [int]$Matches[1]
                            }
                            if ($registrySection -match 'MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\EnableSecuritySignature.*?=.*?4,(\d+)') {
                                $serverEnable = [int]$Matches[1]
                            }

                            # Client Settings
                            if ($registrySection -match 'MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\RequireSecuritySignature.*?=.*?4,(\d+)') {
                                $clientRequire = [int]$Matches[1]
                            }
                            if ($registrySection -match 'MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\EnableSecuritySignature.*?=.*?4,(\d+)') {
                                $clientEnable = [int]$Matches[1]
                            }

                            # Whatever GptTmpl.inf did not say, the registry policy may
                            # have. GptTmpl.inf wins where a GPO carries both: a policy
                            # setting one value twice is a question about that policy, not
                            # about the reading of it.
                            if ($smbRegPolByGpo.ContainsKey($gpoGUID)) {
                                $smbRegPol = $smbRegPolByGpo[$gpoGUID]
                                if ($null -eq $serverRequire -and $smbRegPol.ContainsKey('ServerRequireSecuritySignature')) {
                                    $serverRequire = $smbRegPol['ServerRequireSecuritySignature']
                                }
                                if ($null -eq $serverEnable -and $smbRegPol.ContainsKey('ServerEnableSecuritySignature')) {
                                    $serverEnable = $smbRegPol['ServerEnableSecuritySignature']
                                }
                                if ($null -eq $clientRequire -and $smbRegPol.ContainsKey('ClientRequireSecuritySignature')) {
                                    $clientRequire = $smbRegPol['ClientRequireSecuritySignature']
                                }
                                if ($null -eq $clientEnable -and $smbRegPol.ContainsKey('ClientEnableSecuritySignature')) {
                                    $clientEnable = $smbRegPol['ClientEnableSecuritySignature']
                                }
                            }

                            # If any SMB Signing settings found, add to findings
                            if ($null -ne $serverRequire -or $null -ne $serverEnable -or
                                $null -ne $clientRequire -or $null -ne $clientEnable) {

                                # Determine Server Status
                                $serverStatus = if ($null -eq $serverRequire -and $null -eq $serverEnable) {
                                    "Not configured"
                                } elseif ($serverRequire -eq 1) {
                                    "Required"
                                } elseif ($serverEnable -eq 1) {
                                    "Optional"
                                } elseif ($serverRequire -eq 0 -or $serverEnable -eq 0) {
                                    "Disabled"
                                } else {
                                    "Not configured"
                                }

                                # Determine Client Status
                                $clientStatus = if ($null -eq $clientRequire -and $null -eq $clientEnable) {
                                    "Not configured"
                                } elseif ($clientRequire -eq 1) {
                                    "Required"
                                } elseif ($clientEnable -eq 1) {
                                    "Optional"
                                } elseif ($clientRequire -eq 0 -or $clientEnable -eq 0) {
                                    "Disabled"
                                } else {
                                    "Not configured"
                                }

                                # Get GPO linkage
                                $gpoLinkage = Get-GPOLinkage
                                # Normalize GUID to uppercase for hashtable lookup (Get-GPOLinkage uses uppercase keys)
                                $gpoGUIDUpper = $gpoGUID.ToUpper()

                                # Three-valued. A bare $gpoLinkage[$key] answers $null both
                                # when the map could not be built and when the map is fine but
                                # holds no entry for this GPO - and those two have to be
                                # reported as opposites: the second means "linked nowhere",
                                # which is knowledge. On a $null map the bare index also emits
                                # a "Cannot index into a null array" error record into the host.
                                $links = $null
                                if ($null -ne $gpoLinkage) {
                                    $links = @()
                                    if ($gpoLinkage.ContainsKey($gpoGUIDUpper)) {
                                        $links = @($gpoLinkage[$gpoGUIDUpper])
                                    }
                                }
                                $activeLinks = @()
                                $isDomainWide = $false

                                if ($links) {
                                    $activeLinks = @($links | Where-Object { $_.LinkStatus -ne "Disabled" })
                                    $domainWide = $activeLinks | Where-Object { $_.Scope -eq "Domain" }
                                    $isDomainWide = ($null -ne $domainWide)
                                }

                                # Enrich the native GPO object with SMB Signing attributes
                                $gpo | Add-Member -NotePropertyName "ServerSigning" -NotePropertyValue $serverStatus -Force
                                $gpo | Add-Member -NotePropertyName "ClientSigning" -NotePropertyValue $clientStatus -Force
                                $gpo | Add-Member -NotePropertyName "IsDomainWide" -NotePropertyValue $isDomainWide -Force

                                # Where the policy applies. The full link records, disabled
                                # ones included - the LinkedOUs transformer marks those and
                                # renders an empty list as "Not linked".
                                # Only the unresolved case needs a string: "Not linked" would
                                # be a claim the failed lookup cannot support. Plain
                                # assignment, then an override - an "if" whose branch yields
                                # @() writes nothing and would land the variable as $null.
                                $linkedOUsDisplay = $links
                                if ($null -eq $links) {
                                    $linkedOUsDisplay = 'Unknown - linkage could not be resolved'
                                }
                                $gpo | Add-Member -NotePropertyName "LinkedOUs" -NotePropertyValue $linkedOUsDisplay -Force

                                $gpoStatus = Get-GPOEffectiveStatus -StatusEntry $gpoStatusMap[$gpoGUIDUpper] `
                                    -Scope 'Machine' -Link $links
                                if ($gpoStatus) {
                                    $gpo | Add-Member -NotePropertyName "GPOStatus" -NotePropertyValue $gpoStatus -Force
                                }

                                $Script:smbGpoFindings += $gpo
                            }
                        }
                    }
                }
                if ($totalGPOs -gt $Script:ProgressThreshold) {
                    Show-Progress -Activity "Scanning SMB signing GPO settings" -Completed
                }
            }

            $gpoFindings = $Script:smbGpoFindings
            $Script:smbGpoFindings = $null
            $sysvolAccessible = $Script:sysvolAccessible
            $Script:sysvolAccessible = $null

            # Check if SYSVOL was accessible
            if (-not $sysvolAccessible) {
                if ((Test-SysvolAccessible) -eq $false) {
                    Show-Line "Skipped - SYSVOL not accessible" -Class Hint
                } else {
                    Show-Line "SYSVOL access failed - the GPO configuration for SMB Signing was not analyzed" -Class Finding
                }
                return
            }

            if ($gpoFindings -and @($gpoFindings).Count -gt 0) {
                $gpoLinkageForEff = Get-GPOLinkage

                # Where each policy sits in the contest for the domain controllers, and how
                # it ranks there - see Get-GPODCPrecedence for the five scopes, including
                # why Unknown and NotLinked have to stay apart.
                foreach ($gpoFinding in $gpoFindings) {
                    $guid = $gpoFinding.Name.ToUpper()
                    $linksEff = $null
                    if ($null -ne $gpoLinkageForEff) {
                        $linksEff = @()
                        if ($gpoLinkageForEff.ContainsKey($guid)) { $linksEff = @($gpoLinkageForEff[$guid]) }
                    }
                    $precedence = Get-GPODCPrecedence -Link $linksEff
                    $precScope = $precedence.Scope

                    $gpoFinding | Add-Member -NotePropertyName '_PrecedenceScope' -NotePropertyValue $precScope -Force
                    $gpoFinding | Add-Member -NotePropertyName '_PrecedenceRank' -NotePropertyValue $precedence.Rank -Force
                    $gpoFinding | Add-Member -NotePropertyName '_PrecedenceOrder' -NotePropertyValue $precedence.Order -Force
                    $gpoFinding | Add-Member -NotePropertyName '_HasAnyLink' -NotePropertyValue $precedence.HasAnyLink -Force
                    $gpoFinding | Add-Member -NotePropertyName '_IsEffective' -NotePropertyValue $false -Force

                    # A server-side value nobody set does not mean the same thing on a
                    # domain controller as on a member server, and the row said "Not
                    # configured" for both - the same yellow hint for a state that is
                    # required anyway and one that is what a relay needs. The Default
                    # Domain Controllers Policy requires server-side signing; a member
                    # server before Windows Server 2025 has it enabled but not required.
                    #
                    # Only the server side is qualified. The client default is "not
                    # required" on every role up to Windows 11 24H2 - SYSVOL and NETLOGON
                    # aside, which are hardened separately - so a DC-linked policy that is
                    # silent about the client half says nothing reassuring.
                    #
                    # NotLinked and Unknown keep the bare wording on purpose: a policy
                    # that reaches no machine, or whose links could not be resolved, has
                    # no role to be read against.
                    if ($gpoFinding.ServerSigning -eq 'Not configured') {
                        if ($precScope -eq 'DomainControllers') {
                            $gpoFinding.ServerSigning = 'Not configured - the Domain Controllers default requires it'
                        } elseif ($precScope -in @('Domain', 'OtherOU', 'Site', 'Blocked')) {
                            $gpoFinding.ServerSigning = 'Not configured - not required by default before Windows Server 2025'
                        }
                    }
                }

                # Precedence is per setting, not per policy: each value comes from the
                # highest-ranked policy that sets it, and a policy that leaves one unset
                # does not override another policy's value for it. The contest used to elect
                # one policy and call every other one overridden. Unset server values carry
                # the role qualifier from above and still count as unset.
                $smbSettings = @(
                    @{ Property = 'ServerSigning'; Label = 'server signing' }
                    @{ Property = 'ClientSigning'; Label = 'client signing' }
                )
                $settingWinners = Resolve-GPOSettingPrecedence -Finding $gpoFindings -Setting $smbSettings

                # The verdict goes out as a sentence. In the contest it names which of the
                # policy's settings are in force and who overrides the rest; elsewhere it
                # keeps the wording that tells "applies on its OUs", "linked nowhere" and
                # "every link disabled" apart. A policy that reaches no machine is never in
                # force, however its settings read.
                foreach ($gpoFinding in $gpoFindings) {
                    if ($gpoFinding._PrecedenceScope -in @('DomainControllers', 'Domain', 'Site')) {
                        $winsSomething = @($smbSettings | Where-Object {
                            [object]::ReferenceEquals($settingWinners[$_.Property], $gpoFinding)
                        }).Count -gt 0
                        $gpoFinding._IsEffective = $winsSomething
                        $effectiveText = Get-GPOSettingPrecedenceText -Finding $gpoFinding -Setting $smbSettings -Winner $settingWinners
                    } else {
                        $gpoFinding._IsEffective = ($gpoFinding._PrecedenceScope -in @('OtherOU', 'Blocked'))
                        $effectiveText = Get-GPOEffectiveSettingText -Scope $gpoFinding._PrecedenceScope `
                            -IsEffective $gpoFinding._IsEffective -HasAnyLink $gpoFinding._HasAnyLink
                    }
                    $gpoFinding | Add-Member -NotePropertyName 'EffectiveSetting' -NotePropertyValue $effectiveText -Force
                }

                # A signing setting in a policy that is not linked or not enabled reaches no
                # machine. Held back rather than dropped - see Show-GPOInactiveSummary.
                # GuidProperty is Name: these are native GPO objects, and that is what a
                # GPO's GUID is called in the directory.
                $split = Split-GPOFindingByReach -Finding $gpoFindings -GPOStatusMap $gpoStatusMap `
                    -GPOLinkage $gpoLinkageForEff -Scope 'Machine' -GuidProperty 'Name'

                $shown = if ($IncludeInactive) { @($gpoFindings) } else { @($split.Active) }

                # Held-back policies first, then the headline for the active ones, then the
                # active ones - the "Found ..." line heads the finding objects, not the
                # dampening block.
                Show-GPOInactiveSummary -Unlinked $split.Unlinked -Disabled $split.Disabled `
                    -Dormant $split.Dormant -Listed:$IncludeInactive

                if (@($shown).Count -gt 0) {
                    Show-Line "Found SMB Signing configuration in $(@($shown).Count) GPO(s):" -Class Hint
                } else {
                    # Every policy that configures signing is dormant, which leaves every
                    # machine on the OS default - the same exposure as configuring nothing.
                    Show-Line "No SMB Signing configuration is deployed by a policy that is linked and enabled" -Class Finding
                }

                foreach ($gpoFinding in $shown) {
                    $gpoFinding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SMBSigning' -Force

                    if (@($split.Inactive) -contains $gpoFinding) {
                        Show-Object $gpoFinding -Class Note
                    } else {
                        Show-Object $gpoFinding -Class Hint
                    }
                }

                # What is in force on the domain controllers, value by value, and which
                # policy each comes from. Not without the linkage - every policy is then
                # Unknown, and "Not configured" for both halves would be a claim the failed
                # lookup cannot support. An unset server half stays plain "Not configured":
                # nothing linked to the domain controllers sets it, so the role qualifier
                # the rows above carry - the Domain Controllers default - is not in force.
                if ($null -ne $gpoLinkageForEff) {
                    $posture = [PSCustomObject]@{
                        ServerSigning = $(if ($settingWinners['ServerSigning']) { $settingWinners['ServerSigning'].ServerSigning } else { 'Not configured' })
                        ClientSigning = $(if ($settingWinners['ClientSigning']) { $settingWinners['ClientSigning'].ClientSigning } else { 'Not configured' })
                        decidedBy     = Get-GPOSettingPostureSource -Setting $smbSettings -Winner $settingWinners
                    }
                    $posture | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'EffectiveSMBSigning' -Force

                    # The class of the worst value in force, on the scale the value
                    # triggers use.
                    $postureClasses = @(
                        foreach ($postureValue in @($posture.ServerSigning, $posture.ClientSigning)) {
                            switch ($postureValue) { 'Required' { 'Secure' } 'Disabled' { 'Finding' } default { 'Hint' } }
                        }
                    )
                    $postureClass = if ($postureClasses -contains 'Finding') { 'Finding' } elseif ($postureClasses -contains 'Hint') { 'Hint' } else { 'Secure' }

                    Show-Line "In force on the domain controllers, by policy precedence:" -Class $postureClass
                    Show-Object $posture -Class $postureClass
                }

                # Check if SMB Signing is only configured for Domain Controllers
                # This means member servers and clients rely on OS defaults (which vary by version)
                # Over the policies that actually reach a machine. $gpoFindings is every
                # policy that carries a signing value, dormant ones included, and both
                # summaries below used to be computed from it: a disabled or unlinked GPO
                # counted as an insecure configuration, and one single dormant policy
                # outside the DC OU was enough to suppress the member-server warning.
                # Same defect as the headline above, two blocks further down.
                $reaching = @($split.Active)
                $gpoLinkage = Get-GPOLinkage
                $dcOnlyGPOs = @($reaching | Where-Object {
                    # Normalize GUID to uppercase for hashtable lookup. Guarded, because a
                    # bare index on an unresolved ($null) map emits an error record into the
                    # host for every GPO in the list.
                    $links = $null
                    if ($null -ne $gpoLinkage) { $links = $gpoLinkage[$_.Name.ToUpper()] }
                    if (-not $links) { return $false }

                    $activeLinks = @($links | Where-Object { $_.LinkStatus -ne "Disabled" })
                    if ($activeLinks.Count -eq 0) { return $false }

                    # Check if ALL active links are to Domain Controllers OU only
                    $allLinksToDCOU = $true
                    foreach ($link in $activeLinks) {
                        if ($link.DistinguishedName -notmatch 'OU=Domain Controllers') {
                            $allLinksToDCOU = $false
                            break
                        }
                    }
                    return $allLinksToDCOU
                })

                # If ALL SMB Signing GPOs are DC-only, warn about member servers.
                # Use Hint when the DC policy actually requires signing (partially secured).
                # Keep Finding when signing is only Optional or Disabled on DCs.
                #
                # As the member computers' counterpart of the domain controller object
                # above, not as a line: the sentence had no card behind it, so the HTML
                # report showed it without the remediation the SMB signing card carries.
                # The two values read the way the policy rows read an unset value outside
                # the Domain Controllers OU, which is what the card's triggers answer.
                if (@($dcOnlyGPOs).Count -gt 0 -and @($dcOnlyGPOs).Count -eq $reaching.Count) {
                    $hasRequiredSigning = @($dcOnlyGPOs | Where-Object { $_.ServerSigning -eq 'Required' }).Count -gt 0
                    $dcOnlyClass = if ($hasRequiredSigning) { 'Hint' } else { 'Finding' }
                    $memberPosture = [PSCustomObject]@{
                        ServerSigning = 'Not configured - not required by default before Windows Server 2025'
                        ClientSigning = 'Not configured'
                        # Short; why no policy reaches them, and what is not read here, is
                        # the card's to say.
                        decidedBy     = 'None (signing is set on the DC OU only)'
                    }
                    $memberPosture | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'EffectiveSMBSigningMembers' -Force
                    Show-Line "In force on member servers and clients:" -Class $dcOnlyClass
                    Show-Object $memberPosture -Class $dcOnlyClass
                }

                # Check for insecure configurations and report findings
                $insecureGPOs = @()
                foreach ($gpoFinding in $reaching) {
                    # Server: Disabled or Optional is insecure (allows relay attacks)
                    if ($gpoFinding.ServerSigning -eq "Disabled" -or $gpoFinding.ServerSigning -eq "Optional") {
                        $insecureGPOs += $gpoFinding.DisplayName
                    }
                    # Client: Only flag as insecure if explicitly Disabled
                    elseif ($gpoFinding.ClientSigning -eq "Disabled") {
                        $insecureGPOs += $gpoFinding.DisplayName
                    }
                }

                if ($insecureGPOs.Count -gt 0) {
                    # The names were collected all along and then counted. A number sends
                    # the reader back up through the objects to work out which ones.
                    Show-Line "SMB signing is weakened by: $($insecureGPOs -join ', ')" -Class Finding
                }

            } else {
                Show-Line "No SMB Signing configuration found in any GPO - computers rely on OS defaults (varies by Windows version)" -Class Finding
            }

        } catch {
            Write-Log "[Get-SMBSigningStatus] Error: $_" -Level Error
            Show-Line "Error during check - the SMB signing configuration could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-SMBSigningStatus] Check completed"
    }
}
