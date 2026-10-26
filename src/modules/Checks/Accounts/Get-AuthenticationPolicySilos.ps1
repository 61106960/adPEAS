function Get-AuthenticationPolicySilos {
    <#
    .SYNOPSIS
    Analyzes authentication policy silos and authentication policies.

    .DESCRIPTION
    An authentication policy silo and the authentication policies it carries restrict the
    devices an account may sign on from, the principals that may authenticate to a service
    running as it, and how long its ticket-granting ticket lives. They protect only where
    the KDC applies them, and each of the following leaves an account looking protected
    while it is not:

    1. Audit mode. A silo or a directly assigned policy that is not enforced makes the KDC
       log what it would have refused and refuse nothing. For a silo member the silo's flag
       decides, not the policy's (MS-KILE 3.3.5.5).
    2. An enforced silo without an authentication policy, or without an enrolled account.
    3. Incomplete enrollment. The KDC applies a silo only to an account that is assigned to
       it (msDS-AssignedAuthNPolicySilo) and listed among its members
       (msDS-AuthNPolicySiloMembers) - MS-KILE 3.3.5.4. Either half alone does nothing, and
       Windows accepts an assignment without the membership (measured).
    4. The built-in Administrator, which Windows always exempts from authentication
       policies, assigned or not.
    5. A condition that admits a broad group - "any domain computer" as the devices an
       account may sign on from restricts nothing.
    6. Write access for a principal outside Tier 0, which can switch a silo to audit mode,
       enroll or remove an account, or rewrite a policy.

    All of it lives in the configuration partition, whose silo and policy objects grant
    Authenticated Users read access by default (measured), so a domain user sees it all.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-AuthenticationPolicySilos

    .EXAMPLE
    Get-AuthenticationPolicySilos -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Accounts
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
        Write-Log "[Get-AuthenticationPolicySilos] Starting check"
    }

    process {
        try {
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            # For the helpers below, which have no $PSBoundParameters of this function.
            $connectionParams = @{}
            foreach ($connectionKey in @('Domain', 'Server', 'Credential')) {
                if ($PSBoundParameters.ContainsKey($connectionKey)) { $connectionParams[$connectionKey] = $PSBoundParameters[$connectionKey] }
            }

            Show-SubHeader "Analyzing authentication policy silos and authentication policies..." -ObjectType "AuthNPolicySilo"

            $configNC = [string]$Script:LDAPContext.ConfigurationNamingContext
            if (-not $configNC) {
                Show-Line "The configuration naming context is not known - authentication policy silos were not checked" -Class Note
                return
            }
            $authNBase = "CN=AuthN Policy Configuration,CN=Services,$configNC"

            $silos = @()
            $policies = @()
            try {
                $silos = @(Get-DomainObject -LDAPFilter '(objectClass=msDS-AuthNPolicySilo)' -SearchBase $authNBase @connectionParams)
                $policies = @(Get-DomainObject -LDAPFilter '(objectClass=msDS-AuthNPolicy)' -SearchBase $authNBase @connectionParams)
            } catch {
                Write-Log "[Get-AuthenticationPolicySilos] The authentication policy configuration could not be read: $_" -Level Warning
                Show-Line "The authentication policy configuration could not be read - not checked" -Class Note
                return
            }

            if ($silos.Count -eq 0 -and $policies.Count -eq 0) {
                # Neither secure nor insecure: the feature is simply not in use.
                Show-Line "No authentication policy silo and no authentication policy is configured"
                return
            }

            # The built-in Administrator of this domain, which Windows exempts from every
            # authentication policy. Members from other domains of the forest are compared
            # by DN only, so their own Administrator is not recognised.
            $builtinAdminDN = $null
            if ($Script:LDAPContext.DomainSID) {
                try {
                    $builtinAdmin = @(Get-DomainObject -Identity "$($Script:LDAPContext.DomainSID)-500" -Properties 'distinguishedName' @connectionParams)[0]
                    if ($builtinAdmin) { $builtinAdminDN = [string]$builtinAdmin.distinguishedName }
                } catch {
                    Write-Log "[Get-AuthenticationPolicySilos] The built-in Administrator could not be looked up: $_"
                }
            }

            $siloAttributes = @('msDS-AuthNPolicySiloMembers', 'msDS-AuthNPolicySiloEnforced', 'msDS-UserAuthNPolicy',
                                'msDS-ComputerAuthNPolicy', 'msDS-ServiceAuthNPolicy')
            $policyAttributes = @('msDS-AuthNPolicyEnforced', 'msDS-UserAllowedToAuthenticateFrom', 'msDS-UserAllowedToAuthenticateTo',
                                  'msDS-ServiceAllowedToAuthenticateFrom', 'msDS-ServiceAllowedToAuthenticateTo',
                                  'msDS-ComputerAllowedToAuthenticateTo', 'msDS-UserTGTLifetime', 'msDS-ServiceTGTLifetime',
                                  'msDS-ComputerTGTLifetime')

            # ----- Silos -----
            $siloClasses = @()
            foreach ($silo in $silos) {
                $members  = @(@($silo.'msDS-AuthNPolicySiloMembers') | Where-Object { $_ } | ForEach-Object { [string]$_ })
                $assigned = @(@($silo.'msDS-AssignedAuthNPolicySiloBL') | Where-Object { $_ } | ForEach-Object { [string]$_ })
                # -contains compares without regard to case, as the DC compares DNs.
                $enrolled           = @($members | Where-Object { $assigned -contains $_ })
                $membersNotAssigned = @($members | Where-Object { $assigned -notcontains $_ })
                $assignedNotMembers = @($assigned | Where-Object { $members -notcontains $_ })
                $siloPolicies = @(@($silo.'msDS-UserAuthNPolicy', $silo.'msDS-ComputerAuthNPolicy', $silo.'msDS-ServiceAuthNPolicy') | Where-Object { $_ })
                $enforced = ([string]@($silo.'msDS-AuthNPolicySiloEnforced')[0]) -eq 'TRUE'

                $status = 'Enforced'
                if (-not $enforced) {
                    $status = 'Audit only - the KDC restricts no member'
                } elseif ($siloPolicies.Count -eq 0) {
                    $status = 'No authentication policy - the KDC restricts no member'
                } elseif ($enrolled.Count -eq 0) {
                    $status = 'No account enrolled - the KDC restricts nobody'
                }
                $silo | Add-Member -NotePropertyName 'siloStatus' -NotePropertyValue $status -Force

                if ($membersNotAssigned.Count -gt 0) {
                    $silo | Add-Member -NotePropertyName 'siloMembersNotAssigned' -NotePropertyValue @($membersNotAssigned | ForEach-Object { Get-AuthNObjectName -DistinguishedName $_ }) -Force
                }
                if ($assignedNotMembers.Count -gt 0) {
                    $silo | Add-Member -NotePropertyName 'siloAssignedNotMembers' -NotePropertyValue @($assignedNotMembers | ForEach-Object { Get-AuthNObjectName -DistinguishedName $_ }) -Force
                }
                if ($builtinAdminDN -and (@($members + $assigned) -contains $builtinAdminDN)) {
                    $silo | Add-Member -NotePropertyName 'siloExemptAccount' -NotePropertyValue "$(Get-AuthNObjectName -DistinguishedName $builtinAdminDN) (built-in Administrator, always exempt)" -Force
                }

                # The policies by name: each is listed in full below, and its DN in the
                # configuration partition filled a console line on its own.
                foreach ($policyAttribute in @('msDS-UserAuthNPolicy', 'msDS-ComputerAuthNPolicy', 'msDS-ServiceAuthNPolicy')) {
                    $policyDN = [string]@($silo.$policyAttribute)[0]
                    if ($policyDN) { $silo.$policyAttribute = Get-AuthNObjectName -DistinguishedName $policyDN }
                }

                $writers = @(Get-AuthNObjectWriter -DistinguishedName ([string]$silo.distinguishedName) -Attribute $siloAttributes -ConnectionParams $connectionParams)
                if ($writers.Count -gt 0) {
                    $silo | Add-Member -NotePropertyName 'siloWritableBy' -NotePropertyValue $writers -Force
                }

                $siloClass = 'Standard'
                if ($writers.Count -gt 0) {
                    $siloClass = 'Finding'
                } elseif ($status -ne 'Enforced' -or $membersNotAssigned.Count -gt 0 -or $assignedNotMembers.Count -gt 0 -or $silo.PSObject.Properties['siloExemptAccount']) {
                    $siloClass = 'Hint'
                }
                $silo | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'AuthNPolicySilo' -Force
                $siloClasses += $siloClass
            }

            # ----- Policies -----
            $policyClasses = @()
            $conditionsSet = $false
            foreach ($policy in $policies) {
                $assignedAccounts = @(@($policy.'msDS-AssignedAuthNPolicyBL') | Where-Object { $_ } | ForEach-Object { [string]$_ })
                $usingSilos = @(@($policy.'msDS-UserAuthNPolicyBL') + @($policy.'msDS-ComputerAuthNPolicyBL') + @($policy.'msDS-ServiceAuthNPolicyBL') | Where-Object { $_ })
                $enforced = ([string]@($policy.'msDS-AuthNPolicyEnforced')[0]) -eq 'TRUE'

                # The policy's own flag decides only for the accounts it is assigned to
                # directly; for a silo member the silo's flag decides.
                $status = 'Enforced'
                if ($assignedAccounts.Count -gt 0 -and -not $enforced) {
                    $status = 'Audit only - the KDC restricts no assigned account'
                } elseif ($assignedAccounts.Count -eq 0 -and $usingSilos.Count -eq 0) {
                    $status = 'Unused - no silo and no account refers to it'
                } elseif ($assignedAccounts.Count -eq 0) {
                    $status = 'Used through silos - their enforcement decides'
                }
                $policy | Add-Member -NotePropertyName 'policyStatus' -NotePropertyValue $status -Force

                if ($builtinAdminDN -and ($assignedAccounts -contains $builtinAdminDN)) {
                    $policy | Add-Member -NotePropertyName 'policyExemptAccount' -NotePropertyValue "$(Get-AuthNObjectName -DistinguishedName $builtinAdminDN) (built-in Administrator, always exempt)" -Force
                }

                # The lifetimes in minutes and the conditions as SDDL. The directory holds
                # 100-nanosecond intervals and binary security descriptors, and neither
                # tells a reader anything as it stands.
                foreach ($lifetimeAttribute in @('msDS-UserTGTLifetime', 'msDS-ServiceTGTLifetime', 'msDS-ComputerTGTLifetime')) {
                    $minutes = ConvertFrom-AuthNTGTLifetime -Value @($policy.$lifetimeAttribute)[0]
                    if ($minutes) { $policy.$lifetimeAttribute = $minutes }
                }
                $broadConditions = @()
                foreach ($conditionAttribute in @('msDS-UserAllowedToAuthenticateFrom', 'msDS-UserAllowedToAuthenticateTo',
                                                  'msDS-ServiceAllowedToAuthenticateFrom', 'msDS-ServiceAllowedToAuthenticateTo',
                                                  'msDS-ComputerAllowedToAuthenticateTo')) {
                    # The value as it is: a single-valued byte[], which @(...)[0] would take
                    # apart into its first byte.
                    $sddl = ConvertTo-AuthNConditionText -Value $policy.$conditionAttribute
                    if (-not $sddl) { continue }
                    $conditionsSet = $true
                    $policy.$conditionAttribute = $sddl
                    $broadNames = @(Get-AuthNBroadCondition -Sddl $sddl)
                    if ($broadNames.Count -gt 0) {
                        $broadConditions += "$conditionAttribute admits $($broadNames -join ', ')"
                    }
                }
                if ($broadConditions.Count -gt 0) {
                    $policy | Add-Member -NotePropertyName 'broadConditions' -NotePropertyValue $broadConditions -Force
                }

                $writers = @(Get-AuthNObjectWriter -DistinguishedName ([string]$policy.distinguishedName) -Attribute $policyAttributes -ConnectionParams $connectionParams)
                if ($writers.Count -gt 0) {
                    $policy | Add-Member -NotePropertyName 'policyWritableBy' -NotePropertyValue $writers -Force
                }

                $policyClass = 'Standard'
                if ($writers.Count -gt 0) {
                    $policyClass = 'Finding'
                } elseif ($status -like 'Audit only*' -or $broadConditions.Count -gt 0 -or $policy.PSObject.Properties['policyExemptAccount']) {
                    $policyClass = 'Hint'
                }
                $policy | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'AuthNPolicy' -Force
                $policyClasses += $policyClass
            }

            # ----- Output -----
            if ($silos.Count -gt 0) {
                Show-Line "Found $($silos.Count) authentication policy silo(s):" -Class (Get-AuthNHeadlineClass -Class $siloClasses)
                for ($i = 0; $i -lt $silos.Count; $i++) { Show-Object $silos[$i] -Class $siloClasses[$i] }
            } else {
                Show-Line "No authentication policy silo is configured"
            }

            if ($policies.Count -gt 0) {
                Show-Line "Found $($policies.Count) authentication policy(ies):" -Class (Get-AuthNHeadlineClass -Class $policyClasses)
                for ($i = 0; $i -lt $policies.Count; $i++) { Show-Object $policies[$i] -Class $policyClasses[$i] }
            }

            # Device and service conditions need the domain controllers to apply "KDC
            # support for claims, compound authentication and Kerberos armoring", which is a
            # Group Policy setting this check does not read. TGT lifetimes do not need it.
            if ($conditionsSet) {
                Show-Line "Sign-on and service conditions need DC support for claims and Kerberos armoring - not checked" -Class Note
            }

            if (@(@($siloClasses) + @($policyClasses) | Where-Object { $_ -ne 'Standard' }).Count -eq 0) {
                Show-Line "Every silo is enforced with its members enrolled, and only Tier 0 can change silos and policies" -Class Secure
            }

        } catch {
            Write-Log "[Get-AuthenticationPolicySilos] Error: $_" -Level Error
            Show-Line "Error during check - authentication policy silos could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-AuthenticationPolicySilos] Check completed"
    }
}

<#
.SYNOPSIS
    The first RDN value of a DN, for a short console value.

.PARAMETER DistinguishedName
    The DN.

.OUTPUTS
    String - the value of the first RDN, or the DN itself where it has none.
#>
function Get-AuthNObjectName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$DistinguishedName
    )

    if ($DistinguishedName -match '^[A-Za-z]+=((?:\\.|[^,])+)') { return $Matches[1] }
    return $DistinguishedName
}

<#
.SYNOPSIS
    The class a headline gets from the classes of the objects below it.

.PARAMETER Class
    The classes of the objects.

.OUTPUTS
    'Finding' if any object is one, else 'Hint' if any object is one, else 'Note'.
#>
function Get-AuthNHeadlineClass {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [string[]]$Class = @()
    )

    if ($Class -contains 'Finding') { return 'Finding' }
    if ($Class -contains 'Hint') { return 'Hint' }
    return 'Note'
}

<#
.SYNOPSIS
    A TGT lifetime of an authentication policy in minutes.

.DESCRIPTION
    msDS-UserTGTLifetime and its siblings hold 100-nanosecond intervals (measured: 240
    minutes are stored as 144000000000), although the schema description speaks of
    seconds. The resulting ticket is not renewable, and the KDC never issues one that
    outlives the domain's own maximum.

.PARAMETER Value
    The stored value.

.OUTPUTS
    String - "N minutes", or $null for no or an unreadable value.
#>
function ConvertFrom-AuthNTGTLifetime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value
    )

    $ticks = [long]0
    if ($null -eq $Value -or -not [long]::TryParse([string]$Value, [ref]$ticks) -or $ticks -le 0) { return $null }
    return "$([long]($ticks / 600000000)) minutes"
}

<#
.SYNOPSIS
    An AllowedToAuthenticateFrom/To condition of an authentication policy as SDDL.

.DESCRIPTION
    The condition is a self-relative security descriptor whose DACL holds a callback ACE
    with the conditional expression. RawSecurityDescriptor renders it, condition included,
    on Windows PowerShell 5.1 and PowerShell 7 alike (measured):
    O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID(S-1-5-21-...-515)})).

.PARAMETER Value
    The stored value - bytes as the directory sends them, or SDDL text already.

.OUTPUTS
    String - the SDDL, or $null for no or an unreadable value.
#>
function ConvertTo-AuthNConditionText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) {
        if ($Value) { return $Value }
        return $null
    }
    if (-not ($Value -is [byte[]]) -or $Value.Length -eq 0) { return $null }
    try {
        return (New-Object System.Security.AccessControl.RawSecurityDescriptor($Value, 0)).GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
    } catch {
        Write-Log "[Get-AuthenticationPolicySilos] A condition could not be read: $_"
        return $null
    }
}

<#
.SYNOPSIS
    The broad groups a condition admits.

.DESCRIPTION
    A condition restricts nothing when one of its allow ACEs admits a group that holds most
    of the domain - "Member_of_any {SID(Domain Computers)}" as the devices an account may
    sign on from is every domain-joined machine. One such ACE is enough: access is granted
    when any allow ACE matches, so a narrower ACE beside it changes nothing.

    Recognised as broad: an allow ACE without a condition for a broad trustee, and a
    callback ACE for a broad trustee whose whole expression is one Member_of /
    Member_of_any / Device_Member_of / Device_Member_of_any test over broad SIDs only.
    Anything else - a silo claim, a named group, a combination - is a real restriction as
    far as this check can tell. A descriptor with a deny ACE is left alone altogether: the
    deny may take back what the broad ACE grants.

.PARAMETER Sddl
    The condition as SDDL.

.OUTPUTS
    The names of the broad groups admitted, one by one; nothing when the condition is not
    broad.
#>
function Get-AuthNBroadCondition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Sddl
    )

    # The SDDL aliases a condition can name for a broad group. Domain-relative ones (DU, DC)
    # are written as full SIDs by GetSddlForm, which Test-IsBroadTrustee reads by RID.
    $aliases = @{ 'WD' = 'S-1-1-0'; 'AU' = 'S-1-5-11'; 'BU' = 'S-1-5-32-545'; 'IU' = 'S-1-5-4' }
    $broadSIDs = @()

    $aces = @([regex]::Matches($Sddl, '\((?<type>[A-Z]+);[^;]*;[^;]*;[^;]*;[^;]*;(?<sid>[^;)]+)(?:;(?<cond>\(.*?\)))?\)(?=\(|$)'))
    if (@($aces | Where-Object { $_.Groups['type'].Value -in @('D', 'XD', 'OD') }).Count -gt 0) { return }

    foreach ($ace in $aces) {
        if ($ace.Groups['type'].Value -notin @('A', 'XA')) { continue }
        $trustee = [string]$ace.Groups['sid'].Value
        if ($aliases.ContainsKey($trustee)) { $trustee = $aliases[$trustee] }
        if (-not (Test-IsBroadTrustee -SID $trustee)) { continue }

        $condition = [string]$ace.Groups['cond'].Value
        if (-not $condition) {
            # No condition: the ACE admits its broad trustee as it is.
            $broadSIDs += $trustee
            continue
        }

        $expression = $condition.Trim()
        while ($expression.StartsWith('(') -and $expression.EndsWith(')')) {
            $expression = $expression.Substring(1, $expression.Length - 2).Trim()
        }
        if ($expression -notmatch '^(?:Device_)?Member_of(?:_any)?\s*\{(?<sids>[^}]*)\}$') { continue }

        $named = @([regex]::Matches($Matches['sids'], 'SID\((?<s>[^)]+)\)') | ForEach-Object {
            $s = [string]$_.Groups['s'].Value
            if ($aliases.ContainsKey($s)) { $aliases[$s] } else { $s }
        })
        if ($named.Count -eq 0) { continue }
        if (@($named | Where-Object { -not (Test-IsBroadTrustee -SID $_) }).Count -gt 0) { continue }
        $broadSIDs += $named
    }

    foreach ($broadSID in @($broadSIDs | Select-Object -Unique)) {
        $broadName = ConvertFrom-SID -SID $broadSID
        if ($broadName) { $broadName } else { $broadSID }
    }
}

<#
.SYNOPSIS
    The principals outside Tier 0 that may change a silo or a policy.

.DESCRIPTION
    Read the way Get-CriticalObjectACLs reads its objects: the owner, and every allow ACE
    that applies to the object itself and grants GenericAll, GenericWrite, WriteDacl,
    WriteOwner, an unrestricted WriteProperty, or WriteProperty on one of the attributes
    that decide what the object restricts. Tier 0 holds these by default; an operator does
    not, and counts.

.PARAMETER DistinguishedName
    The silo or policy.

.PARAMETER Attribute
    The attributes whose write matters on it, by name in $Script:PropertyGUIDs.

.PARAMETER ConnectionParams
    Domain, Server and Credential of the calling check.

.OUTPUTS
    One string per principal: "NAME (rights)".
#>
function Get-AuthNObjectWriter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName,

        [Parameter(Mandatory = $false)]
        [string[]]$Attribute = @(),

        [Parameter(Mandatory = $false)]
        [hashtable]$ConnectionParams = @{}
    )

    $aclResult = $null
    try {
        $aclResult = Get-ObjectACL -DistinguishedName $DistinguishedName -DangerousOnly -AllowOnly @ConnectionParams
    } catch {
        Write-Log "[Get-AuthenticationPolicySilos] The ACL of $DistinguishedName could not be read: $_"
    }
    if (-not $aclResult) { return }

    $attributeByGuid = @{}
    foreach ($name in $Attribute) {
        if ($Script:PropertyGUIDs.ContainsKey($name)) { $attributeByGuid[$Script:PropertyGUIDs[$name].ToString().ToLowerInvariant()] = $name }
    }

    $rightsBySID = [ordered]@{}
    $nameBySID = @{}
    if ($aclResult.OwnerSID) {
        $rightsBySID[[string]$aclResult.OwnerSID] = @('Owner')
        $nameBySID[[string]$aclResult.OwnerSID] = $(if ($aclResult.Owner) { [string]$aclResult.Owner } else { [string]$aclResult.OwnerSID })
    }
    foreach ($ace in @($aclResult.ACEs)) {
        if (-not (Test-ACEAppliesToSelf -ACE $ace)) { continue }

        $granted = @()
        $objectType = ([string]$ace.ObjectType).ToLowerInvariant()
        if (-not $objectType -or $objectType -eq '00000000-0000-0000-0000-000000000000') {
            $granted += @($ace.RightsRaw | Where-Object { $_ -in @('GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'WriteProperty') })
        } elseif ($attributeByGuid.ContainsKey($objectType) -and @($ace.RightsRaw) -contains 'WriteProperty') {
            $granted += "WriteProperty ($($attributeByGuid[$objectType]))"
        }
        if ($granted.Count -eq 0) { continue }

        $sid = [string]$ace.TrusteeSID
        if (-not $rightsBySID.Contains($sid)) {
            $rightsBySID[$sid] = @()
            $nameBySID[$sid] = $(if ($ace.Trustee) { [string]$ace.Trustee } else { $sid })
        }
        $rightsBySID[$sid] = @($rightsBySID[$sid]) + $granted
    }

    foreach ($sid in @($rightsBySID.Keys)) {
        if ((Test-IsPrivileged -Identity $sid).Category -eq 'Privileged') { continue }
        "$($nameBySID[$sid]) ($(@($rightsBySID[$sid] | Select-Object -Unique) -join ', '))"
    }
}
