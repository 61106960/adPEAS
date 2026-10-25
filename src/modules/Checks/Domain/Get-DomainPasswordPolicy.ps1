<#
.SYNOPSIS
    The pwdHistoryLength row, for the domain policy and a fine-grained one alike.

.DESCRIPTION
    How many previous passwords may not be set again, 0 to 24. Microsoft's default domain
    policy remembers 24, the maximum, which is also the best practice ("Enforce password
    history"); 0 lets a user set the password a reset replaced at once. A value between
    the two is said as what it is, without a verdict.

.PARAMETER Value
    The number of remembered passwords, or $null when it could not be read.
#>
function Format-PasswordHistoryLength {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) { return 'Unknown - the value could not be read' }
    if ([int]$Value -eq 0) { return 'Disabled - a password can be set again right away' }
    if ([int]$Value -lt 24) { return "$Value passwords remembered - fewer than the 24 Microsoft sets by default" }
    return "$Value passwords remembered"
}

<#
.SYNOPSIS
    The Fine-Grained Password Policies an account outside Domain Admins can find: by name
    in the Password Settings Container, and through the users and groups they are
    assigned to.

.DESCRIPTION
    By default only Domain Admins and SYSTEM may read a policy (Microsoft, "AD DS:
    Fine-Grained Password Policies"). Its name is visible all the same: a one-level search
    below the Password Settings Container returns the DN of every policy in it. Measured
    in a lab domain as a domain user: all three policies, the one assigned to nobody
    included, came back without a single attribute. The search has to match on
    (objectClass=*), which the directory answers without reading objectClass; a lookup of
    the container itself by its DN returns nothing, since distinguishedName is not
    readable either.

    The assignment is stored at the other end too: msDS-PSOApplied, the back link of
    msDS-PSOAppliesTo, holds the DN of the policy on every user and global group the
    policy names. It belongs to no property set, so it needs Read all properties on that
    object - which Pre-Windows 2000 Compatible Access holds on every user and group, and
    Authenticated Users is a member of it by default. The scanning account's own
    msDS-ResultantPSO, the policy that wins for it, is readable to the account itself; it
    is constructed, so it has to be asked for by name.

    All three carry a DN and nothing more: the name of a policy and whom it is assigned
    to, never its settings or its precedence. An assignment on an object this account may
    not read stays invisible, and so does a policy where the container cannot be listed.

.PARAMETER DomainDN
    The DN of the domain searched.

.PARAMETER ThisAccountDN
    The DN of the scanning account, or empty. Read only when it lies in DomainDN - the
    resultant policy of an account from another domain is not one of this domain's.

.PARAMETER ConnectionParams
    Domain, Server and Credential for Get-DomainObject, where the check was given them.

.OUTPUTS
    One PSCustomObject per policy, sorted by name: DistinguishedName, Name, Targets (the
    DNs of the users and groups it was found on), InEffectForThisAccount and Listed
    (whether the listing of the container returned it).
#>
function Get-PSOAssignment {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainDN,

        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ThisAccountDN,

        [Parameter(Mandatory=$false)]
        [hashtable]$ConnectionParams = @{}
    )

    # Keyed by the policy DN; a PowerShell hashtable compares string keys without case,
    # as the directory compares DNs.
    $policies = @{}
    function Add-PSOEntry {
        param([string]$PolicyDN)
        if (-not $policies.ContainsKey($PolicyDN)) {
            $parsedDN = Split-LDAPDN -DistinguishedName $PolicyDN
            $policyName = if ($parsedDN -and $parsedDN.RDNValue) { $parsedDN.RDNValue } else { $PolicyDN }
            $policies[$PolicyDN] = [PSCustomObject]@{
                DistinguishedName      = $PolicyDN
                Name                   = $policyName
                Targets                = @()
                InEffectForThisAccount = $false
                Listed                 = $false
            }
        }
        return $policies[$PolicyDN]
    }

    # Only the DNs of the direct children: the container holds nothing but policies, and
    # the base entry is the container itself.
    $psoContainerDN = "CN=Password Settings Container,CN=System,$DomainDN"
    $listedPolicies = @(Get-DomainObject -LDAPFilter '(objectClass=*)' -SearchBase $psoContainerDN -Scope OneLevel -Properties 'distinguishedName' @ConnectionParams)
    foreach ($listedPolicy in $listedPolicies) {
        $listedDN = if ($listedPolicy) { [string]$listedPolicy.distinguishedName } else { '' }
        if (-not $listedDN.EndsWith(",$psoContainerDN", [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        (Add-PSOEntry -PolicyDN $listedDN).Listed = $true
    }

    # The users and groups are read for this lookup only and never shown as objects of
    # their own, so the property list is allowed here.
    $assignedObjects = @(Get-DomainObject -LDAPFilter '(msDS-PSOApplied=*)' -Properties 'distinguishedName', 'msDS-PSOApplied' @ConnectionParams)
    foreach ($assignedObject in $assignedObjects) {
        # A $null answer arrives here as one $null element, and a $null value list as one
        # $null value; neither names a policy.
        foreach ($policyDN in @($assignedObject.'msDS-PSOApplied')) {
            if ([string]::IsNullOrWhiteSpace([string]$policyDN)) { continue }
            $entry = Add-PSOEntry -PolicyDN "$policyDN"
            $entry.Targets = @($entry.Targets) + @("$($assignedObject.distinguishedName)")
        }
    }

    if ($ThisAccountDN -and $ThisAccountDN.EndsWith(",$DomainDN", [System.StringComparison]::OrdinalIgnoreCase)) {
        $thisAccount = @(Get-DomainObject -Identity $ThisAccountDN -Properties 'distinguishedName', 'msDS-ResultantPSO' @ConnectionParams)[0]
        $resultantDN = if ($thisAccount) { [string]$thisAccount.'msDS-ResultantPSO' } else { '' }
        if (-not [string]::IsNullOrWhiteSpace($resultantDN)) {
            (Add-PSOEntry -PolicyDN $resultantDN).InEffectForThisAccount = $true
        }
    }

    return @($policies.Values | Sort-Object -Property Name)
}

function Get-DomainPasswordPolicy {
    <#
    .SYNOPSIS
    Analyzes domain password policy configuration.

    .DESCRIPTION
    Evaluates both domain-level and Fine-Grained Password Policies (FGPP/PSO) for security weaknesses:

    Collects:
    - Domain Default Policy: minimum length, complexity, minimum and maximum age, password
      history, reversible encryption, lockout threshold, duration and observation window,
      and the pwdProperties flags that have no row of their own
    - Fine-Grained Password Policies (FGPP): the same settings from each policy, its
      precedence, and whom it applies to

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-DomainPasswordPolicy

    .EXAMPLE
    Get-DomainPasswordPolicy -Domain "contoso.com" -Credential (Get-Credential)

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
        Write-Log "[Get-DomainPasswordPolicy] Starting check"
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            Show-SubHeader "Analyzing password policy..." -ObjectType "DomainPasswordPolicy"

            $domainDN = $Script:LDAPContext.DomainDN

            # Query domain object for password policy attributes
            $domainPolicyResults = Get-DomainObject -Identity $domainDN @PSBoundParameters

            if (-not $domainPolicyResults) {
                Write-Warning "[Get-DomainPasswordPolicy] Could not retrieve domain password policy from $domainDN"
                return
            }

            # Get-DomainObject may return single object or array - normalize to single object
            $domainPolicy = if ($domainPolicyResults -is [array]) { $domainPolicyResults[0] } else { $domainPolicyResults }

            # Extract and convert values.
            # NOTE: The interval attributes (minPwdAge, maxPwdAge, lockoutDuration,
            # lockOutObservationWindow) arrive as the RAW negative 100-nanosecond interval
            # string (e.g. "-18000000000"), NOT pre-formatted: ConvertFrom-LDAPAttribute's
            # FileTime branch claims those attribute names, [DateTime]::FromFileTime()
            # throws on a negative delta, and the raw value falls through. That is
            # deliberate - the BloodHound export needs the raw number - so converting them
            # is this module's job. ConvertFrom-ADInterval does the arithmetic (and knows
            # the Int64.MinValue "never" sentinel, which must be recognised before
            # dividing or it yields a nonsensical value like 15372286728 minutes);
            # what a duration means for the policy is decided here.
            # - minPwdLength, lockoutThreshold: integer as string (e.g., "7")
            # - pwdProperties: flag array (e.g., @("DOMAIN_PASSWORD_COMPLEX", ...))

            # Whether the attribute arrived at all, kept apart from its value - the same
            # distinction the lockout block below already makes, for the same reason.
            #
            # A minPwdLength nobody could read became 0, and 0 renders as "Disabled",
            # which the lt_12 predicate reads as the worst possible policy. So an
            # unreadable attribute produced the hardest finding this check has, about a
            # setting nobody had seen. The other direction of the same mistake is one
            # screen further down in this file.
            $rawMinPwdLength = $domainPolicy.minPwdLength
            $hasMinPwdLength = ($null -ne $rawMinPwdLength) -and
                               (-not [string]::IsNullOrWhiteSpace([string]$rawMinPwdLength))
            $minPwdLength = 0
            if ($hasMinPwdLength) {
                try { $minPwdLength = [int]$rawMinPwdLength } catch { $hasMinPwdLength = $false }
            }

            # minPwdAge / maxPwdAge in whole days. ConvertFrom-ADInterval answers $null
            # for three different things - an unreadable value, an absent one, and the
            # Int64.MinValue "never" sentinel - so the raw attribute decides whether
            # anything was read, and the TimeSpan decides what it said.
            $rawMinPwdAge = $domainPolicy.minPwdAge
            $hasMinPwdAge = ($null -ne $rawMinPwdAge) -and
                            (-not [string]::IsNullOrWhiteSpace([string]$rawMinPwdAge))
            $minPwdAgeSpan = ConvertFrom-ADInterval -Value $rawMinPwdAge
            $minPwdAge = if ($minPwdAgeSpan) { [Math]::Round($minPwdAgeSpan.TotalDays) } else { 0 }

            $rawMaxPwdAge = $domainPolicy.maxPwdAge
            $hasMaxPwdAge = ($null -ne $rawMaxPwdAge) -and
                            (-not [string]::IsNullOrWhiteSpace([string]$rawMaxPwdAge))
            $maxPwdAgeSpan = ConvertFrom-ADInterval -Value $rawMaxPwdAge
            $maxPwdAge = if ($maxPwdAgeSpan) { [Math]::Round($maxPwdAgeSpan.TotalDays) } else { 0 }

            # The same split for the lockout threshold. Its 0 carries the no_lockout
            # verdict, and an absent attribute became that 0 - "Account lockout disabled"
            # about a threshold nobody had read. "Not set" is a read value and means 0.
            $rawLockoutThreshold = $domainPolicy.lockoutThreshold
            $hasLockoutThreshold = ($null -ne $rawLockoutThreshold) -and
                                   (-not [string]::IsNullOrWhiteSpace([string]$rawLockoutThreshold))
            $lockoutThreshold = 0
            if ($hasLockoutThreshold -and [string]$rawLockoutThreshold -notmatch 'Not set') {
                try { $lockoutThreshold = [int]$rawLockoutThreshold } catch { $hasLockoutThreshold = $false }
            }

            # Three states, and they used to collapse into one. ConvertFrom-ADInterval
            # answers [TimeSpan]::Zero for a configured 0 and $null for three different
            # things - an unreadable value, an absent one, and the Int64.MinValue "never"
            # sentinel - and the display turned every one of them into "Forever (manual
            # unlock)", which the trigger reads as Secure. So a policy whose lockout
            # duration nobody could read, and one where no lockout exists at all, were
            # both reported as a hardening measure. In the second case the report carried
            # "Account lockout disabled" in red and "lockout duration unlimited - a secure
            # configuration" in green, one line apart.
            #
            # 0 and the sentinel do mean the same thing: the account stays locked until
            # somebody unlocks it. What separates them from "not readable" is whether the
            # attribute arrived at all, and what makes the statement a hardening measure
            # is a lockout existing in the first place.
            $rawLockoutDuration = $domainPolicy.lockoutDuration
            $hasLockoutDuration = ($null -ne $rawLockoutDuration) -and
                                  (-not [string]::IsNullOrWhiteSpace([string]$rawLockoutDuration))
            $lockoutDurationSpan = ConvertFrom-ADInterval -Value $rawLockoutDuration
            $lockoutDuration = if ($lockoutDurationSpan) { $lockoutDurationSpan.TotalMinutes } else { 0 }

            $lockoutDurationText = 'Unknown - the value could not be read'
            if ($hasLockoutDuration) {
                if ($lockoutDuration -gt 0) {
                    $lockoutDurationText = "$lockoutDuration minutes"
                } elseif (-not $hasLockoutThreshold) {
                    # Whether there is a lockout to stay in is the threshold's to say.
                    $lockoutDurationText = 'Until manually unlocked - the lockout threshold could not be read'
                } elseif ($lockoutThreshold -eq 0) {
                    $lockoutDurationText = 'N/A - no lockout is configured'
                } else {
                    $lockoutDurationText = 'Forever (manual unlock)'
                }
            }

            # lockoutWindow in minutes; 0 is displayed as "N/A".
            $lockoutWindowSpan = ConvertFrom-ADInterval -Value $domainPolicy.lockOutObservationWindow
            $lockoutWindow = if ($lockoutWindowSpan) { $lockoutWindowSpan.TotalMinutes } else { 0 }

            # pwdHistoryLength: how many previous passwords may not be set again, 0 to 24.
            # It was not read at all. 0 lets a user set the password a reset replaced at
            # once; Microsoft's default domain policy remembers 24, the maximum, and that is
            # also the best practice ("Enforce password history").
            $rawPwdHistoryLength = $domainPolicy.pwdHistoryLength
            $hasPwdHistoryLength = ($null -ne $rawPwdHistoryLength) -and
                                   (-not [string]::IsNullOrWhiteSpace([string]$rawPwdHistoryLength))
            $pwdHistoryLength = 0
            if ($hasPwdHistoryLength) {
                try { $pwdHistoryLength = [int]$rawPwdHistoryLength } catch { $hasPwdHistoryLength = $false }
            }

            # Password Properties - Invoke-LDAPSearch returns a flag array (e.g.,
            # @("DOMAIN_PASSWORD_COMPLEX")), the raw integer is the fallback; both are
            # read through the table below, by name or by bit.
            #
            # All six flags, by name and bit. The texts follow MS-SAMR (Domain Fields,
            # PasswordProperties), which calls three of them reserved, with no effect on the
            # password policy. DOMAIN_LOCKOUT_ADMINS is one of the three, but what it changes
            # is the lockout, not the password policy: DOMAIN_PASSWORD_INFORMATION (ntsecapi.h)
            # documents it as letting network logons lock out the built-in Administrator, who
            # is exempt without it. Two flags carry a verdict below; the rest are shown as
            # they are. The exemption, the state every domain ships in, has no row: it
            # is not a setting a GPO is documented to change for the domain.
            $pwdPropertyFlags = @(
                @{ Name = 'DOMAIN_PASSWORD_COMPLEX';         Bit = 1;  Text = 'complexity required' }
                @{ Name = 'DOMAIN_PASSWORD_NO_ANON_CHANGE';  Bit = 2;  Text = 'reserved - MS-SAMR gives it no effect on the password policy' }
                @{ Name = 'DOMAIN_PASSWORD_NO_CLEAR_CHANGE'; Bit = 4;  Text = 'password change methods that hand the DC the cleartext password are refused' }
                @{ Name = 'DOMAIN_LOCKOUT_ADMINS';           Bit = 8;  Text = 'the built-in Administrator can be locked out from network logons' }
                @{ Name = 'DOMAIN_PASSWORD_STORE_CLEARTEXT'; Bit = 16; Text = 'passwords are stored with reversible encryption' }
                @{ Name = 'DOMAIN_REFUSE_PASSWORD_CHANGE';   Bit = 32; Text = 'reserved - MS-SAMR gives it no effect on the password policy' }
            )

            # And the read/unread split once more: complexity and reversible encryption
            # come from here, and an absent or unparseable attribute used to become 0 - a
            # no_complexity finding about flags nobody had read.
            $pwdPropsValue = $domainPolicy.pwdProperties
            $hasPwdProperties = ($null -ne $pwdPropsValue) -and
                                (-not [string]::IsNullOrWhiteSpace([string]$pwdPropsValue))
            $pwdPropsSet = @()
            if ($hasPwdProperties) {
                if ($pwdPropsValue -is [array] -or ($pwdPropsValue -is [string] -and $pwdPropsValue -match 'DOMAIN_|^NONE$')) {
                    # Pre-converted flag names from Invoke-LDAPSearch; it writes NONE for 0
                    $pwdPropsArray = @($pwdPropsValue)
                    $pwdPropsSet = @($pwdPropertyFlags | Where-Object { $pwdPropsArray -contains $_.Name })
                } else {
                    # Raw integer value (fallback)
                    try {
                        $pwdPropsInt = [int]$pwdPropsValue
                        $pwdPropsSet = @($pwdPropertyFlags | Where-Object { ($pwdPropsInt -band $_.Bit) -ne 0 })
                    } catch {
                        $hasPwdProperties = $false
                    }
                }
            }
            $pwdPropsNames        = @($pwdPropsSet | ForEach-Object { $_.Name })
            $complexityEnabled    = $pwdPropsNames -contains 'DOMAIN_PASSWORD_COMPLEX'
            $reversibleEncryption = $pwdPropsNames -contains 'DOMAIN_PASSWORD_STORE_CLEARTEXT'

            # Create password policy object for consistent display.
            #
            # "Unknown" where the attribute never arrived. It is not a hedge: the three
            # settings below each have a verdict attached to them, and an unreadable
            # value would otherwise be reported as the verdict for its numeric zero -
            # "Disabled" for the length, which is the worst state the policy has.
            $passwordPolicyObj = [PSCustomObject]@{
                minPwdLength = if (-not $hasMinPwdLength) { "Unknown - the value could not be read" }
                               elseif ($minPwdLength -eq 0) { "Disabled" } else { "$minPwdLength characters" }
                minPwdAge = if (-not $hasMinPwdAge) { "Unknown - the value could not be read" }
                            elseif ($minPwdAge -eq 0) { "Disabled" } else { "$minPwdAge days" }
                maxPwdAge = if (-not $hasMaxPwdAge) { "Unknown - the value could not be read" }
                            elseif ($maxPwdAge -eq 0) { "Disabled (Never expires)" } else { "$maxPwdAge days" }
                passwordComplexity = if (-not $hasPwdProperties) { "Unknown - the value could not be read" }
                                     elseif ($complexityEnabled) { "Enabled" } else { "Disabled" }
                reversibleEncryption = if (-not $hasPwdProperties) { "Unknown - the value could not be read" }
                                       elseif ($reversibleEncryption) { "Enabled" } else { "Disabled" }
                lockoutThreshold = if (-not $hasLockoutThreshold) { "Unknown - the value could not be read" }
                                   elseif ($lockoutThreshold -eq 0) { "Disabled" } else { "After $lockoutThreshold failed attempts" }
                lockoutDuration = $lockoutDurationText
                lockoutObservationWindow = if ($lockoutWindow -gt 0) { "$lockoutWindow minutes" } else { "N/A" }
                pwdHistoryLength = Format-PasswordHistoryLength -Value $(if ($hasPwdHistoryLength) { $pwdHistoryLength } else { $null })
            }

            # The flags that have no row of their own, named and read out, so no bit of the
            # attribute is lost. Complexity and reversible encryption are rows above, and
            # in an ordinary domain repeating them was all this row said -
            # "DOMAIN_PASSWORD_COMPLEX - complexity required" two rows under
            # "passwordComplexity: Enabled". With none of the others set there is no row.
            # Only where the attribute arrived; an absent one says nothing about any flag.
            if ($hasPwdProperties) {
                $pwdPropsOwnRow = @('DOMAIN_PASSWORD_COMPLEX', 'DOMAIN_PASSWORD_STORE_CLEARTEXT')
                $pwdPropsDisplay = @($pwdPropsSet | Where-Object { $pwdPropsOwnRow -notcontains $_.Name } |
                    ForEach-Object { "$($_.Name) - $($_.Text)" })
                if ($pwdPropsDisplay.Count -gt 0) {
                    $passwordPolicyObj | Add-Member -NotePropertyName 'passwordProperties' -NotePropertyValue $pwdPropsDisplay -Force
                }
            }

            # Determine severity based on policy weaknesses
            # Finding: Short password (<8), no complexity, reversible encryption, no lockout
            # Hint: Moderate weakness (8-13 chars, high lockout threshold)
            # Secure: Good policy
            $policyWeaknesses = @()

            # Check for critical weaknesses (Finding).
            #
            # Only on values that were read. An unreadable minimum length is not a short
            # one, and "0 characters" is what an absent attribute looked like here -
            # which made the hardest verdict this check has the default answer for a
            # policy nobody had seen. The row says Unknown now, and this list skips it.
            if ($hasMinPwdLength -and $minPwdLength -lt 8) { $policyWeaknesses += "short_password" }
            if ($hasPwdProperties -and -not $complexityEnabled) { $policyWeaknesses += "no_complexity" }
            if ($reversibleEncryption) { $policyWeaknesses += "reversible_encryption" }

            # A threshold of 0 disables account lockout outright: an attacker may guess
            # without limit against every account in the domain, which is the precondition
            # that makes password spraying work. That is not a moderate weakness - it ranks
            # with a short minimum length, not below it.
            if ($hasLockoutThreshold -and $lockoutThreshold -eq 0) { $policyWeaknesses += "no_lockout" }

            # Check for moderate weaknesses (Hint)
            $moderateWeaknesses = @()
            if ($hasMinPwdLength -and $minPwdLength -ge 8 -and $minPwdLength -lt 14) { $moderateWeaknesses += "moderate_password_length" }
            if ($lockoutThreshold -gt 10) { $moderateWeaknesses += "high_lockout_threshold" }
            # Same rule: the sentinel and a configured 0 both mean "never expires", and
            # an attribute that did not arrive means nothing at all.
            if ($hasMaxPwdAge -and $maxPwdAge -eq 0) { $moderateWeaknesses += "password_never_expires" }
            if ($hasPwdHistoryLength -and $pwdHistoryLength -eq 0) { $moderateWeaknesses += "password_history_disabled" }

            # Nothing weak among the values that were read is not a secure policy while a
            # value that carries a verdict could not be read: the green line vouched for a
            # lockout threshold or a complexity flag nobody had seen. Unknown, not clean -
            # the class the other checks give a result they could not complete.
            $unreadVerdictValues = @()
            if (-not $hasMinPwdLength)     { $unreadVerdictValues += 'minPwdLength' }
            if (-not $hasMaxPwdAge)        { $unreadVerdictValues += 'maxPwdAge' }
            if (-not $hasPwdProperties)    { $unreadVerdictValues += 'pwdProperties' }
            if (-not $hasLockoutThreshold) { $unreadVerdictValues += 'lockoutThreshold' }
            if (-not $hasPwdHistoryLength) { $unreadVerdictValues += 'pwdHistoryLength' }

            # Determine overall severity
            $policySeverity = if (@($policyWeaknesses).Count -gt 0) {
                "Finding"
            } elseif (@($moderateWeaknesses).Count -gt 0) {
                "Hint"
            } elseif (@($unreadVerdictValues).Count -gt 0) {
                "Note"
            } else {
                "Secure"
            }

            Show-Line "Found password policy:" -Class $policySeverity
            $passwordPolicyObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'DomainPasswordPolicy' -Force
            Show-Object $passwordPolicyObj -Class $policySeverity

            # ===== Fine-Grained Password Policies (FGPP/PSO) Analysis =====
            Show-SubHeader "Checking for Fine-Grained Password Policies (FGPP)..." -ObjectType "FineGrainedPasswordPolicy"

            # DomainFunctionality might be a string or integer, ensure proper conversion
            $domainFunctionalLevel = 0
            if ($Script:LDAPContext.DomainFunctionality) {
                $dflValue = $Script:LDAPContext.DomainFunctionality
                if ($dflValue -is [int] -or $dflValue -is [long]) {
                    $domainFunctionalLevel = [int]$dflValue
                }
                elseif ($dflValue -is [string]) {
                    # Try to parse as integer
                    $parsed = 0
                    if ([int]::TryParse($dflValue, [ref]$parsed)) {
                        $domainFunctionalLevel = $parsed
                    }
                }
            }
            Write-Log "[Get-DomainPasswordPolicy] Domain Functional Level: $domainFunctionalLevel"

            if ($domainFunctionalLevel -ge 3) {
                # Query Password Settings Container
                $psoContainerDN = "CN=Password Settings Container,CN=System,$domainDN"

                # First check if Password Settings Container exists
                $psoContainerExists = $false
                try {
                    # Use Get-DomainObject to check container existence (no custom SearchBase issues)
                    $containerCheck = Get-DomainObject -Identity $psoContainerDN @PSBoundParameters -ErrorAction SilentlyContinue
                    if ($containerCheck) {
                        $psoContainerExists = $true
                        Write-Log "[Get-DomainPasswordPolicy] Password Settings Container exists"
                    } else {
                        Write-Log "[Get-DomainPasswordPolicy] Password Settings Container not returned - not visible to this account"
                    }
                } catch {
                    Write-Log "[Get-DomainPasswordPolicy] Password Settings Container not returned (error: $_)"
                }

                # Whether the policies themselves came back. Where they did not, they are
                # looked for where they are assigned, below.
                $psosListed = $false

                if ($psoContainerExists) {
                    try {
                        $psos = Get-DomainObject -LDAPFilter "(objectClass=msDS-PasswordSettings)" -SearchBase $psoContainerDN @PSBoundParameters

                    if (@($psos).Count -gt 0) {
                        $psosListed = $true
                        Show-Line "Found $(@($psos).Count) Fine-Grained Password Polic$(if(@($psos).Count -eq 1){'y'}else{'ies'}):" -Class Hint

                        # Every setting read below is a mandatory attribute of
                        # msDS-PasswordSettings (adschema: systemMustContain), so a policy
                        # without one was not read - it was not configured as 0. And by its
                        # default security descriptor only Domain Admins and SYSTEM may read a
                        # policy at all, which makes the absent value the normal case for any
                        # other account. It printed "Disabled", counted as a weakness, and the
                        # precedence became 999 - all about settings nobody had seen.
                        #
                        # Returns $null where the value did not arrive or does not parse - it
                        # used to throw out of [int] and take the whole section with it. A
                        # typed $true or $false reads as the same TRUE or FALSE.
                        function Read-PSOSetting {
                            param($Value, [switch]$Boolean)
                            if ($Boolean) {
                                if ([string]$Value -eq 'TRUE') { return $true }
                                if ([string]$Value -eq 'FALSE') { return $false }
                                return $null
                            }
                            $parsedValue = 0
                            if ([int]::TryParse([string]$Value, [ref]$parsedValue)) { return $parsedValue }
                            return $null
                        }

                        # The four interval settings hold the same negative 100-nanosecond
                        # intervals as maxPwdAge and its siblings on the domain, and arrive
                        # raw for the same reason. $null where the value did not arrive or is
                        # no number; [TimeSpan]::Zero for 0 and for the Int64.MinValue
                        # "never" sentinel, which ConvertFrom-ADInterval answers with $null -
                        # both mean no limit for an age, and until unlocked for a lockout.
                        function Read-PSOInterval {
                            param($Value)
                            if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
                            $span = ConvertFrom-ADInterval -Value $Value
                            if ($null -ne $span) { return $span }
                            $ticks = 0L
                            if ([Int64]::TryParse(([string]$Value).Trim(), [ref]$ticks)) { return [TimeSpan]::Zero }
                            return $null
                        }

                        $unknownValue = 'Unknown - the value could not be read'
                        $psoReadings = @()

                        foreach ($pso in $psos) {
                            $psoName = $pso.name
                            $precedence           = Read-PSOSetting $pso.'msDS-PasswordSettingsPrecedence'
                            $minLength            = Read-PSOSetting $pso.'msDS-MinimumPasswordLength'
                            $complexityEnabled    = Read-PSOSetting $pso.'msDS-PasswordComplexityEnabled' -Boolean
                            $reversibleEncryption = Read-PSOSetting $pso.'msDS-PasswordReversibleEncryptionEnabled' -Boolean
                            $lockoutThresholdPSO  = Read-PSOSetting $pso.'msDS-LockoutThreshold'
                            # Five more mandatory settings, which were not read: a policy that
                            # lets the passwords of the admin group never expire was silent.
                            $historyPSO           = Read-PSOSetting $pso.'msDS-PasswordHistoryLength'
                            $maxAgePSO            = Read-PSOInterval $pso.'msDS-MaximumPasswordAge'
                            $minAgePSO            = Read-PSOInterval $pso.'msDS-MinimumPasswordAge'
                            $lockoutDurationPSO   = Read-PSOInterval $pso.'msDS-LockoutDuration'
                            $lockoutWindowPSO     = Read-PSOInterval $pso.'msDS-LockoutObservationWindow'
                            $appliesTo = @(@(if ($pso.'msDS-PSOAppliesTo') { $pso.'msDS-PSOAppliesTo' } else { @() }) | Where-Object { $_ })

                            # Not one mandatory value arrived: the policy was not read at all,
                            # and then an empty msDS-PSOAppliesTo says nothing either.
                            $psoRead = ($null -ne $precedence) -or ($null -ne $minLength) -or ($null -ne $complexityEnabled) -or
                                       ($null -ne $reversibleEncryption) -or ($null -ne $lockoutThresholdPSO) -or
                                       ($null -ne $historyPSO) -or ($null -ne $maxAgePSO) -or ($null -ne $minAgePSO) -or
                                       ($null -ne $lockoutDurationPSO) -or ($null -ne $lockoutWindowPSO)

                            # A weakness only from a value that was read - and a policy is only
                            # clean when every value a verdict hangs on was. $null is neither
                            # true nor equal to 0, so only the length and the complexity need
                            # the guard: $null is less than 8, and -not $null is true.
                            $psoWeak = $reversibleEncryption -or
                                       (($null -ne $minLength) -and $minLength -lt 8) -or
                                       (($null -ne $complexityEnabled) -and -not $complexityEnabled) -or
                                       ($lockoutThresholdPSO -eq 0)
                            $psoVerdictsRead = ($null -ne $minLength) -and ($null -ne $complexityEnabled) -and
                                               ($null -ne $reversibleEncryption) -and ($null -ne $lockoutThresholdPSO)

                            # A policy assigned to nobody applies to nobody. Counting it as a
                            # weakness was the same false positive as an unlinked GPO, which
                            # two other checks in this project state explicitly - so the
                            # unassigned ones are named separately instead, and so are the ones
                            # that could not be read: not assessed is not the same as clean.
                            $psoState = if (-not $psoRead) {
                                'Unread'
                            } elseif (@($appliesTo).Count -eq 0) {
                                'Unassigned'
                            } elseif ($psoWeak) {
                                'Weak'
                            } elseif (-not $psoVerdictsRead) {
                                'Unread'
                            } else {
                                'Clean'
                            }
                            $psoReadings += [PSCustomObject]@{ Name = "$psoName"; State = $psoState }

                            # Who the policy applies to, by name, and whether any of them
                            # is privileged.
                            #
                            # The row used to read "3 user(s)/group(s)" - a count, which
                            # is the one thing a reader cannot act on. "A weak policy
                            # applies to Domain Admins" is the reason to look at PSOs at
                            # all, and msDS-PSOAppliesTo has carried the answer all along.
                            $appliesToNames = @()
                            $appliesToPrivileged = @()
                            foreach ($targetDN in $appliesTo) {
                                $targetName = (("$targetDN" -split ',')[0]) -replace '^CN=', ''
                                if (-not $targetName) { $targetName = "$targetDN" }
                                $appliesToNames += $targetName

                                $psoTargetPriv = Test-IsPrivileged -Identity "$targetDN" -IncludeOperators
                                if ($psoTargetPriv.IsPrivileged) { $appliesToPrivileged += $targetName }
                            }

                            # Create PSO object for consistent display
                            $psoObj = [PSCustomObject]@{
                                psoName = $psoName
                                precedence = if ($null -eq $precedence) { $unknownValue } else { $precedence }
                                minPwdLength = if ($null -eq $minLength) { $unknownValue }
                                               elseif ($minLength -eq 0) { "Disabled" } else { "$minLength characters" }
                                passwordComplexity = if ($null -eq $complexityEnabled) { $unknownValue }
                                                     elseif ($complexityEnabled) { "Enabled" } else { "Disabled" }
                                reversibleEncryption = if ($null -eq $reversibleEncryption) { $unknownValue }
                                                       elseif ($reversibleEncryption) { "Enabled" } else { "Disabled" }
                                lockoutThreshold = if ($null -eq $lockoutThresholdPSO) { $unknownValue }
                                                   elseif ($lockoutThresholdPSO -eq 0) { "Disabled" } else { "After $lockoutThresholdPSO failed attempts" }
                                # The rows and their texts are the domain policy's, so its
                                # triggers judge a policy and the domain alike.
                                minPwdAge = if ($null -eq $minAgePSO) { $unknownValue }
                                            elseif ([Math]::Round($minAgePSO.TotalDays) -eq 0) { "Disabled" } else { "$([Math]::Round($minAgePSO.TotalDays)) days" }
                                maxPwdAge = if ($null -eq $maxAgePSO) { $unknownValue }
                                            elseif ([Math]::Round($maxAgePSO.TotalDays) -eq 0) { "Disabled (Never expires)" } else { "$([Math]::Round($maxAgePSO.TotalDays)) days" }
                                pwdHistoryLength = Format-PasswordHistoryLength -Value $historyPSO
                                lockoutDuration = if ($null -eq $lockoutDurationPSO) { $unknownValue }
                                                  elseif ($lockoutDurationPSO.TotalMinutes -gt 0) { "$($lockoutDurationPSO.TotalMinutes) minutes" }
                                                  elseif ($null -eq $lockoutThresholdPSO) { 'Until manually unlocked - the lockout threshold could not be read' }
                                                  elseif ($lockoutThresholdPSO -eq 0) { 'N/A - no lockout is configured' }
                                                  else { 'Forever (manual unlock)' }
                                lockoutObservationWindow = if ($null -eq $lockoutWindowPSO) { $unknownValue }
                                                           elseif ($lockoutWindowPSO.TotalMinutes -gt 0) { "$($lockoutWindowPSO.TotalMinutes) minutes" } else { "N/A" }
                                appliesTo = if (@($appliesToNames).Count -gt 0) {
                                    (@($appliesToNames) -join ', ')
                                } elseif (-not $psoRead) {
                                    'Unknown - the policy could not be read'
                                } else {
                                    'Nobody - this policy is assigned to no user and no group'
                                }
                            }

                            # The PRIVILEGED prefix is what the WEAK_FGPP trigger answers, so it
                            # is written for a weak policy only. A strong policy for Domain
                            # Admins is what Microsoft recommends, and it read as a finding with
                            # the card "Weaker Than the Domain Default" behind it.
                            if (@($appliesToPrivileged).Count -gt 0) {
                                $privilegedTargets = @($appliesToPrivileged) -join ', '
                                if ($psoState -eq 'Weak') { $privilegedTargets = 'PRIVILEGED - ' + $privilegedTargets }
                                $psoObj | Add-Member -NotePropertyName 'appliesToPrivileged' -NotePropertyValue $privilegedTargets -Force
                            }

                            # Named and not assessed, so its rows carry no verdict either:
                            # Get-TriggerMatch leaves an object with this context uncoloured.
                            if ($psoState -eq 'Unassigned') {
                                $psoObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'NotAssessed' -Force
                            }

                            $psoObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'FineGrainedPasswordPolicy' -Force
                            Show-Object $psoObj -Class Hint
                        }

                        # Output FGPP findings summary.
                        $weakPSONames       = @($psoReadings | Where-Object { $_.State -eq 'Weak' } | ForEach-Object { $_.Name })
                        $cleanPSONames      = @($psoReadings | Where-Object { $_.State -eq 'Clean' } | ForEach-Object { $_.Name })
                        $unreadPSONames     = @($psoReadings | Where-Object { $_.State -eq 'Unread' } | ForEach-Object { $_.Name })
                        $unassignedPSONames = @($psoReadings | Where-Object { $_.State -eq 'Unassigned' } | ForEach-Object { $_.Name })

                        if ($weakPSONames.Count -gt 0) {
                            # Named, not counted: which policy is weak is the whole
                            # answer, and the line carries the write-up so the HTML
                            # report has an impact and a remediation for it. It had no
                            # FindingId at all, so it reached the report as a sentence
                            # with nothing behind it and no contribution to the score.
                            Show-Line "$($weakPSONames.Count) Fine-Grained Password Polic$(if($weakPSONames.Count -eq 1){'y'}else{'ies'}) with a weakness: $($weakPSONames -join ', ')" -Class Finding -FindingId 'WEAK_FGPP'
                        } elseif ($cleanPSONames.Count -gt 0 -and $unreadPSONames.Count -eq 0) {
                            Show-Line "Fine-Grained Password Policies are properly configured" -Class Secure
                        } elseif ($cleanPSONames.Count -gt 0) {
                            Show-Line "No weakness in the Fine-Grained Password Policies that could be read" -Class Note
                        }

                        if ($unreadPSONames.Count -gt 0) {
                            Show-Line "Could not be read in full, and therefore not assessed: $($unreadPSONames -join ', ')" -Class Note
                        }

                        if ($unassignedPSONames.Count -gt 0) {
                            Show-Line "Assigned to no user and no group, and therefore not assessed: $($unassignedPSONames -join ', ')" -Class Note
                        }

                    }
                    } catch {
                        Write-Log "[Get-DomainPasswordPolicy] FGPP enumeration failed: $_" -Level Error
                        Write-Warning "[Get-DomainPasswordPolicy] Failed to query Fine-Grained Password Policies: $_"
                    }
                }

                # No policy came back - and that is what any account outside Domain Admins
                # gets, whatever the domain holds: by default Authenticated Users may not
                # read a policy (Microsoft, "AD DS: Fine-Grained Password Policies"). The
                # line said so and nothing more.
                #
                # The names of the policies are in the listing of the container, who a
                # policy is assigned to is written on the assigned users and groups, and the
                # policy in force for this account on the account. That gives the names and
                # the direct targets, never the settings.
                if (-not $psosListed) {
                    $connectionParams = @{}
                    if ($PSBoundParameters.ContainsKey('Domain')) { $connectionParams['Domain'] = $Domain }
                    if ($PSBoundParameters.ContainsKey('Server')) { $connectionParams['Server'] = $Server }
                    if ($PSBoundParameters.ContainsKey('Credential')) { $connectionParams['Credential'] = $Credential }

                    $assignedPSOs = $null
                    try {
                        $assignedPSOs = @(Get-PSOAssignment -DomainDN $domainDN -ThisAccountDN ([string]$Script:LDAPContext.AuthenticatedUserDN) -ConnectionParams $connectionParams)
                    } catch {
                        Write-Log "[Get-DomainPasswordPolicy] PSO assignment lookup failed: $_" -Level Error
                        Write-Warning "[Get-DomainPasswordPolicy] Failed to look up Fine-Grained Password Policy assignments: $_"
                    }

                    if ($null -ne $assignedPSOs -and $assignedPSOs.Count -gt 0) {
                        # How they were found: the listing of the container gives every
                        # name, the assignments only the policies that are assigned.
                        $foundBy = if (@($assignedPSOs | Where-Object { $_.Listed }).Count -gt 0) { 'by name and assignment' } else { 'by assignment' }
                        Show-Line "Found $($assignedPSOs.Count) Fine-Grained Password Polic$(if($assignedPSOs.Count -eq 1){'y'}else{'ies'}) $($foundBy):" -Class Hint

                        foreach ($assignedPSO in $assignedPSOs) {
                            $targetNames = @()
                            $privilegedTargetNames = @()
                            foreach ($targetDN in @($assignedPSO.Targets)) {
                                $parsedTarget = Split-LDAPDN -DistinguishedName "$targetDN"
                                $targetName = if ($parsedTarget -and $parsedTarget.RDNValue) { $parsedTarget.RDNValue } else { "$targetDN" }
                                $targetNames += $targetName

                                $assignedTargetPriv = Test-IsPrivileged -Identity "$targetDN" -IncludeOperators
                                if ($assignedTargetPriv.IsPrivileged) { $privilegedTargetNames += $targetName }
                            }

                            # Short rows: what the settings are is not known, and the card says
                            # why. Without the settings rows there is no verdict to draw, so a
                            # privileged target is named without the PRIVILEGED prefix that
                            # makes a weak policy a finding.
                            #
                            # No target: assigned to nobody, or only to users and groups this
                            # account may not read - the two look the same from here.
                            $assignedObj = [PSCustomObject]@{
                                psoName   = $assignedPSO.Name
                                settings  = 'Unknown (readable by Domain Admins only)'
                                appliesTo = if ($targetNames.Count -gt 0) { $targetNames -join ', ' } else { 'Unknown - assigned to no user or group this account can read' }
                            }
                            if ($privilegedTargetNames.Count -gt 0) {
                                $assignedObj | Add-Member -NotePropertyName 'appliesToPrivileged' -NotePropertyValue ($privilegedTargetNames -join ', ') -Force
                            }
                            if ($assignedPSO.InEffectForThisAccount) {
                                $assignedObj | Add-Member -NotePropertyName 'inEffectForThisAccount' -NotePropertyValue 'Yes' -Force
                            }

                            $assignedObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'FineGrainedPasswordPolicy' -Force
                            Show-Object $assignedObj -Class Hint
                        }
                    } elseif ($null -ne $assignedPSOs) {
                        # Not "none configured": where the container cannot be listed, a
                        # policy assigned only to objects this account may not read is not
                        # found either.
                        Show-Line "No Fine-Grained Password Policy found by name or by assignment" -Class Note
                    }
                }
            } else {
                Show-Line "Fine-Grained Password Policies not available (requires Domain Functional Level 2008+)" -Raw
            }

        } catch {
            Write-Log "[Get-DomainPasswordPolicy] Error: $_" -Level Error
            Show-Line "Error during check - the password policy could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-DomainPasswordPolicy] Check completed"
    }
}
