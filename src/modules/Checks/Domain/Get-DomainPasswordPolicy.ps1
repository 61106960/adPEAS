function Get-DomainPasswordPolicy {
    <#
    .SYNOPSIS
    Analyzes domain password policy configuration.

    .DESCRIPTION
    Evaluates both domain-level and Fine-Grained Password Policies (FGPP/PSO) for security weaknesses:

    Collects:
    - Domain Default Policy:
    - Fine-Grained Password Policies (FGPP):

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
            # they are, and the exemption gets a sentence of its own.
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
            $adminLockoutApplies  = $pwdPropsNames -contains 'DOMAIN_LOCKOUT_ADMINS'

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
            }

            # Every flag that is set, named and read out - so a reader sees the whole
            # attribute, not the two flags the verdict uses. Only where the attribute
            # arrived; an absent one says nothing about any flag.
            if ($hasPwdProperties) {
                $pwdPropsDisplay = @($pwdPropsSet | ForEach-Object { "$($_.Name) - $($_.Text)" })
                if ($pwdPropsDisplay.Count -eq 0) { $pwdPropsDisplay = @('None set') }
                $passwordPolicyObj | Add-Member -NotePropertyName 'passwordProperties' -NotePropertyValue $pwdPropsDisplay -Force
            }

            # Without DOMAIN_LOCKOUT_ADMINS - the default - failed network logons never lock
            # the built-in Administrator (RID 500) out, so the lockout above does not slow
            # down guessing its password. Information, not a verdict: it is the state every
            # domain ships in. Said only where there is a lockout to be exempt from.
            if ($hasPwdProperties -and $lockoutThreshold -gt 0 -and -not $adminLockoutApplies) {
                $passwordPolicyObj | Add-Member -NotePropertyName 'builtinAdministratorLockout' `
                    -NotePropertyValue 'the built-in Administrator is exempt from account lockout - DOMAIN_LOCKOUT_ADMINS is not set' -Force
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

            # Nothing weak among the values that were read is not a secure policy while a
            # value that carries a verdict could not be read: the green line vouched for a
            # lockout threshold or a complexity flag nobody had seen. Unknown, not clean -
            # the class the other checks give a result they could not complete.
            $unreadVerdictValues = @()
            if (-not $hasMinPwdLength)     { $unreadVerdictValues += 'minPwdLength' }
            if (-not $hasMaxPwdAge)        { $unreadVerdictValues += 'maxPwdAge' }
            if (-not $hasPwdProperties)    { $unreadVerdictValues += 'pwdProperties' }
            if (-not $hasLockoutThreshold) { $unreadVerdictValues += 'lockoutThreshold' }

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

                if ($psoContainerExists) {
                    try {
                        $psos = Get-DomainObject -LDAPFilter "(objectClass=msDS-PasswordSettings)" -SearchBase $psoContainerDN @PSBoundParameters

                    if (@($psos).Count -gt 0) {
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

                        $unknownValue = 'Unknown - the value could not be read'
                        $psoReadings = @()

                        foreach ($pso in $psos) {
                            $psoName = $pso.name
                            $precedence           = Read-PSOSetting $pso.'msDS-PasswordSettingsPrecedence'
                            $minLength            = Read-PSOSetting $pso.'msDS-MinimumPasswordLength'
                            $complexityEnabled    = Read-PSOSetting $pso.'msDS-PasswordComplexityEnabled' -Boolean
                            $reversibleEncryption = Read-PSOSetting $pso.'msDS-PasswordReversibleEncryptionEnabled' -Boolean
                            $lockoutThresholdPSO  = Read-PSOSetting $pso.'msDS-LockoutThreshold'
                            $appliesTo = @(@(if ($pso.'msDS-PSOAppliesTo') { $pso.'msDS-PSOAppliesTo' } else { @() }) | Where-Object { $_ })

                            # Not one mandatory value arrived: the policy was not read at all,
                            # and then an empty msDS-PSOAppliesTo says nothing either.
                            $psoRead = ($null -ne $precedence) -or ($null -ne $minLength) -or ($null -ne $complexityEnabled) -or
                                       ($null -ne $reversibleEncryption) -or ($null -ne $lockoutThresholdPSO)

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
                                appliesTo = if (@($appliesToNames).Count -gt 0) {
                                    (@($appliesToNames) -join ', ')
                                } elseif (-not $psoRead) {
                                    'Unknown - the policy could not be read'
                                } else {
                                    'Nobody - this policy is assigned to no user and no group'
                                }
                            }

                            if (@($appliesToPrivileged).Count -gt 0) {
                                $psoObj | Add-Member -NotePropertyName 'appliesToPrivileged' -NotePropertyValue (
                                    'PRIVILEGED - ' + (@($appliesToPrivileged) -join ', ')) -Force
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

                    } else {
                        # Not "none configured": by default Authenticated Users may not read a
                        # policy (Microsoft, "AD DS: Fine-Grained Password Policies"), so an
                        # empty answer is what any account outside Domain Admins gets.
                        Show-Line "No Fine-Grained Password Policy found - by default only Domain Admins can read them" -Class Note
                    }
                    } catch {
                        Write-Log "[Get-DomainPasswordPolicy] FGPP enumeration failed: $_" -Level Error
                        Write-Warning "[Get-DomainPasswordPolicy] Failed to query Fine-Grained Password Policies: $_"
                    }
                } else {
                    # The container is created in every domain and cannot be renamed, moved or
                    # deleted (same source), and its default security descriptor admits only
                    # Domain Admins and SYSTEM - so not finding it means not seeing it, which
                    # says nothing about the policies.
                    Show-Line "No Fine-Grained Password Policy found - by default only Domain Admins can read them" -Class Note
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
