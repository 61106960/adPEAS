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

            $lockoutThreshold = if ($domainPolicy.lockoutThreshold -and $domainPolicy.lockoutThreshold -notmatch "Not set") {
                try { [int]$domainPolicy.lockoutThreshold } catch { 0 }
            } else { 0 }

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
                } elseif ($lockoutThreshold -eq 0) {
                    $lockoutDurationText = 'N/A - no lockout is configured'
                } else {
                    $lockoutDurationText = 'Forever (manual unlock)'
                }
            }

            # lockoutWindow in minutes; 0 is displayed as "N/A".
            $lockoutWindowSpan = ConvertFrom-ADInterval -Value $domainPolicy.lockOutObservationWindow
            $lockoutWindow = if ($lockoutWindowSpan) { $lockoutWindowSpan.TotalMinutes } else { 0 }

            # Password Properties - Invoke-LDAPSearch returns flag array (e.g., @("DOMAIN_PASSWORD_COMPLEX"))
            # Check for flags by name instead of bitwise operations
            $pwdPropsValue = $domainPolicy.pwdProperties
            if ($pwdPropsValue -is [array] -or ($pwdPropsValue -is [string] -and $pwdPropsValue -match "DOMAIN_")) {
                # Pre-converted flag names from Invoke-LDAPSearch
                $pwdPropsArray = @($pwdPropsValue)
                $complexityEnabled = $pwdPropsArray -contains "DOMAIN_PASSWORD_COMPLEX"
                $reversibleEncryption = $pwdPropsArray -contains "DOMAIN_PASSWORD_STORE_CLEARTEXT"
            } else {
                # Raw integer value (fallback)
                $pwdPropsInt = if ($pwdPropsValue) { try { [int]$pwdPropsValue } catch { 0 } } else { 0 }
                $complexityEnabled = ($pwdPropsInt -band 1) -ne 0
                $reversibleEncryption = ($pwdPropsInt -band 16) -ne 0
            }

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
                passwordComplexity = if ($complexityEnabled) { "Enabled" } else { "Disabled" }
                reversibleEncryption = if ($reversibleEncryption) { "Enabled" } else { "Disabled" }
                lockoutThreshold = if ($lockoutThreshold -eq 0) { "Disabled" } else { "After $lockoutThreshold failed attempts" }
                lockoutDuration = $lockoutDurationText
                lockoutObservationWindow = if ($lockoutWindow -gt 0) { "$lockoutWindow minutes" } else { "N/A" }
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
            if (-not $complexityEnabled) { $policyWeaknesses += "no_complexity" }
            if ($reversibleEncryption) { $policyWeaknesses += "reversible_encryption" }

            # A threshold of 0 disables account lockout outright: an attacker may guess
            # without limit against every account in the domain, which is the precondition
            # that makes password spraying work. That is not a moderate weakness - it ranks
            # with a short minimum length, not below it.
            if ($lockoutThreshold -eq 0) { $policyWeaknesses += "no_lockout" }

            # Check for moderate weaknesses (Hint)
            $moderateWeaknesses = @()
            if ($hasMinPwdLength -and $minPwdLength -ge 8 -and $minPwdLength -lt 14) { $moderateWeaknesses += "moderate_password_length" }
            if ($lockoutThreshold -gt 10) { $moderateWeaknesses += "high_lockout_threshold" }
            # Same rule: the sentinel and a configured 0 both mean "never expires", and
            # an attribute that did not arrive means nothing at all.
            if ($hasMaxPwdAge -and $maxPwdAge -eq 0) { $moderateWeaknesses += "password_never_expires" }

            # Determine overall severity
            $policySeverity = if (@($policyWeaknesses).Count -gt 0) {
                "Finding"
            } elseif (@($moderateWeaknesses).Count -gt 0) {
                "Hint"
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
                        Write-Log "[Get-DomainPasswordPolicy] Password Settings Container does not exist"
                    }
                } catch {
                    Write-Log "[Get-DomainPasswordPolicy] Password Settings Container does not exist (error: $_)"
                }

                if ($psoContainerExists) {
                    try {
                        $psos = Get-DomainObject -LDAPFilter "(objectClass=msDS-PasswordSettings)" -SearchBase $psoContainerDN @PSBoundParameters

                    if (@($psos).Count -gt 0) {
                        Show-Line "Found $(@($psos).Count) Fine-Grained Password Polic$(if(@($psos).Count -eq 1){'y'}else{'ies'}):" -Class Hint

                        foreach ($pso in $psos) {
                            $psoName = $pso.name
                            $precedence = if ($pso.'msDS-PasswordSettingsPrecedence') { [int]$pso.'msDS-PasswordSettingsPrecedence' } else { 999 }
                            $minLength = if ($pso.'msDS-MinimumPasswordLength') { [int]$pso.'msDS-MinimumPasswordLength' } else { 0 }
                            $complexityEnabled = if ($pso.'msDS-PasswordComplexityEnabled') { $pso.'msDS-PasswordComplexityEnabled' -eq 'TRUE' } else { $false }
                            $reversibleEncryption = if ($pso.'msDS-PasswordReversibleEncryptionEnabled') { $pso.'msDS-PasswordReversibleEncryptionEnabled' -eq 'TRUE' } else { $false }
                            $lockoutThresholdPSO = if ($pso.'msDS-LockoutThreshold') { [int]$pso.'msDS-LockoutThreshold' } else { 0 }
                            $appliesTo = @(@(if ($pso.'msDS-PSOAppliesTo') { $pso.'msDS-PSOAppliesTo' } else { @() }) | Where-Object { $_ })

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
                                precedence = $precedence
                                minPwdLength = if ($minLength -eq 0) { "Disabled" } else { "$minLength characters" }
                                passwordComplexity = if ($complexityEnabled) { "Enabled" } else { "Disabled" }
                                reversibleEncryption = if ($reversibleEncryption) { "Enabled" } else { "Disabled" }
                                lockoutThreshold = if ($lockoutThresholdPSO -eq 0) { "Disabled" } else { "After $lockoutThresholdPSO failed attempts" }
                                appliesTo = if (@($appliesToNames).Count -gt 0) {
                                    (@($appliesToNames) -join ', ')
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
                        #
                        # A policy assigned to nobody applies to nobody. Counting it as a
                        # weakness was the same false positive as an unlinked GPO, which
                        # two other checks in this project state explicitly - so the
                        # unassigned ones are named separately instead.
                        $unassignedPSOs = @()
                        $weakPSOs = @()
                        foreach ($candidate in @($psos)) {
                            $psoTargets = @(@($candidate.'msDS-PSOAppliesTo') | Where-Object { $_ })
                            if (@($psoTargets).Count -eq 0) {
                                $unassignedPSOs += $candidate
                                continue
                            }

                            $psoRE = if ($candidate.'msDS-PasswordReversibleEncryptionEnabled') { $candidate.'msDS-PasswordReversibleEncryptionEnabled' -eq 'TRUE' } else { $false }
                            $psoMinLen = if ($candidate.'msDS-MinimumPasswordLength') { [int]$candidate.'msDS-MinimumPasswordLength' } else { 0 }
                            $psoComp = if ($candidate.'msDS-PasswordComplexityEnabled') { $candidate.'msDS-PasswordComplexityEnabled' -eq 'TRUE' } else { $false }
                            $psoLockout = if ($candidate.'msDS-LockoutThreshold') { [int]$candidate.'msDS-LockoutThreshold' } else { 0 }

                            if ($psoRE -or ($psoMinLen -lt 8) -or (-not $psoComp) -or ($psoLockout -eq 0)) {
                                $weakPSOs += $candidate
                            }
                        }

                        if (@($weakPSOs).Count -gt 0) {
                            # Named, not counted: which policy is weak is the whole
                            # answer, and the line carries the write-up so the HTML
                            # report has an impact and a remediation for it. It had no
                            # FindingId at all, so it reached the report as a sentence
                            # with nothing behind it and no contribution to the score.
                            $weakPSONames = @($weakPSOs | ForEach-Object { "$($_.name)" })
                            Show-Line "$(@($weakPSOs).Count) Fine-Grained Password Polic$(if(@($weakPSOs).Count -eq 1){'y'}else{'ies'}) with a weakness: $(@($weakPSONames) -join ', ')" -Class Finding -FindingId 'WEAK_FGPP'
                        } elseif (@($unassignedPSOs).Count -lt @($psos).Count) {
                            Show-Line "Fine-Grained Password Policies are properly configured" -Class Secure
                        }

                        if (@($unassignedPSOs).Count -gt 0) {
                            $unassignedNames = @($unassignedPSOs | ForEach-Object { "$($_.name)" })
                            Show-Line "Assigned to no user and no group, and therefore not assessed: $(@($unassignedNames) -join ', ')" -Class Note
                        }

                    } else {
                        Show-Line "No Fine-Grained Password Policies configured" -Class Note
                    }
                    } catch {
                        Write-Log "[Get-DomainPasswordPolicy] FGPP enumeration failed: $_" -Level Error
                        Write-Warning "[Get-DomainPasswordPolicy] Failed to query Fine-Grained Password Policies: $_"
                    }
                } else {
                    Show-Line "No Fine-Grained Password Policies configured" -Class Note
                }
            } else {
                Show-Line "Fine-Grained Password Policies not available (requires Domain Functional Level 2008+)" -Raw
            }

        } catch {
            Write-Log "[Get-DomainPasswordPolicy] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-DomainPasswordPolicy] Check completed"
    }
}
