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

            $minPwdLength = if ($domainPolicy.minPwdLength) {
                try { [int]$domainPolicy.minPwdLength } catch { 0 }
            } else { 0 }

            # minPwdAge / maxPwdAge in whole days. A null TimeSpan means the "never"
            # sentinel or an unreadable value; both are 0 here, which the display below
            # renders as "Disabled" resp. "Disabled (Never expires)".
            $minPwdAgeSpan = ConvertFrom-ADInterval -Value $domainPolicy.minPwdAge
            $minPwdAge = if ($minPwdAgeSpan) { [Math]::Round($minPwdAgeSpan.TotalDays) } else { 0 }

            $maxPwdAgeSpan = ConvertFrom-ADInterval -Value $domainPolicy.maxPwdAge
            $maxPwdAge = if ($maxPwdAgeSpan) { [Math]::Round($maxPwdAgeSpan.TotalDays) } else { 0 }

            $lockoutThreshold = if ($domainPolicy.lockoutThreshold -and $domainPolicy.lockoutThreshold -notmatch "Not set") {
                try { [int]$domainPolicy.lockoutThreshold } catch { 0 }
            } else { 0 }

            # lockoutDuration in minutes. 0 and the "never" sentinel both mean the account
            # stays locked until someone unlocks it, and both end up as 0 here - the
            # display below turns that into "Forever (manual unlock)".
            $lockoutDurationSpan = ConvertFrom-ADInterval -Value $domainPolicy.lockoutDuration
            $lockoutDuration = if ($lockoutDurationSpan) { $lockoutDurationSpan.TotalMinutes } else { 0 }

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

            # Create password policy object for consistent display
            $passwordPolicyObj = [PSCustomObject]@{
                minPwdLength = if ($minPwdLength -eq 0) { "Disabled" } else { "$minPwdLength characters" }
                minPwdAge = if ($minPwdAge -eq 0) { "Disabled" } else { "$minPwdAge days" }
                maxPwdAge = if ($maxPwdAge -eq 0) { "Disabled (Never expires)" } else { "$maxPwdAge days" }
                passwordComplexity = if ($complexityEnabled) { "Enabled" } else { "Disabled" }
                reversibleEncryption = if ($reversibleEncryption) { "Enabled" } else { "Disabled" }
                lockoutThreshold = if ($lockoutThreshold -eq 0) { "Disabled" } else { "After $lockoutThreshold failed attempts" }
                lockoutDuration = if ($lockoutDuration -eq 0) { "Forever (manual unlock)" } else { "$lockoutDuration minutes" }
                lockoutObservationWindow = if ($lockoutWindow -gt 0) { "$lockoutWindow minutes" } else { "N/A" }
            }

            # Determine severity based on policy weaknesses
            # Finding: Short password (<8), no complexity, reversible encryption, no lockout
            # Hint: Moderate weakness (8-13 chars, high lockout threshold)
            # Secure: Good policy
            $policyWeaknesses = @()

            # Check for critical weaknesses (Finding)
            if ($minPwdLength -lt 8) { $policyWeaknesses += "short_password" }
            if (-not $complexityEnabled) { $policyWeaknesses += "no_complexity" }
            if ($reversibleEncryption) { $policyWeaknesses += "reversible_encryption" }

            # A threshold of 0 disables account lockout outright: an attacker may guess
            # without limit against every account in the domain, which is the precondition
            # that makes password spraying work. That is not a moderate weakness - it ranks
            # with a short minimum length, not below it.
            if ($lockoutThreshold -eq 0) { $policyWeaknesses += "no_lockout" }

            # Check for moderate weaknesses (Hint)
            $moderateWeaknesses = @()
            if ($minPwdLength -ge 8 -and $minPwdLength -lt 14) { $moderateWeaknesses += "moderate_password_length" }
            if ($lockoutThreshold -gt 10) { $moderateWeaknesses += "high_lockout_threshold" }
            if ($maxPwdAge -eq 0) { $moderateWeaknesses += "password_never_expires" }

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
            Show-Object $passwordPolicyObj

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
                            $appliesTo = if ($pso.'msDS-PSOAppliesTo') { $pso.'msDS-PSOAppliesTo' } else { @() }

                            # Create PSO object for consistent display
                            $psoObj = [PSCustomObject]@{
                                psoName = $psoName
                                precedence = $precedence
                                minPwdLength = if ($minLength -eq 0) { "Disabled" } else { "$minLength characters" }
                                passwordComplexity = if ($complexityEnabled) { "Enabled" } else { "Disabled" }
                                reversibleEncryption = if ($reversibleEncryption) { "Enabled" } else { "Disabled" }
                                lockoutThreshold = if ($lockoutThresholdPSO -eq 0) { "Disabled" } else { "After $lockoutThresholdPSO failed attempts" }
                                appliesTo = "$($appliesTo.Count) user(s)/group(s)"
                            }

                            $psoObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'FineGrainedPasswordPolicy' -Force
                            Show-Object $psoObj
                        }

                        # Output FGPP findings summary
                        $weakPSOCount = @($psos | Where-Object {
                            $psoRE = if ($_.'msDS-PasswordReversibleEncryptionEnabled') { $_.'msDS-PasswordReversibleEncryptionEnabled' -eq 'TRUE' } else { $false }
                            $psoMinLen = if ($_.'msDS-MinimumPasswordLength') { [int]$_.'msDS-MinimumPasswordLength' } else { 0 }
                            $psoComp = if ($_.'msDS-PasswordComplexityEnabled') { $_.'msDS-PasswordComplexityEnabled' -eq 'TRUE' } else { $false }
                            $psoLockout = if ($_.'msDS-LockoutThreshold') { [int]$_.'msDS-LockoutThreshold' } else { 0 }

                            $psoRE -or ($psoMinLen -lt 8) -or (-not $psoComp) -or ($psoLockout -eq 0)
                        }).Count

                        if ($weakPSOCount -gt 0) {
                            Show-Line "Found $weakPSOCount FGPP weakness(es)" -Class Finding
                        } else {
                            Show-Line "Fine-Grained Password Policies are properly configured" -Class Secure
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
