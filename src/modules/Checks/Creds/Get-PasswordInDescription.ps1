function Get-PasswordInDescription {
    <#
    .SYNOPSIS
    Detects user and computer accounts with potential passwords in description or info attributes.

    .DESCRIPTION
    Scans the 'description' and 'info' attributes of user and computer accounts for patterns that indicate credentials are stored in plaintext.
    Uses a two-tier detection system:

    Tier 1 (Finding): High-confidence patterns with explicit password assignments (e.g., "password=Secret123")
    Tier 2 (Hint): Lower-confidence patterns with generic credential mentions (e.g., "password" without value)

    Exclusion patterns filter out false positives from password policy text, help text, and placeholders.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-PasswordInDescription

    .EXAMPLE
    Get-PasswordInDescription -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Creds
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
        [switch]$OPSEC
    )

    begin {
        Write-Log "[Get-PasswordInDescription] Starting check"
    }

    process {
        try {
            # Build connection parameters (exclude OPSEC which Ensure-LDAPConnection doesn't accept)
            $connectionParams = @{}
            if ($Domain) { $connectionParams['Domain'] = $Domain }
            if ($Server) { $connectionParams['Server'] = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            Show-SubHeader "Searching for credentials in description/info attributes..." -ObjectType "PasswordInDescription"

            # OPSEC mode: Skip heavy-load enumeration
            if ($OPSEC) {
                Show-Line "OPSEC mode: Skipping password-in-description check (would check all users and computers)" -Class "Hint"
                return
            }

            # One token for every language variant of the word, used by all three pattern
            # lists below so they cannot drift apart. It replaces a bare 'passw\S*', which
            # was documented as covering Norwegian "passord" and Esperanto "pasvorto" but
            # cannot: neither word contains "passw". Two consequences, both silent - a
            # Norwegian description holding a real password was never matched, and the
            # Norwegian exclusion terms further down (lengde, utloep, maa, boer) could
            # never fire either, because they were anchored to the same impossible prefix.
            #   sw\S*   password, passwd, passwort, passwuert   (EN/DE/LU)
            #   sord    passord                                 (NO)
            #   vorto   pasvorto                                (EO)
            $pwToken = 'pas(?:sw\S*|sord|vorto)'

            # Tier 1: High-confidence patterns (password assignment with value)
            $tier1Patterns = @(
                @{ Pattern = $pwToken + '\s*[=:]\s*["''][^"'']{3,}["'']'; Description = "Password-variant assignment (quoted)" }
                @{ Pattern = $pwToken + '\s*[=:]\s*(?!["''])\S{3,}'; Description = "Password-variant assignment (unquoted)" }
                @{ Pattern = 'pwd\s*[=:]\s*\S{3,}'; Description = "Pwd assignment" }
                @{ Pattern = 'pw\s*[=:]\s*\S{3,}'; Description = "PW assignment" }
                @{ Pattern = '\bpass\s*[=:]\s*\S{3,}'; Description = "Pass assignment" }
                @{ Pattern = 'kennwort\s*[=:]\s*\S{3,}'; Description = "Kennwort assignment (German)" }
                @{ Pattern = '\bparol[ae]?\s*[=:]\s*\S{3,}'; Description = "Parola/parole/parol assignment (RO/LV/IT)" }
            )

            # Tier 2: Lower-confidence patterns (generic credential mentions)
            $tier2Patterns = @(
                @{ Pattern = $pwToken; Description = "Password-variant mention (EN/DE/NO/LU/EO)" }
                @{ Pattern = '\bparol[ae]?\b'; Description = "Parola/parole/parol mention (RO/LV/IT)" }
                @{ Pattern = '\bcred(ential)?s?\b'; Description = "Credential mention" }
                @{ Pattern = '\b(secret|token)\s*[=:]\s*\S{5,}'; Description = "Secret/token assignment" }
            )

            # Exclusion patterns (skip if line matches these - password policy text, help, etc.)
            # Conservative approach: better to show a false positive than to hide a real password
            # Only exact terms - no wildcards for foreign words we haven't verified in real AD data
            $exclusionPatterns = @(
                # Policy/guideline text (EN/DE/IT/RO)
                # Every concatenation is parenthesized on purpose: in PowerShell the comma
                # binds tighter than +, so "$pwToken + 'a', $pwToken + 'b'" parses as
                # "$pwToken + @('a', ...)" and collapses the whole list into one glued
                # string. The exclusions then match nothing at all.
                ($pwToken + '\s*(policy|policies|requirement|guideline|richtlinie|anforderung)'),
                '\bparol[ae]?\s*(policy|politica|cerinta)',
                # Modal verbs: "password must/should..." (EN/DE/NO/IT/RO)
                # Norwegian letters are written as regex \u escapes to keep this file pure ASCII:
                # \u00E5 = a with ring, \u00F8 = o with stroke
                ($pwToken + '\s+(must|should|cannot|shall|muss|soll|darf|kann|m\u00E5|b\u00F8r|deve|trebuie)\s+'),
                # Technical terms: length, complexity, expiry (EN/DE/NO/IT)
                ($pwToken + '\s+(length|complexity|history|age|expir|wechsel|ablauf|historie|lengde|utl\u00F8p|lunghezza|scadenza)'),
                # Reset/change/recover (EN/IT/RO)
                ($pwToken + '\s+(reset|change|recover|forgot|reimpost|cambiar|schimb)'),
                '\bparol[ae]?\s+(reset|change|reimpost|cambiar|schimbar)',
                # Relative: "minimum/maximum password"
                ('(minimum|maximum)\s+' + $pwToken),
                # Imperative: "set/change/update your password" (EN)
                ('(set|change|update|reset)\s+(your|the|a)\s+' + $pwToken),
                # Prompts
                ('Enter\s+(your\s+)?' + $pwToken),
                ($pwToken + '\s+prompt')
            )

            # A second, much narrower list, and the only one that may overrule a tier 1 hit.
            #
            # The two kinds of exclusion above and below are not the same thing. The ones
            # above describe the *sentence* - it reads like policy or help text - and that
            # is a reason to distrust a bare mention, never a reason to ignore an
            # assignment standing next to it. The ones here describe the *value*: the
            # syntax is an assignment, but what was assigned is a row of asterisks or an
            # angle-bracket placeholder, so there is no credential to find whatever the
            # pattern says.
            $placeholderPatterns = @(
                ($pwToken + '\s*[=:]\s*\*+\s*$'),
                ($pwToken + '\s*[=:]\s*<[^>]+>'),
                'pwd\s*[=:]\s*\*+\s*$',
                'pwd\s*[=:]\s*<[^>]+>',
                '\bpass\s*[=:]\s*\*+\s*$',
                '\bpass\s*[=:]\s*<[^>]+>',
                'kennwort\s*[=:]\s*\*+\s*$',
                'kennwort\s*[=:]\s*<[^>]+>'
            )

            $findingCount = 0
            $hintCount = 0

            # Process both Users and Computers
            foreach ($objectType in @('User', 'Computer')) {
                Write-Log "[Get-PasswordInDescription] Checking $objectType accounts..."

                # Phase 1: Lightweight query - only fetch description + info (DN is always included)
                # This avoids loading ALL properties for potentially thousands of objects
                $candidates = if ($objectType -eq 'User') {
                    Get-DomainUser -LDAPFilter "(|(description=*)(info=*))" -Properties "description","info" @connectionParams
                } else {
                    Get-DomainComputer -LDAPFilter "(|(description=*)(info=*))" -Properties "description","info" @connectionParams
                }

                if (-not $candidates) { continue }

                $currentIndex = 0
                $totalCandidates = @($candidates).Count

                foreach ($candidate in @($candidates)) {
                    $currentIndex++

                    # Progress indicator for large candidate counts
                    if ($totalCandidates -gt 50) {
                        Show-Progress -Activity "Checking $objectType descriptions" `
                                     -Current $currentIndex `
                                     -Total $totalCandidates
                    }
                    $accountName = $candidate.distinguishedName
                    $attributesToCheck = @()

                    if ($candidate.description) { $attributesToCheck += @{ Name = 'description'; Value = $candidate.description } }
                    if ($candidate.info) { $attributesToCheck += @{ Name = 'info'; Value = $candidate.info } }

                    # Look at every attribute before reporting, and keep the strongest hit.
                    # Reporting on the first hit meant description was allowed to decide the
                    # severity for the whole account: a bare mention there ("password reset
                    # by helpdesk") broke the loop as a Hint, and an actual assignment in
                    # info was never examined. The account was filed one tier too low and
                    # the credential the check exists to find went unreported.
                    $bestTier = 0
                    $bestAttrName = $null

                    foreach ($attr in $attributesToCheck) {
                        $attrValue = [string]$attr.Value

                        # A masked or bracketed value is not a credential however much the
                        # syntax around it looks like an assignment, so this one clause is
                        # allowed to silence the attribute outright.
                        $isPlaceholder = $false
                        foreach ($phPattern in $placeholderPatterns) {
                            if ($attrValue -imatch $phPattern) {
                                $isPlaceholder = $true
                                Write-Log "[Get-PasswordInDescription] Placeholder value on $accountName ($($attr.Name)): '$phPattern'"
                                break
                            }
                        }
                        if ($isPlaceholder) { continue }

                        # Tier 1 is decided before the prose exclusions are consulted.
                        #
                        # The exclusions used to run first and skipped the whole attribute
                        # on a hit, which is the opposite of what this check is for. Policy
                        # wording and a real credential live in the same description all the
                        # time - "Passwort muss geaendert werden. Passwort = Winter2024!",
                        # "Password complexity required; password: Herbst2024" - and every
                        # one of those was dropped without a word, because the modal verb or
                        # the word "complexity" matched an exclusion. Three of five
                        # realistic strings carrying an actual assignment were lost that way.
                        #
                        # An exclusion says "this reads like policy text", which is a reason
                        # to distrust a bare mention, never a reason to ignore an assignment
                        # with a value next to it. So it only downgrades tier 2 now.
                        $isTier1 = $false
                        foreach ($t1 in $tier1Patterns) {
                            if ($attrValue -imatch $t1.Pattern) {
                                $isTier1 = $true
                                Write-Log "[Get-PasswordInDescription] TIER1 match on $accountName ($($attr.Name)): $($t1.Description)"
                                break
                            }
                        }

                        if ($isTier1) {
                            # Nothing outranks a tier 1 hit, so stop looking.
                            $bestTier = 1
                            $bestAttrName = $attr.Name
                            break
                        }

                        # No assignment here, so policy wording is what it looks like.
                        $excluded = $false
                        foreach ($exPattern in $exclusionPatterns) {
                            if ($attrValue -match $exPattern) {
                                $excluded = $true
                                Write-Log "[Get-PasswordInDescription] Excluded $accountName ($($attr.Name)): matches exclusion '$exPattern'"
                                break
                            }
                        }
                        if ($excluded) { continue }

                        # Check Tier 2 patterns (Hint)
                        $isTier2 = $false
                        foreach ($t2 in $tier2Patterns) {
                            if ($attrValue -imatch $t2.Pattern) {
                                $isTier2 = $true
                                Write-Log "[Get-PasswordInDescription] TIER2 match on $accountName ($($attr.Name)): $($t2.Description)"
                                break
                            }
                        }

                        # Remember the first tier 2 hit, but keep reading: a later attribute
                        # may still hold an assignment.
                        if ($isTier2 -and $bestTier -eq 0) {
                            $bestTier = 2
                            $bestAttrName = $attr.Name
                        }
                    }

                    if ($bestTier -gt 0) {
                        # Phase 2: Re-fetch full object for Show-Object display
                        $fullObj = if ($objectType -eq 'User') {
                            @(Get-DomainUser -Identity $accountName -ShowOwner @connectionParams)[0]
                        } else {
                            @(Get-DomainComputer -Identity $accountName @connectionParams)[0]
                        }

                        if ($bestTier -eq 1) { $findingCount++ } else { $hintCount++ }

                        if ($fullObj) {
                            $fullObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PasswordInDescription' -Force
                            $fullObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue "$objectType - $bestAttrName attribute" -Force
                            if ($bestTier -eq 1) {
                                Show-Line "Probable credential found in $bestAttrName of $objectType '$($fullObj.sAMAccountName)'" -Class Finding
                            } else {
                                Show-Line "Possible credential mention in $bestAttrName of $objectType '$($fullObj.sAMAccountName)'" -Class Hint
                            }
                            Show-Object $fullObj
                        }
                    }
                }

                # Clear progress bar for this object type
                if ($totalCandidates -gt 50) {
                    Show-Progress -Activity "Checking $objectType descriptions" -Completed
                }
            }

            if ($findingCount -eq 0 -and $hintCount -eq 0) {
                Show-Line "No credentials found in description or info attributes" -Class Secure
            } else {
                Write-Log "[Get-PasswordInDescription] Total: $findingCount finding(s), $hintCount hint(s)"
            }

        } catch {
            Write-Log "[Get-PasswordInDescription] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-PasswordInDescription] Check completed"
    }
}
