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
            $unreadableCount = 0

            # Every object class, not only users and computers. description and info sit on
            # practically everything in the directory, and a password typed into a group's
            # description - "Zugang Fileserver, PW Sommer2024" - is the same credential as
            # one in a user's. Get-DomainUser prepends
            # (&(objectCategory=person)(objectClass=user)(!(objectClass=computer))), which is
            # what kept groups, organizational units, contacts, managed service accounts,
            # Group Policy objects and containers out of a check whose own secure line
            # claims the directory is clean. Get-UnixPasswordAccounts makes the same
            # argument in its own comment, one file over.
            #
            # And more than two attributes. These are the free-text fields a human types
            # into, which is where a password ends up.
            #
            # Two queries rather than one: description, info, comment and adminDescription
            # are in every schema, extensionAttribute1-15 are not - they arrive with the
            # Exchange schema extension, which most but not all domains have. A filter that
            # names an attribute the schema does not define does not skip that one clause,
            # the whole search fails with an undefined-attribute error, so the optional half
            # runs on its own and a failure there costs that half alone.
            $baseAttributes     = @('description', 'info', 'comment', 'adminDescription')
            $optionalAttributes = @(1..15 | ForEach-Object { "extensionAttribute$_" })

            # Merged by distinguishedName: an object can come back from both queries, and
            # reporting it twice would be two findings for one account.
            $candidates = @{}
            foreach ($set in @(
                @{ Attributes = $baseAttributes;     Optional = $false }
                @{ Attributes = $optionalAttributes; Optional = $true }
            )) {
                $presenceFilter = '(|' + ((@($set.Attributes) | ForEach-Object { "($_=*)" }) -join '') + ')'
                $wanted = @($set.Attributes) + @('objectCategory', 'sAMAccountName', 'name')

                $found = @()
                try {
                    $found = @(Get-DomainObject -LDAPFilter $presenceFilter -Properties $wanted @connectionParams)
                } catch {
                    if (-not $set.Optional) { throw }
                    Write-Log "[Get-PasswordInDescription] Optional attribute query failed, schema may not define extensionAttribute1-15: $_"
                }

                foreach ($obj in $found) {
                    $dn = [string]$obj.distinguishedName
                    if ([string]::IsNullOrWhiteSpace($dn)) { continue }
                    if (-not $candidates.ContainsKey($dn)) {
                        $candidates[$dn] = @{ Object = $obj; Attributes = @() }
                    }
                    foreach ($name in @($set.Attributes)) {
                        # Joined rather than cast: url and otherWebPages are multi-valued,
                        # and a cast would render an array as System.Object[].
                        $value = (@($obj.$name) | Where-Object { $_ }) -join ' '
                        if (-not [string]::IsNullOrWhiteSpace($value)) {
                            $candidates[$dn].Attributes += @{ Name = $name; Value = $value }
                        }
                    }
                }
            }

            $currentIndex = 0
            $totalCandidates = $candidates.Count

            foreach ($dn in @($candidates.Keys)) {
                    $candidate = $candidates[$dn].Object
                    $currentIndex++

                    # Progress indicator for large candidate counts
                    if ($totalCandidates -gt 50) {
                        Show-Progress -Activity "Checking free-text attributes" `
                                     -Current $currentIndex `
                                     -Total $totalCandidates
                    }
                    $accountName = $dn
                    $attributesToCheck = @($candidates[$dn].Attributes)

                    # What kind of object this is, out of objectCategory - which names the
                    # most specific class, and names it the way the schema does: a user
                    # object's category is Person. The four that a reader would otherwise
                    # have to translate are translated; anything else keeps the schema's
                    # own word, which is better than a wrong guess.
                    $objectType = 'object'
                    if ($candidate.objectCategory) {
                        $schemaClass = ((([string]$candidate.objectCategory) -split ',')[0] -replace '^CN=', '')
                        $objectType = $schemaClass
                        $kindLabels = @{
                            'Person'                              = 'User'
                            'Organizational-Unit'                 = 'OU'
                            'Group-Policy-Container'              = 'GPO'
                            'ms-DS-Group-Managed-Service-Account' = 'gMSA'
                        }
                        if ($kindLabels.ContainsKey($schemaClass)) { $objectType = $kindLabels[$schemaClass] }
                    }

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
                        # Phase 2: the full object, for the row itself. Get-DomainObject
                        # rather than the two typed wrappers, for the same reason as the
                        # query above - and it escapes the DN on the way in.
                        $fullObj = @(Get-DomainObject -Identity $accountName -ShowOwner @connectionParams)[0]

                        if ($fullObj) {
                            # Counted here rather than above. The counter used to be raised
                            # before this guard, and it is also what suppresses the clean
                            # line at the end - so a candidate that matched and could not be
                            # read again left a section with nothing in it at all: no row, no
                            # finding, and no statement that nothing was found either. In the
                            # HTML report that is an empty section, which reads as clean.
                            # An organizational unit has no sAMAccountName, and a Group
                            # Policy object's name is its GUID while displayName is the one
                            # a reader recognises.
                            $shownName = if ($fullObj.sAMAccountName) { $fullObj.sAMAccountName }
                                         elseif ($fullObj.displayName) { $fullObj.displayName }
                                         elseif ($fullObj.name) { $fullObj.name }
                                         else { $accountName }

                            $fullObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PasswordInDescription' -Force
                            $fullObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue "$objectType - $bestAttrName attribute" -Force
                            if ($bestTier -eq 1) {
                                Show-Line "Probable credential found in $bestAttrName of $objectType '$shownName'" -Class Finding
                            } else {
                                Show-Line "Possible credential mention in $bestAttrName of $objectType '$shownName'" -Class Hint
                            }
                            Show-Object $fullObj -Class $(if ($bestTier -eq 1) { 'Finding' } else { 'Hint' })
                            if ($bestTier -eq 1) { $findingCount++ } else { $hintCount++ }
                        } else {
                            # Named, because the reader can go and look: the object matched
                            # on a value this check read a moment earlier and then could not
                            # be read back - deleted in between, or moved out of reach.
                            $unreadableCount++
                            Write-Log "[Get-PasswordInDescription] Candidate could not be re-read: $accountName"
                            Show-Line "Matched but could not be read again: $accountName" -Class Note
                        }
                    }
            }

            if ($totalCandidates -gt 50) {
                Show-Progress -Activity "Checking free-text attributes" -Completed
            }

            if ($findingCount -eq 0 -and $hintCount -eq 0) {
                if ($unreadableCount -gt 0) {
                    # Not green: a candidate matched and could not be read back, so the
                    # directory was not cleared - it was not fully looked at.
                    Show-Line "Nothing could be reported - every match could not be read again" -Class Note
                } else {
                    Show-Line "No credentials found in the free-text attributes of any object" -Class Secure
                }
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
