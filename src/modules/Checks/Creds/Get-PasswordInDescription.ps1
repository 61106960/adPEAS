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

            # Tier 1: High-confidence patterns (password assignment with value)
            # passw\S* covers: password, passwd, passwort, passord, passwuert, pasvorto (EN/DE/NO/LU/EO)
            $tier1Patterns = @(
                @{ Pattern = 'passw\S*\s*[=:]\s*["''][^"'']{3,}["'']'; Description = "Password-variant assignment (quoted)" }
                @{ Pattern = 'passw\S*\s*[=:]\s*(?!["''])\S{3,}'; Description = "Password-variant assignment (unquoted)" }
                @{ Pattern = 'pwd\s*[=:]\s*\S{3,}'; Description = "Pwd assignment" }
                @{ Pattern = 'pw\s*[=:]\s*\S{3,}'; Description = "PW assignment" }
                @{ Pattern = '\bpass\s*[=:]\s*\S{3,}'; Description = "Pass assignment" }
                @{ Pattern = 'kennwort\s*[=:]\s*\S{3,}'; Description = "Kennwort assignment (German)" }
                @{ Pattern = '\bparol[ae]?\s*[=:]\s*\S{3,}'; Description = "Parola/parole/parol assignment (RO/LV/IT)" }
            )

            # Tier 2: Lower-confidence patterns (generic credential mentions)
            $tier2Patterns = @(
                @{ Pattern = 'passw\S*'; Description = "Password-variant mention (EN/DE/NO/LU/EO)" }
                @{ Pattern = '\bparol[ae]?\b'; Description = "Parola/parole/parol mention (RO/LV/IT)" }
                @{ Pattern = '\bcred(ential)?s?\b'; Description = "Credential mention" }
                @{ Pattern = '\b(secret|token)\s*[=:]\s*\S{5,}'; Description = "Secret/token assignment" }
            )

            # Exclusion patterns (skip if line matches these - password policy text, help, etc.)
            # Conservative approach: better to show a false positive than to hide a real password
            # Only exact terms — no wildcards for foreign words we haven't verified in real AD data
            $exclusionPatterns = @(
                # Policy/guideline text (EN/DE/IT/RO)
                'passw\S*\s*(policy|policies|requirement|guideline|richtlinie|anforderung)',
                '\bparol[ae]?\s*(policy|politica|cerinta)',
                # Modal verbs: "password must/should..." (EN/DE/NO/IT/RO)
                'passw\S*\s+(must|should|cannot|shall|muss|soll|darf|kann|må|bør|deve|trebuie)\s+',
                # Technical terms: length, complexity, expiry (EN/DE/NO/IT)
                'passw\S*\s+(length|complexity|history|age|expir|wechsel|ablauf|historie|lengde|utløp|lunghezza|scadenza)',
                # Reset/change/recover (EN/IT/RO)
                'passw\S*\s+(reset|change|recover|forgot|reimpost|cambiar|schimb)',
                '\bparol[ae]?\s+(reset|change|reimpost|cambiar|schimbar)',
                # Relative: "minimum/maximum password"
                '(minimum|maximum)\s+passw\S*',
                # Imperative: "set/change/update your password" (EN)
                '(set|change|update|reset)\s+(your|the|a)\s+passw\S*',
                # Placeholders
                'passw\S*\s*:\s*\*+',
                'passw\S*\s*:\s*<[^>]+>',
                # Prompts
                'Enter\s+(your\s+)?passw\S*',
                'passw\S*\s+prompt'
            )

            $findingCount = 0
            $hintCount = 0

            # Process both Users and Computers
            foreach ($objectType in @('User', 'Computer')) {
                Write-Log "[Get-PasswordInDescription] Checking $objectType accounts..."

                # Phase 1: Lightweight query — only fetch description + info (DN is always included)
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

                    foreach ($attr in $attributesToCheck) {
                        $attrValue = [string]$attr.Value

                        # Check exclusion patterns first
                        $excluded = $false
                        foreach ($exPattern in $exclusionPatterns) {
                            if ($attrValue -match $exPattern) {
                                $excluded = $true
                                Write-Log "[Get-PasswordInDescription] Excluded $accountName ($($attr.Name)): matches exclusion '$exPattern'"
                                break
                            }
                        }
                        if ($excluded) { continue }

                        # Check Tier 1 patterns (Finding)
                        $isTier1 = $false
                        foreach ($t1 in $tier1Patterns) {
                            if ($attrValue -imatch $t1.Pattern) {
                                $isTier1 = $true
                                Write-Log "[Get-PasswordInDescription] TIER1 match on $accountName ($($attr.Name)): $($t1.Description)"
                                break
                            }
                        }

                        if ($isTier1) {
                            $findingCount++
                            # Phase 2: Re-fetch full object for Show-Object display
                            $fullObj = if ($objectType -eq 'User') {
                                @(Get-DomainUser -Identity $accountName -ShowOwner @connectionParams)[0]
                            } else {
                                @(Get-DomainComputer -Identity $accountName @connectionParams)[0]
                            }
                            if ($fullObj) {
                                $fullObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PasswordInDescription' -Force
                                $fullObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue "$objectType - $($attr.Name) attribute" -Force
                                Show-Line "Probable credential found in $($attr.Name) of $objectType '$($fullObj.sAMAccountName)'" -Class Finding
                                Show-Object $fullObj
                            }
                            break  # One match per object is enough
                        }

                        # Check Tier 2 patterns (Hint)
                        $isTier2 = $false
                        foreach ($t2 in $tier2Patterns) {
                            if ($attrValue -imatch $t2.Pattern) {
                                $isTier2 = $true
                                Write-Log "[Get-PasswordInDescription] TIER2 match on $accountName ($($attr.Name)): $($t2.Description)"
                                break
                            }
                        }

                        if ($isTier2) {
                            $hintCount++
                            # Phase 2: Re-fetch full object for Show-Object display
                            $fullObj = if ($objectType -eq 'User') {
                                @(Get-DomainUser -Identity $accountName -ShowOwner @connectionParams)[0]
                            } else {
                                @(Get-DomainComputer -Identity $accountName @connectionParams)[0]
                            }
                            if ($fullObj) {
                                $fullObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PasswordInDescription' -Force
                                $fullObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue "$objectType - $($attr.Name) attribute" -Force
                                Show-Line "Possible credential mention in $($attr.Name) of $objectType '$($fullObj.sAMAccountName)'" -Class Hint
                                Show-Object $fullObj
                            }
                            break  # One match per object is enough
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
