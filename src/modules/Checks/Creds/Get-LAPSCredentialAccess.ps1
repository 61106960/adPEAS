function Resolve-LAPSEncryptedComputer {
    <#
    .SYNOPSIS
    Decrypts a computer's Windows LAPS blob onto the object, if this account may.

    .DESCRIPTION
    The only reliable test of whether an encrypted LAPS password is readable is whether
    NCryptUnprotectSecret opens the blob. On success the password, the account name and the
    update timestamp are added to the object and the blob is removed, so what goes to the
    report is the password rather than the envelope it came in - and the finding definitions
    see msLAPS-Password, which is what they describe.

    Both callers need the same conversions beforehand: a -Raw query answers every attribute
    as LDAP sends it, and the card showed them so. Only objectSid and objectGUID used to be
    converted here; a live scan's card then read "userAccountControl: 4096",
    "pwdLastSet: 133839533787743374". Every attribute but the blob now goes through
    ConvertFrom-LDAPAttribute, the conversion each object of a normal query gets.

    .PARAMETER Computer
    A computer object from a -Raw query, carrying msLAPS-EncryptedPassword.

    .OUTPUTS
    [bool] whether the password is now on the object.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Computer
    )

    if (-not $Computer) { return $false }
    $blob = $Computer.'msLAPS-EncryptedPassword'
    if (-not $blob) { return $false }

    $decryptedInfo = ConvertFrom-LAPSEncryptedPassword -Blob $blob -Decrypt
    if (-not $decryptedInfo -or -not $decryptedInfo.DecryptionSucceeded) { return $false }

    foreach ($property in @($Computer.PSObject.Properties)) {
        if ($property.Name -ieq 'msLAPS-EncryptedPassword') { continue }
        try {
            $converted = ConvertFrom-LDAPAttribute -Name $property.Name -Value $property.Value
        } catch {
            Write-Log "[Resolve-LAPSEncryptedComputer] Could not convert $($property.Name): $_"
            continue
        }
        $Computer.PSObject.Properties.Remove($property.Name)
        if (-not $converted) { continue }
        foreach ($convertedName in $converted.Keys) {
            $Computer | Add-Member -NotePropertyName $convertedName -NotePropertyValue $converted[$convertedName] -Force
        }
    }

    $Computer | Add-Member -NotePropertyName 'msLAPS-Password' -NotePropertyValue $decryptedInfo.Password -Force
    $Computer | Add-Member -NotePropertyName 'msLAPS-Account' -NotePropertyValue $decryptedInfo.Account -Force
    $Computer | Add-Member -NotePropertyName 'msLAPS-Updated' -NotePropertyValue $decryptedInfo.UpdateTimestamp -Force
    # The envelope has served its purpose, and leaving it on the object would have the row
    # claim both states at once.
    $Computer.PSObject.Properties.Remove('msLAPS-EncryptedPassword')

    return $true
}

function Get-LAPSCredentialAccess {
    <#
    .SYNOPSIS
    Tests if the current user account can read LAPS passwords.

    .DESCRIPTION
    Performs an actual read test on LAPS password attributes to determine if the current authenticated user has access to LAPS credentials.

    This check:
    - Attempts to read ms-Mcs-AdmPwd (Legacy LAPS) from computers
    - Attempts to read msLAPS-Password (Windows LAPS v2 plaintext) from computers
    - Attempts to read msLAPS-EncryptedPassword (Windows LAPS v2 encrypted) from computers
    - Parses encrypted LAPS metadata (timestamp, target SID)
    - Attempts decryption via NCryptUnprotectSecret if authorized
    - Reports which computers' passwords are accessible
    - Groups accessible credentials by OU

    Related Checks:
    - Get-LAPSConfiguration (Computer): Is LAPS deployed?
    - Get-LAPSPermissions (Rights): WHO has LAPS read rights per OU?

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-LAPSCredentialAccess

    .EXAMPLE
    Get-LAPSCredentialAccess -Domain "contoso.com" -Credential (Get-Credential)

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
        [System.Management.Automation.PSCredential]$Credential
    )

    begin {
        Write-Log "[Get-LAPSCredentialAccess] Starting check"
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            Show-SubHeader "Testing LAPS password read access for current user..." -ObjectType "LAPSCredential"

            # One definition of "does this domain run LAPS", shared with
            # Get-LAPSConfiguration and Get-LAPSPermissions and cached for the session.
            $lapsSchema = Get-LAPSSchemaPresence @PSBoundParameters
            $lapsLegacySchemaPresent = $lapsSchema.LegacyPresent
            $windowsLAPSSchemaPresent = $lapsSchema.NativePresent

            if (-not $lapsLegacySchemaPresent -and -not $windowsLAPSSchemaPresent) {
                Show-Line "No LAPS schema found" -Class "Note"
                return
            }

            $readableComputers = @()
            $withheldCount = 0

            # The presence filter is ACL-gated, so a returned object is normally a readable
            # one. Trust it only as far as the value that actually arrives: an object that
            # comes back without the attribute is not a readable password, and counting it
            # as one tells the operator they hold access they do not have. This check
            # reports Finding, the most severe verdict the tool has, so a false positive
            # here is expensive.
            $hasValue = {
                param($Object, $Attribute)
                -not [string]::IsNullOrWhiteSpace([string]$Object.$Attribute)
            }

            # Test Legacy LAPS - query for readable ms-Mcs-AdmPwd
            # ACL-based: attribute only returned if user has read permission
            if ($lapsLegacySchemaPresent) {
                Write-Log "[Get-LAPSCredentialAccess] Querying for readable Legacy LAPS passwords"
                $computersWithLegacy = @(Get-DomainComputer -LDAPFilter "(ms-Mcs-AdmPwd=*)" @PSBoundParameters)
                foreach ($comp in $computersWithLegacy) {
                    if (& $hasValue $comp 'ms-Mcs-AdmPwd') {
                        $readableComputers += $comp
                    } else {
                        $withheldCount++
                        Write-Log "[Get-LAPSCredentialAccess] Legacy LAPS attribute withheld for '$($comp.distinguishedName)'"
                    }
                }
            }

            # Test Windows LAPS plaintext - query for msLAPS-Password attribute in AD
            if ($windowsLAPSSchemaPresent) {
                Write-Log "[Get-LAPSCredentialAccess] Querying for readable Windows LAPS plaintext passwords"
                $computersWithPlaintext = @(Get-DomainComputer -LDAPFilter "(msLAPS-Password=*)" @PSBoundParameters)
                foreach ($comp in $computersWithPlaintext) {
                    if (& $hasValue $comp 'msLAPS-Password') {
                        $readableComputers += $comp
                    } else {
                        $withheldCount++
                        Write-Log "[Get-LAPSCredentialAccess] Windows LAPS attribute withheld for '$($comp.distinguishedName)'"
                    }
                }
            }

            # Test Windows LAPS encrypted - optimized approach:
            # 1. Get current user's token groups (once)
            # 2. Query all computers with ALL properties but -Raw (no decryption)
            # 3. Parse Target SID from each blob locally (<1ms)
            # 4. Check if Target SID is in our token groups (local check)
            # 5. For authorized: decrypt blob directly (no second LDAP query!)
            if ($windowsLAPSSchemaPresent) {
                Write-Log "[Get-LAPSCredentialAccess] Checking encrypted LAPS passwords (optimized)"

                # Step 1: Get current user's token groups (cached after first call)
                $myTokenGroups = Get-CurrentUserTokenGroups
                if ($myTokenGroups -and $myTokenGroups.Count -gt 0) {
                    Write-Log "[Get-LAPSCredentialAccess] Got $($myTokenGroups.Count) token groups for current user"

                    # Step 2: Query all computers with encrypted LAPS - ALL properties but Raw (no decryption)
                    # This way we have the full object and only need to decrypt the blob locally
                    $encryptedComputers = @(Get-DomainComputer -LDAPFilter "(msLAPS-EncryptedPassword=*)" -Raw @PSBoundParameters)

                    if (@($encryptedComputers).Count -gt 0) {
                        Write-Log "[Get-LAPSCredentialAccess] Found $($encryptedComputers.Count) computers with encrypted LAPS"

                        # Step 3, 4 & 5: Parse Target SID, check authorization, decrypt if authorized
                        $authorizedCount = 0
                        foreach ($comp in $encryptedComputers) {
                            $readable = $false
                            $blob = $comp.'msLAPS-EncryptedPassword'
                            if ($blob) {
                                # Parse metadata only (no decryption attempt) - very fast, <1ms
                                $lapsInfo = ConvertFrom-LAPSEncryptedPassword -Blob $blob
                                if ($lapsInfo -and $lapsInfo.TargetSID) {
                                    # Check if Target SID is in our token groups (local check)
                                    if ($myTokenGroups -contains $lapsInfo.TargetSID) {
                                        $authorizedCount++
                                        # Decrypt directly - no second LDAP query needed!
                                        $readable = Resolve-LAPSEncryptedComputer -Computer $comp
                                        if ($readable) { $readableComputers += $comp }
                                    }
                                }
                            }
                            # Every one of these computers has a LAPS password stored. The
                            # ones left over are the ones this account cannot open, and they
                            # were counted nowhere - so a domain on encrypted LAPS where
                            # nothing decrypts ended on "No readable LAPS passwords found",
                            # in green, with no mention that there were passwords at all.
                            if (-not $readable) {
                                $withheldCount++
                                Write-Log "[Get-LAPSCredentialAccess] Encrypted LAPS password not readable for '$($comp.distinguishedName)'"
                            }
                        }

                        Write-Log "[Get-LAPSCredentialAccess] User is authorized for $authorizedCount of $($encryptedComputers.Count) encrypted LAPS computers"
                    }
                } else {
                    # No token groups, so the authorization pre-check is unavailable. That
                    # check is an optimisation and never the test: what decides whether a
                    # blob is readable is whether NCryptUnprotectSecret opens it. Three of
                    # them decide whether the rest are worth the attempt.
                    #
                    # This branch used to sample without -Raw and then filter on
                    # msLAPS-Password - an attribute that cannot be there. Without -Raw,
                    # ConvertFrom-LDAPAttribute renders the blob as
                    # "[Encrypted - Updated: ...]" and produces no password property at all,
                    # so the sample was always empty, the load-everything branch behind it
                    # was dead, and nothing was counted as withheld either. On a domain
                    # using encrypted LAPS, a failed token-group lookup therefore ended the
                    # section with "No readable LAPS passwords found" in green.
                    Write-Log "[Get-LAPSCredentialAccess] No token groups - sampling decryption instead"
                    $encryptedComputers = @(Get-DomainComputer -LDAPFilter "(msLAPS-EncryptedPassword=*)" -Raw @PSBoundParameters)

                    $sampleDecrypts = $false
                    foreach ($comp in @($encryptedComputers | Select-Object -First 3)) {
                        $sampleInfo = ConvertFrom-LAPSEncryptedPassword -Blob $comp.'msLAPS-EncryptedPassword' -Decrypt
                        if ($sampleInfo -and $sampleInfo.DecryptionSucceeded) { $sampleDecrypts = $true; break }
                    }

                    if ($sampleDecrypts) {
                        Write-Log "[Get-LAPSCredentialAccess] Fallback: decryption works, trying all $(@($encryptedComputers).Count)"
                        foreach ($comp in $encryptedComputers) {
                            if (Resolve-LAPSEncryptedComputer -Computer $comp) {
                                $readableComputers += $comp
                            } else {
                                $withheldCount++
                            }
                        }
                    } else {
                        $withheldCount += @($encryptedComputers).Count
                    }
                }
            }

            # Whose read access this is.
            #
            # Every computer whose LAPS password the bound account can read used to be a
            # Finding at BaseScore 55, which is the wrong answer in both directions. An
            # audit run with an administrative account - the normal case - reads every
            # LAPS-managed machine in the domain, so a 2000-seat domain produced 2000 red
            # findings that say nothing, and buried the one machine a helpdesk account can
            # read. The neighbouring BitLocker check has exactly the same mechanism and says
            # so in its own definition: "Read access is often legitimate (recovery and
            # helpdesk roles) and is not by itself a vulnerability".
            #
            # So the verdict hangs on the principal rather than on the read succeeding.
            # Test-IsPrivileged is what Get-CredentialRoaming uses for the same distinction.
            $readerIsPrivileged = $false
            $readerName = $null
            if ($Script:LDAPContext.AuthenticatedUserSAM) { $readerName = [string]$Script:LDAPContext.AuthenticatedUserSAM }
            elseif ($Script:LDAPContext.AuthenticatedUserDN) { $readerName = [string]$Script:LDAPContext.AuthenticatedUserDN }
            if ($readerName) {
                try {
                    $readerIsPrivileged = ((Test-IsPrivileged -Identity $readerName).IsPrivileged -eq $true)
                } catch {
                    Write-Log "[Get-LAPSCredentialAccess] Privilege check failed for '$readerName': $_"
                }
            }

            # Output results
            if (@($readableComputers).Count -gt 0) {
                if ($readerIsPrivileged) {
                    # A hint, and the headline says why - not a finding to be explained away
                    # in the card after the reader has already counted it.
                    Show-Line "Found $(@($readableComputers).Count) computer(s) with readable LAPS password - expected for this account:" -Class "Hint"
                } else {
                    Show-Line "Found $(@($readableComputers).Count) computer(s) with readable LAPS password:" -Class "Finding"
                }
                $totalComputers = @($readableComputers).Count
                $currentIndex = 0
                foreach ($computer in $readableComputers) {
                    $currentIndex++
                    if ($totalComputers -gt $Script:ProgressThreshold) { Show-Progress -Activity "Checking LAPS credential access" -Current $currentIndex -Total $totalComputers -ObjectName $computer.name }
                    $computer | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LAPSCredential' -Force
                    if ($readerIsPrivileged) {
                        # On the object, because the card is what a reader opens next and
                        # the row has to say the same thing as the line above it.
                        $computer | Add-Member -NotePropertyName 'lapsReadContext' -NotePropertyValue (
                            "Expected - the account this scan runs as is privileged ($readerName)") -Force
                        Show-Object $computer -Class Hint
                    } else {
                        Show-Object $computer -Class Finding
                    }
                }
                if ($totalComputers -gt $Script:ProgressThreshold) { Show-Progress -Activity "Checking LAPS credential access" -Completed }
            } else {
                Show-Line "No readable LAPS passwords found" -Class "Secure"
            }

            # Say so rather than staying silent: these computers do have a LAPS password
            # stored, the directory just did not hand it over. That is a different fact
            # from "no LAPS in this domain" and it changes what the reader does next.
            if ($withheldCount -gt 0) {
                Show-Line "$withheldCount computer(s) have a LAPS password stored that this account may not read" -Class "Note"
            }

        } catch {
            Write-Log "[Get-LAPSCredentialAccess] Error: $_" -Level Error
            Show-Line "Error during check - LAPS password access could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-LAPSCredentialAccess] Check completed"
    }
}

