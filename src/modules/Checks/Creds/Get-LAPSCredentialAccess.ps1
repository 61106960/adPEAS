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

    .PARAMETER DecryptionError
    Optional. Receives why the blob did not open - the reason ConvertFrom-LAPSEncryptedPassword
    gives - and $null when it opened or there was no blob to try.

    .OUTPUTS
    [bool] whether the password is now on the object.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Computer,

        [Parameter(Mandatory = $false)]
        [ref]$DecryptionError
    )

    if ($DecryptionError) { $DecryptionError.Value = $null }
    if (-not $Computer) { return $false }
    $blob = $Computer.'msLAPS-EncryptedPassword'
    if (-not $blob) { return $false }

    $decryptedInfo = ConvertFrom-LAPSEncryptedPassword -Blob $blob -Decrypt
    if (-not $decryptedInfo -or -not $decryptedInfo.DecryptionSucceeded) {
        if ($DecryptionError) {
            $DecryptionError.Value = if ($decryptedInfo -and $decryptedInfo.DecryptionError) { [string]$decryptedInfo.DecryptionError }
                                     elseif ($decryptedInfo) { 'decryption returned no password' }
                                     else { 'the blob could not be parsed' }
        }
        return $false
    }

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
    - Reports separately the computers whose decryptor group the bound account is in but
      whose blob Windows did not open, with Windows' error code
    - Decrypts only where the bound account's groups name the blob's decryptor. A blob can
      open without the bound account - from the Windows key cache, or with the logon's own
      credentials after an NTLM bind - so where its groups cannot be read the encrypted
      passwords are counted as not tested rather than decrypted
    - Does not decrypt on a host outside any domain: Windows requests the key only on a
      domain member, so these blobs are reported on a line of their own

    Related Checks:
    - Get-LAPSConfiguration (Computer): Is LAPS deployed?
    - Get-LAPSPermissions (Rights): WHO has LAPS read rights per OU?

    .PARAMETER Identity
    Restricts the test to these computers (name, sAMAccountName, DN, SID or GUID; wildcards
    as Get-DomainComputer takes them). Without it every computer in the domain is tested.
    A name that matches no computer is reported as such.

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

    .EXAMPLE
    Get-LAPSCredentialAccess -Identity "WS001", "SRV-FILE01"
    Tests two computers only, the same way the scan tests all of them.

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

        # Last, so the positions the other three had are unchanged.
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Identity
    )

    begin {
        Write-Log "[Get-LAPSCredentialAccess] Starting check"
    }

    process {
        try {
            # The connection parameters, and nothing else. -Identity is this check's own:
            # splatting @PSBoundParameters on would hand it to Ensure-LDAPConnection and
            # Get-LAPSSchemaPresence, which do not take it.
            $connectionParams = @{}
            foreach ($connectionKey in @('Domain', 'Server', 'Credential')) {
                if ($PSBoundParameters.ContainsKey($connectionKey)) {
                    $connectionParams[$connectionKey] = $PSBoundParameters[$connectionKey]
                }
            }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            Show-SubHeader "Testing LAPS password read access for current user..." -ObjectType "LAPSCredential"

            # One definition of "does this domain run LAPS", shared with
            # Get-LAPSConfiguration and Get-LAPSPermissions and cached for the session.
            $lapsSchema = Get-LAPSSchemaPresence @connectionParams
            $lapsLegacySchemaPresent = $lapsSchema.LegacyPresent
            $windowsLAPSSchemaPresent = $lapsSchema.NativePresent

            if (-not $lapsLegacySchemaPresent -and -not $windowsLAPSSchemaPresent) {
                Show-Line "No LAPS schema found" -Class "Note"
                return
            }

            $readableComputers = @()
            $withheldCount = 0
            # Computers whose blob names a group the bound account is in and still did not
            # open. Not withheld: the directory handed the password over to an account that
            # may open it, and what failed is the decryption on this machine.
            $decryptFailures = @()
            # Encrypted passwords the check could not test: the bound account's token groups
            # were unreadable, and without them nothing ties a blob to that account.
            $untestedEncryptedCount = 0
            # Blobs this account may open that were not tried: this host is in no domain, and
            # Windows requests the key only on a domain member.
            $offDomainCount = 0

            # -Identity narrows every query of this check to those computers; without it
            # each query runs once, domain-wide. One query per identity, ANDed with the
            # presence filter by Get-DomainObject, and a computer two identities match
            # (wildcards) is kept once. $identityHits records which identity found anything.
            # Assigned, not taken from an if-expression: its output goes through the
            # pipeline, which unrolls @($null) to a bare $null - and foreach over $null runs
            # no query at all.
            $identityScopes = @($null)
            if ($PSBoundParameters.ContainsKey('Identity')) { $identityScopes = @($Identity) }
            $identityHits = @{}
            $getLAPSComputers = {
                param([string]$Filter, [switch]$AsRaw)
                $seenDN = @{}
                foreach ($scope in $identityScopes) {
                    $query = @{ LDAPFilter = $Filter }
                    if ($scope) { $query['Identity'] = $scope }
                    if ($AsRaw) { $query['Raw'] = $true }
                    foreach ($found in @(Get-DomainComputer @query @connectionParams)) {
                        if ($scope) { $identityHits[$scope] = $true }
                        $foundDN = [string]$found.distinguishedName
                        if ($foundDN) {
                            if ($seenDN.ContainsKey($foundDN)) { continue }
                            $seenDN[$foundDN] = $true
                        }
                        $found
                    }
                }
            }
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
                $computersWithLegacy = @(& $getLAPSComputers -Filter '(ms-Mcs-AdmPwd=*)')
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
                $computersWithPlaintext = @(& $getLAPSComputers -Filter '(msLAPS-Password=*)')
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
                    $encryptedComputers = @(& $getLAPSComputers -Filter '(msLAPS-EncryptedPassword=*)' -AsRaw)

                    if (@($encryptedComputers).Count -gt 0) {
                        Write-Log "[Get-LAPSCredentialAccess] Found $($encryptedComputers.Count) computers with encrypted LAPS"

                        # On a host in a workgroup Windows asks no DC for the key, so a blob
                        # fails there whoever may open it - measured 2026-11-17: one blob and
                        # one authorized account, decrypted from a member of an unrelated
                        # domain, no connection at all from a workgroup host, decrypted from
                        # that host once it was joined. Each attempt also costs its time, for
                        # every computer this account may open. Asked once; $null (status
                        # unreadable) decrypts as before.
                        $hostIsDomainMember = Test-adPEASHostDomainMember

                        # Step 3, 4 & 5: Parse Target SID, check authorization, decrypt if authorized
                        $authorizedCount = 0
                        foreach ($comp in $encryptedComputers) {
                            $readable = $false
                            # This account may open the blob and it did not come out:
                            # decryption failed, or was not tried outside a domain.
                            $authorizedUnread = $false
                            $blob = $comp.'msLAPS-EncryptedPassword'
                            if ($blob) {
                                # Parse metadata only (no decryption attempt) - very fast, <1ms
                                $lapsInfo = ConvertFrom-LAPSEncryptedPassword -Blob $blob
                                if ($lapsInfo -and $lapsInfo.TargetSID) {
                                    # Check if Target SID is in our token groups (local check)
                                    if ($myTokenGroups -contains $lapsInfo.TargetSID) {
                                        $authorizedCount++
                                        if ($hostIsDomainMember -eq $false) {
                                            $authorizedUnread = $true
                                            $offDomainCount++
                                            Write-Log "[Get-LAPSCredentialAccess] Decryptor group held, not decrypted outside a domain: '$($comp.distinguishedName)'"
                                        } else {
                                            # Decrypt directly - no second LDAP query needed!
                                            $decryptionError = $null
                                            $readable = Resolve-LAPSEncryptedComputer -Computer $comp -DecryptionError ([ref]$decryptionError)
                                            if ($readable) {
                                                $readableComputers += $comp
                                            } else {
                                                # The token groups say this account may open
                                                # the blob; the decryption did not. A blob that
                                                # failed here was counted with the ones this
                                                # account may not read, so the line said "may
                                                # not read" to an account that may.
                                                $authorizedUnread = $true
                                                $decryptFailures += [PSCustomObject]@{
                                                    Computer = [string]$comp.distinguishedName
                                                    Reason   = $decryptionError
                                                }
                                                Write-Log "[Get-LAPSCredentialAccess] Decryptor group held, decryption failed for '$($comp.distinguishedName)': $decryptionError"
                                            }
                                        }
                                    }
                                }
                            }
                            # Every one of these computers has a LAPS password stored. The
                            # ones left over are the ones this account cannot open, and they
                            # were counted nowhere - so a domain on encrypted LAPS where
                            # nothing decrypts ended on "No readable LAPS passwords found",
                            # in green, with no mention that there were passwords at all.
                            if (-not $readable -and -not $authorizedUnread) {
                                $withheldCount++
                                Write-Log "[Get-LAPSCredentialAccess] Encrypted LAPS password not readable for '$($comp.distinguishedName)'"
                            }
                        }

                        Write-Log "[Get-LAPSCredentialAccess] User is authorized for $authorizedCount of $($encryptedComputers.Count) encrypted LAPS computers"
                    }
                } else {
                    # No token groups, so nothing says whether the bound account may open
                    # these blobs - and a decryption does not say it either. A blob can open
                    # without the bound account: measured 2026-11-16, a session bound as a
                    # standard user (simple bind) decrypted a blob protected for a group that
                    # user is not in. The key came from the Windows user's own key cache,
                    # without asking a DC (measured 2026-11-17). Windows requests a key with
                    # the logon session's credentials - the adPEAS ticket after a Kerberos
                    # bind, the logon's own after an NTLM bind.
                    #
                    # This branch used to decrypt anyway, on the premise that the decryption
                    # is "the only test there is", and reported every blob that opened as a
                    # password the bound account can read - a Finding for an account that may
                    # read nothing. The blobs are counted as not tested instead.
                    Write-Log "[Get-LAPSCredentialAccess] No token groups - encrypted LAPS passwords not tested"
                    $untestedEncryptedCount += @(& $getLAPSComputers -Filter '(msLAPS-EncryptedPassword=*)').Count
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

            # A name that matched nothing in any query is either no computer at all or a
            # computer with no LAPS password this account can see. Only the first deserves
            # a line of its own; the second is what the lines below already say.
            $missingIdentities = @()
            if ($PSBoundParameters.ContainsKey('Identity')) {
                foreach ($scope in $identityScopes) {
                    if ($identityHits.ContainsKey($scope)) { continue }
                    $existing = @(Get-DomainComputer -Identity $scope -Properties 'distinguishedName' @connectionParams)
                    if ($existing.Count -eq 0) { $missingIdentities += $scope }
                }
            }
            foreach ($missing in $missingIdentities) {
                Show-Line "No computer found for '$missing'" -Class "Note"
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
            } elseif (@($decryptFailures).Count -gt 0) {
                # Not "no readable passwords": this account may read them, and only the
                # decryption on this machine failed. The lines below say what was tested.
                Write-Log "[Get-LAPSCredentialAccess] Nothing decrypted, $(@($decryptFailures).Count) failure(s) with the decryptor group held"
            } elseif ($offDomainCount -gt 0) {
                # As above: passwords this account may open, not tried on this host.
                Write-Log "[Get-LAPSCredentialAccess] Nothing decrypted, $offDomainCount blob(s) with the decryptor group held, host in no domain"
            } elseif (@($missingIdentities).Count -gt 0 -and @($missingIdentities).Count -eq @($identityScopes).Count) {
                # None of the names is a computer, so nothing was tested at all.
                Write-Log "[Get-LAPSCredentialAccess] No given identity matches a computer"
            } elseif ($untestedEncryptedCount -gt 0) {
                # Encrypted passwords exist and were not tested, so the section cannot be
                # clean; the line below says why.
                Write-Log "[Get-LAPSCredentialAccess] Nothing readable, $untestedEncryptedCount encrypted password(s) not tested"
            } else {
                Show-Line "No readable LAPS passwords found" -Class "Secure"
            }

            # Say so rather than staying silent: these computers do have a LAPS password
            # stored, the directory just did not hand it over. That is a different fact
            # from "no LAPS in this domain" and it changes what the reader does next.
            if ($withheldCount -gt 0) {
                Show-Line "$withheldCount computer(s) have a LAPS password stored that this account may not read" -Class "Note"
            }

            if ($untestedEncryptedCount -gt 0) {
                Show-Line "$untestedEncryptedCount computer(s) have an encrypted LAPS password that was not tested - this account's groups could not be read" -Class "Note"
            }

            # The bound account is in the group the blob names, so the directory's answer is
            # "readable"; Windows did not open it. The reason is Windows' own code and
            # nothing more - no cause is guessed. The bound account is none: the token
            # groups already say it may open the blob.
            if (@($decryptFailures).Count -gt 0) {
                Show-Line "$(@($decryptFailures).Count) computer(s) name a decryptor group this account is in, but Windows did not decrypt them" -Class "Note"
                foreach ($reasonGroup in @($decryptFailures | Group-Object -Property Reason)) {
                    $reasonText = if ($reasonGroup.Name) { $reasonGroup.Name } else { 'no reason given' }
                    Show-KeyValue "Decryption error" "$reasonText - $($reasonGroup.Count) computer(s)"
                }
            }

            # A cause of a failed decryption that is measured, so it is named - in a row of
            # its own, the way the error codes above are. The line says what happened, the
            # row why, and neither runs past a terminal. Run from a domain member;
            # membership of the scanned domain is not needed, and with a Kerberos session
            # Windows requests the key with its ticket.
            if ($offDomainCount -gt 0) {
                Show-Line "$offDomainCount computer(s) name a decryptor group this account is in, not tried on this host" -Class "Note"
                Show-KeyValue "Not tried" "This host is not domain-joined - Windows requests the key only on a domain member"
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

