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
                            $blob = $comp.'msLAPS-EncryptedPassword'
                            if ($blob) {
                                # Parse metadata only (no decryption attempt) - very fast, <1ms
                                $lapsInfo = ConvertFrom-LAPSEncryptedPassword -Blob $blob
                                if ($lapsInfo -and $lapsInfo.TargetSID) {
                                    # Check if Target SID is in our token groups (local check)
                                    if ($myTokenGroups -contains $lapsInfo.TargetSID) {
                                        $authorizedCount++
                                        # Decrypt directly - no second LDAP query needed!
                                        $decryptedInfo = ConvertFrom-LAPSEncryptedPassword -Blob $blob -Decrypt
                                        if ($decryptedInfo -and $decryptedInfo.DecryptionSucceeded) {
                                            # Convert Raw byte[] attributes to proper types for Show-Object
                                            if ($comp.objectSid -is [byte[]]) {
                                                try {
                                                    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($comp.objectSid, 0)
                                                    $comp | Add-Member -NotePropertyName 'objectSid' -NotePropertyValue $sidObj.Value -Force
                                                } catch { }
                                            }
                                            if ($comp.objectGUID -is [byte[]]) {
                                                try {
                                                    $comp | Add-Member -NotePropertyName 'objectGUID' -NotePropertyValue ([System.Guid]$comp.objectGUID).ToString() -Force
                                                } catch { }
                                            }
                                            # Add decrypted LAPS properties to existing object
                                            $comp | Add-Member -NotePropertyName 'msLAPS-Password' -NotePropertyValue $decryptedInfo.Password -Force
                                            $comp | Add-Member -NotePropertyName 'msLAPS-Account' -NotePropertyValue $decryptedInfo.Account -Force
                                            $comp | Add-Member -NotePropertyName 'msLAPS-Updated' -NotePropertyValue $decryptedInfo.UpdateTimestamp -Force
                                            # Remove raw encrypted blob from output
                                            $comp.PSObject.Properties.Remove('msLAPS-EncryptedPassword')
                                            $readableComputers += $comp
                                        }
                                    }
                                }
                            }
                        }

                        Write-Log "[Get-LAPSCredentialAccess] User is authorized for $authorizedCount of $($encryptedComputers.Count) encrypted LAPS computers"
                    }
                } else {
                    Write-Log "[Get-LAPSCredentialAccess] Could not retrieve token groups - skipping encrypted LAPS optimization"
                    # Fallback: try sampling approach
                    $sampleComputers = @(Get-DomainComputer -LDAPFilter "(msLAPS-EncryptedPassword=*)" -ResultLimit 3 @PSBoundParameters)
                    if ($sampleComputers.Count -gt 0) {
                        $decryptableSample = $sampleComputers | Where-Object { $_.'msLAPS-Password' }
                        if ($decryptableSample) {
                            Write-Log "[Get-LAPSCredentialAccess] Fallback: Decryption works, loading all"
                            $allEncrypted = @(Get-DomainComputer -LDAPFilter "(msLAPS-EncryptedPassword=*)" @PSBoundParameters)
                            $decryptable = $allEncrypted | Where-Object { $_.'msLAPS-Password' }
                            $readableComputers += @($decryptable)
                        }
                    }
                }
            }

            # Output results
            if (@($readableComputers).Count -gt 0) {
                Show-Line "Found $(@($readableComputers).Count) computer(s) with readable LAPS password:" -Class "Finding"
                $totalComputers = @($readableComputers).Count
                $currentIndex = 0
                foreach ($computer in $readableComputers) {
                    $currentIndex++
                    if ($totalComputers -gt $Script:ProgressThreshold) { Show-Progress -Activity "Checking LAPS credential access" -Current $currentIndex -Total $totalComputers -ObjectName $computer.name }
                    $computer | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LAPSCredential' -Force
                    Show-Object $computer
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
        }
    }

    end {
        Write-Log "[Get-LAPSCredentialAccess] Check completed"
    }
}

