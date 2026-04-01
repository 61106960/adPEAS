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

            # Check if LAPS schema info is available from Get-LAPSConfiguration
            $lapsLegacySchemaPresent = $false
            $windowsLAPSSchemaPresent = $false

            if ($Script:LAPSSchemaInfo) {
                $lapsLegacySchemaPresent = $Script:LAPSSchemaInfo.LegacyPresent
                $windowsLAPSSchemaPresent = $Script:LAPSSchemaInfo.NativePresent
            } else {
                # Detect schema ourselves using Invoke-LDAPSearch with Schema Partition
                $schemaDN = $Script:LDAPContext.SchemaNamingContext

                if ($schemaDN) {
                    try {
                        # Check for Legacy LAPS schema attribute (ms-Mcs-AdmPwdExpirationTime)
                        $legacySchemaFilter = "(&(objectClass=attributeSchema)(|(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)(cn=ms-Mcs-AdmPwdExpirationTime)))"
                        $legacySchemaResult = Invoke-LDAPSearch -Filter $legacySchemaFilter -SearchBase $schemaDN -Properties 'cn' -SizeLimit 1
                        if ($legacySchemaResult) { $lapsLegacySchemaPresent = $true }

                        # Check for Windows LAPS schema attribute (msLAPS-PasswordExpirationTime)
                        $nativeSchemaFilter = "(&(objectClass=attributeSchema)(|(lDAPDisplayName=msLAPS-PasswordExpirationTime)(cn=msLAPS-PasswordExpirationTime)))"
                        $nativeSchemaResult = Invoke-LDAPSearch -Filter $nativeSchemaFilter -SearchBase $schemaDN -Properties 'cn' -SizeLimit 1
                        if ($nativeSchemaResult) { $windowsLAPSSchemaPresent = $true }

                        Write-Log "[Get-LAPSCredentialAccess] Schema check: Legacy=$lapsLegacySchemaPresent, Native=$windowsLAPSSchemaPresent"
                    } catch {
                        Write-Log "[Get-LAPSCredentialAccess] Schema query error: $($_.Exception.Message)"
                    }
                }

                # Fallback: check if any computer has LAPS attributes (minimal query)
                if (-not $lapsLegacySchemaPresent -and -not $windowsLAPSSchemaPresent) {
                    # Only fetch distinguishedName - we just need to know if any object exists
                    $legacyCheck = Get-DomainComputer -LDAPFilter "(ms-Mcs-AdmPwdExpirationTime=*)" -Properties 'distinguishedName' -ResultLimit 1 @PSBoundParameters
                    if ($legacyCheck) { $lapsLegacySchemaPresent = $true }

                    $nativeCheck = Get-DomainComputer -LDAPFilter "(msLAPS-PasswordExpirationTime=*)" -Properties 'distinguishedName' -ResultLimit 1 @PSBoundParameters
                    if ($nativeCheck) { $windowsLAPSSchemaPresent = $true }
                }

                # Cache schema info for other LAPS modules
                $Script:LAPSSchemaInfo = @{
                    LegacyPresent = $lapsLegacySchemaPresent
                    NativePresent = $windowsLAPSSchemaPresent
                }
            }

            if (-not $lapsLegacySchemaPresent -and -not $windowsLAPSSchemaPresent) {
                Show-Line "No LAPS schema found" -Class "Note"
                return
            }

            $readableComputers = @()

            # Test Legacy LAPS - query for readable ms-Mcs-AdmPwd
            # ACL-based: attribute only returned if user has read permission
            if ($lapsLegacySchemaPresent) {
                Write-Log "[Get-LAPSCredentialAccess] Querying for readable Legacy LAPS passwords"
                $computersWithLegacy = @(Get-DomainComputer -LDAPFilter "(ms-Mcs-AdmPwd=*)" @PSBoundParameters)
                $readableComputers += $computersWithLegacy
            }

            # Test Windows LAPS plaintext - query for msLAPS-Password attribute in AD
            if ($windowsLAPSSchemaPresent) {
                Write-Log "[Get-LAPSCredentialAccess] Querying for readable Windows LAPS plaintext passwords"
                $computersWithPlaintext = @(Get-DomainComputer -LDAPFilter "(msLAPS-Password=*)" @PSBoundParameters)
                $readableComputers += $computersWithPlaintext
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

        } catch {
            Write-Log "[Get-LAPSCredentialAccess] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-LAPSCredentialAccess] Check completed"
    }
}

