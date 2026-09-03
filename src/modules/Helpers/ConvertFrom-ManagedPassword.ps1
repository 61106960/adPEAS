function ConvertFrom-ManagedPassword {
    <#
    .SYNOPSIS
    Parses the msDS-ManagedPassword attribute blob from a Group Managed Service Account (gMSA).

    .DESCRIPTION
    Decodes the MSDS-MANAGEDPASSWORD_BLOB structure returned by Active Directory when
    reading the msDS-ManagedPassword constructed attribute from a gMSA.

    The structure contains:
    - Current password (UTF-16LE null-terminated string, up to 256 random characters)
    - Previous password (optional, for password rollover)
    - Query password interval (when to re-query)
    - Unchanged password interval (password validity period)

    This function returns the passwords in multiple formats:
    - SecureString (for secure operations)
    - Plaintext (for display/export)
    - NT Hash (for authentication)

    Security Note:
    gMSA passwords are 256 random Unicode characters and cannot be typed manually.
    They are designed for programmatic use only.

    .PARAMETER Blob
    The raw byte array from the msDS-ManagedPassword attribute.

    .PARAMETER AsSecureString
    If specified, returns passwords as SecureString instead of plaintext.

    .EXAMPLE
    $gmsa = Get-DomainUser -GMSA -Identity "svc_gmsa$" -Properties msDS-ManagedPassword
    $password = ConvertFrom-ManagedPassword -Blob $gmsa.'msDS-ManagedPassword'
    $password.CurrentPassword

    .EXAMPLE
    # Get NT hash for authentication
    $gmsa = Get-DomainUser -GMSA -Identity "svc_gmsa$" -Properties msDS-ManagedPassword
    $password = ConvertFrom-ManagedPassword -Blob $gmsa.'msDS-ManagedPassword'
    $password.CurrentNTHash  # Returns hex string like "32ED87BDB5FDC5E9CBA88547376818D4"

    .NOTES
    References:
    - MS-ADTS 2.2.5.4: MSDS-MANAGEDPASSWORD_BLOB
    - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e

    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [byte[]]$Blob,

        [Parameter(Mandatory = $false)]
        [switch]$AsSecureString
    )

    begin {
        # Structure header size: Version(2) + Reserved(2) + Length(4) + CurrentPwdOffset(2) +
        #                        PreviousPwdOffset(2) + QueryPwdIntervalOffset(2) + UnchangedPwdIntervalOffset(2) = 16 bytes
        $HeaderSize = 16
    }

    process {
        try {
            # Validate input
            if ($null -eq $Blob) {
                Write-Log "[ConvertFrom-ManagedPassword] Blob is null"
                return $null
            }

            if ($Blob.Length -lt $HeaderSize) {
                Write-Log "[ConvertFrom-ManagedPassword] Blob too short (min $HeaderSize bytes required, got $($Blob.Length))"
                return $null
            }

            # Parse header using BinaryReader
            $stream = New-Object System.IO.MemoryStream($Blob, $false)
            $reader = New-Object System.IO.BinaryReader($stream)

            try {
                # Version (2 bytes): Must be 0x0001
                $version = $reader.ReadUInt16()
                if ($version -ne 1) {
                    Write-Log "[ConvertFrom-ManagedPassword] Unsupported version: $version (expected 1)"
                    return $null
                }

                # Reserved (2 bytes): Should be 0x0000, but we ignore it per spec
                [void]$reader.ReadUInt16()

                # Length (4 bytes): Total structure length in bytes
                $length = $reader.ReadInt32()
                if ($Blob.Length -lt $length) {
                    Write-Log "[ConvertFrom-ManagedPassword] Blob truncated: got $($Blob.Length) bytes, header says $length"
                    return $null
                }

                # CurrentPasswordOffset (2 bytes): Offset to current password
                $currentPasswordOffset = $reader.ReadUInt16()

                # PreviousPasswordOffset (2 bytes): Offset to previous password (0 if not present)
                $previousPasswordOffset = $reader.ReadUInt16()

                # QueryPasswordIntervalOffset (2 bytes): Offset to query interval
                $queryPasswordIntervalOffset = $reader.ReadUInt16()

                # UnchangedPasswordIntervalOffset (2 bytes): Offset to unchanged interval
                $unchangedPasswordIntervalOffset = $reader.ReadUInt16()

                Write-Log "[ConvertFrom-ManagedPassword] Parsed header - Version: $version, Length: $length, CurrentPwdOffset: $currentPasswordOffset, PrevPwdOffset: $previousPasswordOffset, QueryOffset: $queryPasswordIntervalOffset, UnchangedOffset: $unchangedPasswordIntervalOffset"

                # Validate offsets
                if ($currentPasswordOffset -lt $HeaderSize) {
                    Write-Log "[ConvertFrom-ManagedPassword] Invalid current password offset: $currentPasswordOffset (must be >= $HeaderSize)"
                    return $null
                }

                if ($queryPasswordIntervalOffset -lt $currentPasswordOffset) {
                    Write-Log "[ConvertFrom-ManagedPassword] Invalid offset order: QueryPasswordIntervalOffset ($queryPasswordIntervalOffset) < CurrentPasswordOffset ($currentPasswordOffset)"
                    return $null
                }

                # Validate we have enough bytes for the interval fields (8 bytes each)
                $minRequiredLength = $unchangedPasswordIntervalOffset + 8
                if ($Blob.Length -lt $minRequiredLength) {
                    Write-Log "[ConvertFrom-ManagedPassword] Blob too short for interval fields: need $minRequiredLength bytes, got $($Blob.Length)"
                    return $null
                }

                # Determine password boundaries
                $currentPasswordEnd = if ($previousPasswordOffset -gt 0 -and $previousPasswordOffset -gt $currentPasswordOffset) {
                    $previousPasswordOffset
                } else {
                    $queryPasswordIntervalOffset
                }

                # Validate password region
                if ($currentPasswordEnd -le $currentPasswordOffset) {
                    Write-Log "[ConvertFrom-ManagedPassword] Invalid password region: start=$currentPasswordOffset, end=$currentPasswordEnd"
                    return $null
                }

                # Read current password (null-terminated UTF-16LE string)
                $currentPasswordLength = $currentPasswordEnd - $currentPasswordOffset
                $currentPasswordBytes = New-Object byte[] $currentPasswordLength
                [Array]::Copy($Blob, $currentPasswordOffset, $currentPasswordBytes, 0, $currentPasswordLength)

                # The exact bytes are kept for the NT hash; the string is for display only
                # and cannot be turned back into these bytes when the password contains an
                # unpaired surrogate.
                $currentPasswordExactBytes = Get-NullTerminatedUnicodeBytes -Bytes $currentPasswordBytes
                $currentPassword = Read-NullTerminatedUnicodeString -Bytes $currentPasswordBytes

                if ([string]::IsNullOrEmpty($currentPassword)) {
                    Write-Log "[ConvertFrom-ManagedPassword] Warning: Current password is empty (this should not happen for gMSA)"
                }

                # Read previous password if present
                $previousPassword = $null
                $previousPasswordExactBytes = New-Object byte[] 0
                if ($previousPasswordOffset -gt 0 -and $previousPasswordOffset -gt $currentPasswordOffset -and $previousPasswordOffset -lt $queryPasswordIntervalOffset) {
                    $previousPasswordLength = $queryPasswordIntervalOffset - $previousPasswordOffset
                    $previousPasswordBytes = New-Object byte[] $previousPasswordLength
                    [Array]::Copy($Blob, $previousPasswordOffset, $previousPasswordBytes, 0, $previousPasswordLength)
                    $previousPasswordExactBytes = Get-NullTerminatedUnicodeBytes -Bytes $previousPasswordBytes
                    $previousPassword = Read-NullTerminatedUnicodeString -Bytes $previousPasswordBytes
                }

                # Read query password interval (8 bytes, 100-nanosecond intervals as unsigned)
                $queryIntervalBytes = New-Object byte[] 8
                [Array]::Copy($Blob, $queryPasswordIntervalOffset, $queryIntervalBytes, 0, 8)
                $queryIntervalTicks = [BitConverter]::ToInt64($queryIntervalBytes, 0)
                # Note: Spec says unsigned, but TimeSpan.FromTicks takes long. Very large values are unlikely in practice.
                $queryPasswordInterval = [TimeSpan]::FromTicks($queryIntervalTicks)

                # Read unchanged password interval (8 bytes, 100-nanosecond intervals)
                $unchangedIntervalBytes = New-Object byte[] 8
                [Array]::Copy($Blob, $unchangedPasswordIntervalOffset, $unchangedIntervalBytes, 0, 8)
                $unchangedIntervalTicks = [BitConverter]::ToInt64($unchangedIntervalBytes, 0)
                $unchangedPasswordInterval = [TimeSpan]::FromTicks($unchangedIntervalTicks)

                Write-Log "[ConvertFrom-ManagedPassword] Password length: $($currentPassword.Length) chars, QueryInterval: $($queryPasswordInterval.TotalHours) hours"

                # Calculate NT hashes over the raw password bytes.
                #
                # Two things were wrong here. The hash was taken from the decoded string,
                # which silently changes the bytes of any gMSA password containing an
                # unpaired surrogate - see Get-NullTerminatedUnicodeBytes for why that is
                # the normal case, not an edge one. And it called
                # "Get-NTHashFromPassword -Password", a second function of that name
                # defined further down this file. Kerberos-Crypto.ps1 defines the same
                # name with a -PlainPassword parameter and is concatenated after this file
                # in the build, so its definition won: the call failed to bind, the outer
                # catch swallowed the error, and ConvertFrom-ManagedPassword returned
                # $null. Every gMSA password extraction in the built artifact produced
                # nothing at all. The duplicate has been removed.
                $currentNTHash = $null
                $previousNTHash = $null

                if ($currentPasswordExactBytes.Length -gt 0) {
                    $hashBytes = Get-MD4Hash -Data $currentPasswordExactBytes
                    if ($hashBytes) {
                        $currentNTHash = ([BitConverter]::ToString($hashBytes) -replace '-', '')
                    }
                }

                if ($previousPasswordExactBytes.Length -gt 0) {
                    $hashBytes = Get-MD4Hash -Data $previousPasswordExactBytes
                    if ($hashBytes) {
                        $previousNTHash = ([BitConverter]::ToString($hashBytes) -replace '-', '')
                    }
                }

                # Build result object with all properties upfront
                if ($AsSecureString) {
                    # Convert to SecureString
                    $secureCurrentPassword = $null
                    $securePreviousPassword = $null

                    if (-not [string]::IsNullOrEmpty($currentPassword)) {
                        $secureCurrentPassword = New-Object System.Security.SecureString
                        foreach ($char in $currentPassword.ToCharArray()) {
                            $secureCurrentPassword.AppendChar($char)
                        }
                        $secureCurrentPassword.MakeReadOnly()
                    }

                    if (-not [string]::IsNullOrEmpty($previousPassword)) {
                        $securePreviousPassword = New-Object System.Security.SecureString
                        foreach ($char in $previousPassword.ToCharArray()) {
                            $securePreviousPassword.AppendChar($char)
                        }
                        $securePreviousPassword.MakeReadOnly()
                    }

                    return [PSCustomObject]@{
                        Version                   = $version
                        CurrentPassword           = $secureCurrentPassword
                        PreviousPassword          = $securePreviousPassword
                        CurrentNTHash             = $currentNTHash
                        PreviousNTHash            = $previousNTHash
                        QueryPasswordInterval     = $queryPasswordInterval
                        UnchangedPasswordInterval = $unchangedPasswordInterval
                    }
                } else {
                    return [PSCustomObject]@{
                        Version                   = $version
                        CurrentPassword           = $currentPassword
                        PreviousPassword          = $previousPassword
                        CurrentNTHash             = $currentNTHash
                        PreviousNTHash            = $previousNTHash
                        QueryPasswordInterval     = $queryPasswordInterval
                        UnchangedPasswordInterval = $unchangedPasswordInterval
                    }
                }

            } finally {
                if ($reader) { $reader.Dispose() }
                if ($stream) { $stream.Dispose() }
            }

        } catch {
            Write-Log "[ConvertFrom-ManagedPassword] Error parsing blob: $_"
            return $null
        }
    }
}


<#
.SYNOPSIS
Returns the bytes of a null-terminated UTF-16LE string, without the terminator.

.DESCRIPTION
Internal helper for ConvertFrom-ManagedPassword. The NT hash has to be computed over
these bytes rather than over the decoded string.

A gMSA password is 256 bytes of cryptographic randomness read as 128 UTF-16 code units,
so roughly one unit in 32 falls in the surrogate range D800-DFFF and almost none of them
form a valid pair. Decoding that to a .NET string replaces every unpaired surrogate with
U+FFFD, and encoding the string back produces different bytes - so an NT hash taken from
the round-tripped string is not the account's NT hash. With 128 units the chance of at
least one surrogate is about 98 percent, which makes this the normal case rather than an
edge one, and the hash is the value someone authenticates with.
#>
function Get-NullTerminatedUnicodeBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    $empty = New-Object byte[] 0
    if ($null -eq $Bytes -or $Bytes.Length -lt 2) { return ,$empty }

    $effectiveLength = $Bytes.Length
    if ($effectiveLength % 2 -ne 0) { $effectiveLength = $effectiveLength - 1 }
    if ($effectiveLength -lt 2) { return ,$empty }

    # Null terminator: two zero bytes on an even offset
    $nullIndex = -1
    for ($i = 0; $i -lt $effectiveLength; $i += 2) {
        if ($Bytes[$i] -eq 0 -and $Bytes[$i + 1] -eq 0) { $nullIndex = $i; break }
    }
    if ($nullIndex -eq -1) { $nullIndex = $effectiveLength }
    if ($nullIndex -eq 0) { return ,$empty }

    $result = New-Object byte[] $nullIndex
    [Array]::Copy($Bytes, 0, $result, 0, $nullIndex)
    return ,$result
}


function Read-NullTerminatedUnicodeString {
    <#
    .SYNOPSIS
    Reads a null-terminated UTF-16LE string from a byte array.
    Internal helper function for ConvertFrom-ManagedPassword.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    if ($null -eq $Bytes -or $Bytes.Length -lt 2) {
        return [string]::Empty
    }

    # Ensure even length for UTF-16LE
    $effectiveLength = $Bytes.Length
    if ($effectiveLength % 2 -ne 0) {
        $effectiveLength = $effectiveLength - 1
    }

    if ($effectiveLength -lt 2) {
        return [string]::Empty
    }

    # Find null terminator (two consecutive zero bytes at even offset)
    $nullIndex = -1
    for ($i = 0; $i -lt $effectiveLength; $i += 2) {
        if ($Bytes[$i] -eq 0 -and $Bytes[$i + 1] -eq 0) {
            $nullIndex = $i
            break
        }
    }

    if ($nullIndex -eq -1) {
        # No null terminator found, use entire effective length
        $nullIndex = $effectiveLength
    }

    if ($nullIndex -eq 0) {
        return [string]::Empty
    }

    # Decode UTF-16LE string (excluding null terminator)
    return [System.Text.Encoding]::Unicode.GetString($Bytes, 0, $nullIndex)
}
