<#
.SYNOPSIS
    Recovers a VNC password from the form the VNC products store it in.

.DESCRIPTION
    RealVNC, TightVNC, TigerVNC and UltraVNC keep the VNC password DES-encrypted with one
    fixed key, the same in every installation and part of their published source code. It
    protects nothing: whoever reads the stored value has the password. The classic value is
    one DES block - 8 bytes, at most eight characters - written as 16 hex digits in a .vnc
    connection file, an .ini or a REG_SZ, and as REG_BINARY elsewhere. UltraVNC's ini
    appends a ninth byte; the password is the first eight.

    A longer password is stored as several such blocks, each encrypted on its own with the
    same key, with no IV and nothing carried from one block to the next - which is how
    RealVNC Enterprise has written passwords over eight characters since 4.5. Decrypting
    every block of a value whose length is a whole number of blocks therefore reads them
    all.

    What this form is not: RealVNC Server stores the password as a salted hash - PBKDF2,
    20000 rounds by default - since 6.11.0 wherever its own encryption is enabled, and that
    cannot be reversed at all. Its RSA/AES security types carry the password inside the
    encrypted channel, so the server no longer has to hold the password itself; the classic
    challenge is a DES operation keyed with the password, which is the reason the reversible
    form existed in the first place. A stored hash is bytes like any other, so the length
    alone does not tell the two apart. This function decrypts and then checks that the
    result can be a password at all, and reads nothing from a value that is not this form.
    Get-VNCPasswordForm says what such a value is instead.

    The key is the VNC key 17 52 6B 06 23 4E 58 07 with the bits of every byte reversed,
    which is how VNC's own DES code applies it - E8 4A D6 60 C4 72 1A E0 for a standard
    DES. Checked against two published values: 7E9B311248B7C8A8 is "Slay4U!!" and
    D7A514D8C556AADE is "Secure!".

.PARAMETER Hex
    The stored value as hex digits: 16 for one block, a multiple of 16 for more, 18 for
    UltraVNC.

.PARAMETER Bytes
    The stored value as bytes: 8 for one block, a multiple of 8 for more, 9 for UltraVNC.

.OUTPUTS
    String - the password, or $null when the value is not one.

.NOTES
    Author: Alexander Sturz (@_61106960_)
    References:
    - https://github.com/peternewman/PasswordDecrypts
    - https://github.com/trinitronx/vncpasswd.py - the multi-block form of a long password
    - https://help.realvnc.com/hc/en-us/articles/6661259023389 - the salted hash since 6.11
#>
function ConvertFrom-VNCPassword {
    [CmdletBinding(DefaultParameterSetName = 'Hex')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Hex')]
        [AllowEmptyString()]
        [string]$Hex,

        [Parameter(Mandatory = $true, ParameterSetName = 'Bytes')]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    if ($PSCmdlet.ParameterSetName -eq 'Hex') {
        $Bytes = ConvertFrom-VNCHex -Hex $Hex
    }
    if ($null -eq $Bytes -or $Bytes.Length -lt 8) { return $null }

    # How many bytes of the value are whole blocks. UltraVNC's ini appends a ninth byte to
    # the single block it writes; every other value is blocks and nothing else, one for the
    # classic password and more for a long RealVNC one. A length that is neither cannot be
    # this form - DES has nothing to decrypt a part of a block with.
    $blockBytes = 0
    if (($Bytes.Length % 8) -eq 0) {
        $blockBytes = $Bytes.Length
    } elseif ($Bytes.Length -eq 9) {
        $blockBytes = 8
    } else {
        return $null
    }

    $des = $null
    $plain = $null
    try {
        $des = New-Object System.Security.Cryptography.DESCryptoServiceProvider
        $des.Mode = [System.Security.Cryptography.CipherMode]::ECB
        $des.Padding = [System.Security.Cryptography.PaddingMode]::None
        $key = [byte[]](0xE8, 0x4A, 0xD6, 0x60, 0xC4, 0x72, 0x1A, 0xE0)
        # ECB with one key, which decrypts every block of the value independently - what
        # the products do for a value of more than one block.
        $plain = $des.CreateDecryptor($key, $null).TransformFinalBlock($Bytes, 0, $blockBytes)
    } catch {
        # DESCryptoServiceProvider is not FIPS-validated and throws where FIPS mode is
        # enforced; the caller then reports the value as it is stored.
        Write-Log "[ConvertFrom-VNCPassword] Decryption failed: $_"
        return $null
    } finally {
        if ($des) { $des.Dispose() }
    }

    # Padded with zero bytes to the block.
    $length = $plain.Length
    while ($length -gt 0 -and $plain[$length - 1] -eq 0) { $length-- }
    if ($length -eq 0) { return $null }

    # And the result has to be a password. Any whole number of blocks decrypts to
    # something, so the plaintext is what tells this form from the other values a VNC
    # password key can hold - a salted hash of a length that happens to be blocks
    # decrypts to noise. A VNC password is typed on a keyboard: no control byte, and no
    # zero byte before the padding.
    for ($i = 0; $i -lt $length; $i++) {
        $byte = $plain[$i]
        if ($byte -lt 0x20 -or $byte -eq 0x7F -or ($byte -ge 0x80 -and $byte -lt 0xA0)) {
            return $null
        }
    }

    # Latin-1, because VNC takes the password byte by byte.
    return [System.Text.Encoding]::GetEncoding(28591).GetString($plain, 0, $length)
}

<#
.SYNOPSIS
    The bytes a stored VNC value holds, read from its hex digits.

.DESCRIPTION
    The products write the value as hex digits, and a registry export separates them with
    commas. An odd digit count is not a byte string, and a character that is not a hex
    digit means the value is not hex at all - $null for both, because there are no bytes
    to work with.

.PARAMETER Hex
    The stored value as hex digits.

.OUTPUTS
    Byte array, or $null when the value is not hex digits.
#>
function ConvertFrom-VNCHex {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Hex
    )

    $digits = $Hex -replace '[\s,]', ''
    if ($digits -notmatch '^[0-9A-Fa-f]+$' -or ($digits.Length % 2) -ne 0) { return $null }

    $bytes = New-Object byte[] ($digits.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($digits.Substring($i * 2, 2), 16)
    }

    # The comma keeps the array one object: a byte array returned bare unrolls into the
    # pipeline, and the caller gets its bytes one at a time.
    return ,$bytes
}

<#
.SYNOPSIS
    What a stored VNC password value is, when the password cannot be read from it.

.DESCRIPTION
    ConvertFrom-VNCPassword reads nothing from a value that is not the reversible form.
    This says what was measured instead, in one line for the report: the length, and why
    it cannot be that form. What such a value usually is:

    - the salted hash RealVNC Server stores since 6.11.0 wherever its own encryption is
      enabled. It is not reversible, and it is not a credential either: the server checks
      the password against it, so holding the hash authenticates nobody. The value is
      still worth reporting - it names the hosts that run a VNC server with password
      authentication, and a policy deploys the same one to every machine in its scope.
    - a value some other product writes in an encoding of its own, or one an
      administrator put under a VNC key by hand.

    $null when nothing is stored at all - then there is nothing to report.

.PARAMETER Hex
    The stored value as hex digits.

.PARAMETER Bytes
    The stored value as bytes.

.OUTPUTS
    String - what the value is, short enough for a console row.
#>
function Get-VNCPasswordForm {
    [CmdletBinding(DefaultParameterSetName = 'Hex')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Hex')]
        [AllowEmptyString()]
        [string]$Hex,

        [Parameter(Mandatory = $true, ParameterSetName = 'Bytes')]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    if ($PSCmdlet.ParameterSetName -eq 'Hex') {
        $digits = $Hex -replace '[\s,]', ''
        if ($digits.Length -eq 0) { return $null }
        $Bytes = ConvertFrom-VNCHex -Hex $digits
        if ($null -eq $Bytes) { return "$($digits.Length) characters - not a hex byte string" }
    }

    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return $null }
    if ($Bytes.Length -lt 8) { return "$($Bytes.Length) bytes - shorter than one DES block" }
    if (($Bytes.Length % 8) -ne 0 -and $Bytes.Length -ne 9) {
        return "$($Bytes.Length) bytes - no whole DES block, not the reversible form"
    }

    # A length that is blocks still has to decrypt to noise before this says it does. The
    # callers ask only about a value no password came out of, so this never changes what
    # they report - it keeps the answer true for anyone who asks about any value.
    if ($null -ne (ConvertFrom-VNCPassword -Bytes $Bytes)) { return $null }

    return "$($Bytes.Length) bytes - decrypts to noise, not the reversible form"
}

<#
.SYNOPSIS
    Whether a registry record is the stored password of a VNC product.

.DESCRIPTION
    The keys the VNC products keep their password under - RealVNC (vncserver, WinVNC4, and
    the policy key its templates write), TightVNC, TigerVNC, and the ORL key of the early
    WinVNC and UltraVNC - and the value names they use for it: Password, PasswordViewOnly,
    ControlPassword, passwd, passwd2. Get-CredentialExposure decrypts them, or reports what
    the value is when it is not the reversible form, and Get-GPORegistrySettings counts
    them as judged there.

.PARAMETER Record
    A record from Parse-PRegRecords, Parse-RegistryXml or Parse-GptTmplRegistryValues.
#>
function Test-VNCPasswordRecord {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        $Record
    )

    $key = ([string]$Record.Key -replace '^\\+', '').TrimEnd('\')
    return ($key -match '(?i)(^|\\)(RealVNC|TightVNC|TigerVNC|ORL)(\\|$)' -and
        [string]$Record.ValueName -match '(?i)^(Password|PasswordViewOnly|ControlPassword|passwd|passwd2)$')
}
