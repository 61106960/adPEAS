<#
.SYNOPSIS
    Recovers a VNC password from the form the VNC products store it in.

.DESCRIPTION
    RealVNC, TightVNC, TigerVNC and UltraVNC keep the VNC password - at most eight
    characters - DES-encrypted with one fixed key, the same in every installation and part
    of their published source code. It protects nothing: whoever reads the stored value has
    the password. The value is 8 bytes, written as 16 hex digits in a .vnc connection file,
    an .ini or a REG_SZ, and as REG_BINARY elsewhere. UltraVNC's ini appends a ninth byte;
    the password is the first eight.

    The key is the VNC key 17 52 6B 06 23 4E 58 07 with the bits of every byte reversed,
    which is how VNC's own DES code applies it - E8 4A D6 60 C4 72 1A E0 for a standard
    DES. Checked against two published values: 7E9B311248B7C8A8 is "Slay4U!!" and
    D7A514D8C556AADE is "Secure!".

.PARAMETER Hex
    The stored value as hex digits: 16, or 18 for UltraVNC.

.PARAMETER Bytes
    The stored value as bytes: 8, or more.

.OUTPUTS
    String - the password, or $null when the value is not one.

.NOTES
    Author: Alexander Sturz (@_61106960_)
    References:
    - https://github.com/peternewman/PasswordDecrypts
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
        $digits = $Hex -replace '[\s,]', ''
        if ($digits -notmatch '^([0-9A-Fa-f]{16}|[0-9A-Fa-f]{18})$') { return $null }
        $Bytes = New-Object byte[] ($digits.Length / 2)
        for ($i = 0; $i -lt $Bytes.Length; $i++) {
            $Bytes[$i] = [Convert]::ToByte($digits.Substring($i * 2, 2), 16)
        }
    }
    if ($null -eq $Bytes -or $Bytes.Length -lt 8) { return $null }

    $des = $null
    $plain = $null
    try {
        $des = New-Object System.Security.Cryptography.DESCryptoServiceProvider
        $des.Mode = [System.Security.Cryptography.CipherMode]::ECB
        $des.Padding = [System.Security.Cryptography.PaddingMode]::None
        $key = [byte[]](0xE8, 0x4A, 0xD6, 0x60, 0xC4, 0x72, 0x1A, 0xE0)
        $plain = $des.CreateDecryptor($key, $null).TransformFinalBlock($Bytes, 0, 8)
    } catch {
        # DESCryptoServiceProvider is not FIPS-validated and throws where FIPS mode is
        # enforced; the caller then reports the value as it is stored.
        Write-Log "[ConvertFrom-VNCPassword] Decryption failed: $_"
        return $null
    } finally {
        if ($des) { $des.Dispose() }
    }

    # Padded with zero bytes to eight. Latin-1, because VNC takes the password byte by byte.
    $length = 8
    while ($length -gt 0 -and $plain[$length - 1] -eq 0) { $length-- }
    return [System.Text.Encoding]::GetEncoding(28591).GetString($plain, 0, $length)
}

<#
.SYNOPSIS
    Whether a registry record is the stored password of a VNC product.

.DESCRIPTION
    The keys the VNC products keep their password under - RealVNC (vncserver, WinVNC4, and
    the policy key its templates write), TightVNC, TigerVNC, and the ORL key of the early
    WinVNC and UltraVNC - and the value names they use for it: Password, PasswordViewOnly,
    ControlPassword, passwd, passwd2. Get-CredentialExposure decrypts them, and
    Get-GPORegistrySettings counts them as judged there.

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
