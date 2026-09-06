# Flag names as ConvertFrom-LDAPAttribute writes them (MS-ADTS 2.2.16), and the bit each
# one stands for. One table, so the decoding and the re-encoding cannot drift apart.
$Script:UACNameToBit = @{
    'SCRIPT' = 1; 'ACCOUNTDISABLE' = 2; 'HOMEDIR_REQUIRED' = 8; 'LOCKOUT' = 16
    'PASSWD_NOTREQD' = 32; 'PASSWD_CANT_CHANGE' = 64
    'ENCRYPTED_TEXT_PWD_ALLOWED' = 128; 'TEMP_DUPLICATE_ACCOUNT' = 256
    'NORMAL_ACCOUNT' = 512; 'INTERDOMAIN_TRUST_ACCOUNT' = 2048
    'WORKSTATION_TRUST_ACCOUNT' = 4096; 'SERVER_TRUST_ACCOUNT' = 8192
    'DONT_EXPIRE_PASSWORD' = 65536; 'MNS_LOGON_ACCOUNT' = 131072
    'SMARTCARD_REQUIRED' = 262144; 'TRUSTED_FOR_DELEGATION' = 524288
    'NOT_DELEGATED' = 1048576; 'USE_DES_KEY_ONLY' = 2097152
    'DONT_REQ_PREAUTH' = 4194304; 'PASSWORD_EXPIRED' = 8388608
    'TRUSTED_TO_AUTH_FOR_DELEGATION' = 16777216
    'NO_AUTH_DATA_REQUIRED' = 33554432; 'PARTIAL_SECRETS_ACCOUNT' = 67108864
}

function ConvertTo-UACValue {
    <#
    .SYNOPSIS
    Turns whatever shape a userAccountControl arrived in back into its numeric mask.

    .DESCRIPTION
    Two shapes reach the rest of adPEAS and both have to work.

    The raw integer, the way the attribute sits in the directory. And the decoded flag
    names - @('NORMAL_ACCOUNT', 'ACCOUNTDISABLE', ...) - which is what every object that
    came through Invoke-LDAPSearch carries, because ConvertFrom-LDAPAttribute replaces the
    number with them before any caller sees it.

    Code that read the attribute numerically therefore worked on hand-built objects and
    failed on real ones. Two ways, both silent:

    - '[int]$object.userAccountControl' throws on the decoded array, and the throw was
      caught by an enclosing handler and reported as the operation failing for some other
      reason.
    - A parse that fell back to zero turned a disabled account into an enabled one, which
      is the answer no caller checks.

    .PARAMETER Value
    The attribute as read: an integer, a numeric string, an array of flag names, or any
    mixture. $null and unknown names contribute nothing rather than voiding the whole mask.

    .PARAMETER Default
    What to return when nothing usable was found - typically 512 (NORMAL_ACCOUNT) for a
    user and 4096 (WORKSTATION_TRUST_ACCOUNT) for a computer. Defaults to 0, which reads
    as "no flags set" and is the safe answer for a caller that only tests bits.

    .OUTPUTS
    Int32.

    .EXAMPLE
    ConvertTo-UACValue -Value @('NORMAL_ACCOUNT', 'ACCOUNTDISABLE')
    514

    .EXAMPLE
    ConvertTo-UACValue -Value $user.userAccountControl -Default 512
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory=$false, Position=0)]
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory=$false)]
        [int]$Default = 0
    )

    $uac = 0
    $sawSomething = $false

    foreach ($part in @($Value)) {
        if ($null -eq $part) { continue }

        if ($part -is [int] -or $part -is [long]) {
            $uac = $uac -bor [int]$part
            $sawSomething = $true
            continue
        }

        $text = "$part"
        if ([string]::IsNullOrWhiteSpace($text)) { continue }

        $parsed = 0
        if ([int]::TryParse($text, [ref]$parsed)) {
            $uac = $uac -bor $parsed
            $sawSomething = $true
        }
        elseif ($Script:UACNameToBit.ContainsKey($text.ToUpperInvariant())) {
            $uac = $uac -bor $Script:UACNameToBit[$text.ToUpperInvariant()]
            $sawSomething = $true
        }
        # An unknown name is skipped rather than voiding the mask: a future Windows flag
        # must not make an account look enabled when ACCOUNTDISABLE sits next to it.
    }

    if (-not $sawSomething) { return $Default }
    return $uac
}
