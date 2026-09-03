<#
.SYNOPSIS
    Generates a random password without problematic special characters.

.DESCRIPTION
    Creates cryptographically random passwords suitable for use in scripts, command lines, and configuration files.
    Excludes characters that cause escaping issues in PowerShell, CMD, and other contexts.

    Excluded characters:
    - " (double quote) - PowerShell/CMD string delimiter
    - ' (single quote) - PowerShell string delimiter
    - ` (backtick) - PowerShell escape character
    - $ (dollar) - PowerShell variable prefix
    - \ (backslash) - Escape character in many contexts
    - / (forward slash) - Path separator, can cause issues
    - | (pipe) - Shell pipe operator
    - < > (angle brackets) - Redirection operators
    - & (ampersand) - Command separator
    - ; (semicolon) - Command separator
    - % (percent) - CMD variable syntax
    - ! (exclamation) - History expansion in some shells

    Included safe special characters:
    - @ # ^ * ( ) _ - + = { } [ ] : . , ? ~

.PARAMETER Length
    Length of the password to generate. Default: 20. Minimum: 8.

.PARAMETER NoSpecialChars
    Generate password with only alphanumeric characters (A-Z, a-z, 0-9).

.EXAMPLE
    New-SafePassword
    Returns a 20-character password with safe special characters.

.EXAMPLE
    New-SafePassword -Length 32
    Returns a 32-character password.

.EXAMPLE
    New-SafePassword -NoSpecialChars
    Returns a 20-character alphanumeric-only password.

.OUTPUTS
    String - The generated password.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function New-SafePassword {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$false)]
        [ValidateRange(8, 128)]
        [int]$Length = 20,

        [Parameter(Mandatory=$false)]
        [switch]$NoSpecialChars
    )

    process {
        # Character sets
        $Lowercase = 'abcdefghijklmnopqrstuvwxyz'
        $Uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        $Digits = '0123456789'

        # Safe special characters (no escaping issues in PowerShell, CMD, or common shells)
        # Excluded: " ' ` $ \ / | < > & ; % !
        $SafeSpecials = '@#^*()_-+={[]}:.?,~'

        if ($NoSpecialChars) {
            $CharSet = $Lowercase + $Uppercase + $Digits
        } else {
            $CharSet = $Lowercase + $Uppercase + $Digits + $SafeSpecials
        }

        $CharArray = $CharSet.ToCharArray()

        # Use cryptographically secure random number generator
        $RNG = [System.Security.Cryptography.RandomNumberGenerator]::Create()

        try {
            $Password = [System.Text.StringBuilder]::new($Length)
            $RandomBytes = New-Object byte[] 1

            # Rejection sampling rather than a plain modulo. 256 is not a multiple of the
            # alphabet size - 81 with the special characters, 62 without - so "byte % n"
            # hands the first 256 mod n characters an extra chance each and skews the
            # distribution. Bytes at or above the largest whole multiple of n are drawn
            # again instead, which costs a few extra draws and leaves every character
            # equally likely. This generates passwords that get set on real accounts.
            $Limit = 256 - (256 % $CharArray.Length)

            for ($i = 0; $i -lt $Length; $i++) {
                do {
                    $RNG.GetBytes($RandomBytes)
                } while ([int]$RandomBytes[0] -ge $Limit)

                $Index = [int]$RandomBytes[0] % $CharArray.Length
                [void]$Password.Append($CharArray[$Index])
            }

            # Ensure password contains at least one of each required character type
            # This helps meet typical password policy requirements
            $PasswordString = $Password.ToString()

            $HasLower = $PasswordString -cmatch '[a-z]'
            $HasUpper = $PasswordString -cmatch '[A-Z]'
            $HasDigit = $PasswordString -match '[0-9]'
            $HasSpecial = if (-not $NoSpecialChars) { $PasswordString -match '[@#^*()_\-+={}\[\]:.,?~]' } else { $true }

            # If missing required character types, regenerate (recursive with limit)
            if (-not ($HasLower -and $HasUpper -and $HasDigit -and $HasSpecial)) {
                # Simple retry - call ourselves again (limited by stack depth)
                return New-SafePassword -Length $Length -NoSpecialChars:$NoSpecialChars
            }

            return $PasswordString
        }
        finally {
            $RNG.Dispose()
        }
    }
}
