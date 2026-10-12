function Get-UnixPasswordFormat {
    <#
    .SYNOPSIS
    Names the storage format of a Unix, LDAP or Samba password attribute value.

    .DESCRIPTION
    userPassword, unixUserPassword, msSFU30Password, sambaNTPassword and sambaLMPassword are
    ordinary attributes, so whatever is in them is readable by whoever the ACL allows - but
    what is in them differs by orders of magnitude in what it is worth to an attacker, and
    the check reported one verdict for all of it.

    Three classes, and the difference between the first two and the third is the whole point:

      Usable as it stands  a cleartext password, or an NT hash, which authenticates as it is.
                           Nothing has to be cracked and nothing has to be guessed.
      Trivially cracked    an LM hash (two seven-character halves, uppercased), DES crypt
                           (eight characters at most), or an unsalted MD5 or SHA-1 digest.
                           Hours on commodity hardware, and no salt to get in the way.
      Has to be cracked    a salted crypt(3) hash - MD5, SHA-256, SHA-512, bcrypt, yescrypt -
                           or {SSHA}. Still worth reporting, because the password is now
                           offline and the account is a target, but the finding is a hint.

    The shapes are the documented ones: RFC 2307 names a scheme in braces ({crypt}, {MD5},
    {SHA}, {SSHA}), crypt(3) prefixes the hash with $id$ ($1$ MD5, $2a$/$2b$/$2y$ bcrypt,
    $5$ SHA-256, $6$ SHA-512, $y$ yescrypt), DES crypt is 13 characters of its own alphabet
    with no prefix at all, and an NT or LM hash is 32 hex characters.

    .PARAMETER Value
    The attribute value, already decoded to text.

    .PARAMETER Attribute
    The attribute it came from. It decides between the two 32-hex-character hashes:
    sambaLMPassword holds an LM hash, sambaNTPassword an NT hash, and in any other attribute
    32 hex characters are an NT hash in practice.

    .OUTPUTS
    Hashtable with Format (the sentence that goes on the object) and Severity.

    .EXAMPLE
    Get-UnixPasswordFormat -Value '$6$rounds=5000$abc$def' -Attribute 'userPassword'

    .NOTES
    Author: Alexander Sturz (@_61106960_)
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Attribute
    )

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return @{ Format = 'Empty - the attribute is set but carries no value'; Severity = 'Note' }
    }
    $text = $text.Trim()

    # The empty-LM placeholder. Every Samba installation that stores no LM hash writes this
    # exact value, so reporting it as a readable credential is a false positive with a
    # recognisable face.
    # The wording deliberately avoids the words "LM hash": Test-UnixPasswordUsableAsIs
    # matches on those, and a placeholder that says it has none would have read as one.
    if ($text -ieq 'aad3b435b51404eeaad3b435b51404ee') {
        return @{ Format = 'No hash stored - the value is the documented empty placeholder'; Severity = 'Note' }
    }

    # RFC 2307 scheme prefix. {crypt} is followed by a crypt(3) value, which the block
    # below classifies, so the prefix is stripped rather than answered here.
    $scheme = $null
    if ($text -match '^\{([A-Za-z0-9-]+)\}(.*)$') {
        $scheme = $Matches[1].ToUpper()
        $text   = $Matches[2]
        if ($scheme -eq 'CLEARTEXT' -or $scheme -eq 'CLEAR') {
            return @{ Format = 'Cleartext - the password as it stands, nothing to crack'; Severity = 'Finding' }
        }
        if ($scheme -eq 'SSHA' -or $scheme -eq 'SSHA256' -or $scheme -eq 'SSHA512') {
            return @{ Format = "Salted SHA-1 ({$scheme}) - has to be cracked"; Severity = 'Hint' }
        }
        if ($scheme -eq 'MD5' -or $scheme -eq 'SHA') {
            return @{ Format = "Unsalted digest ({$scheme}) - no salt, so rainbow tables apply"; Severity = 'Finding' }
        }
        if ($scheme -eq 'NT' -or $scheme -eq 'NTLM') {
            return @{ Format = 'NT hash - authenticates as it is, no cracking needed'; Severity = 'Finding' }
        }
    }

    # crypt(3), by its $id$ prefix.
    if ($text -match '^\$([A-Za-z0-9]{1,3})\$') {
        $id = $Matches[1]
        switch ($id) {
            '1'  { return @{ Format = 'MD5 crypt - salted, but fast to try; has to be cracked'; Severity = 'Hint' } }
            '2'  { return @{ Format = 'bcrypt - salted and deliberately slow; has to be cracked'; Severity = 'Hint' } }
            '2a' { return @{ Format = 'bcrypt - salted and deliberately slow; has to be cracked'; Severity = 'Hint' } }
            '2b' { return @{ Format = 'bcrypt - salted and deliberately slow; has to be cracked'; Severity = 'Hint' } }
            '2x' { return @{ Format = 'bcrypt - salted and deliberately slow; has to be cracked'; Severity = 'Hint' } }
            '2y' { return @{ Format = 'bcrypt - salted and deliberately slow; has to be cracked'; Severity = 'Hint' } }
            '5'  { return @{ Format = 'SHA-256 crypt - salted; has to be cracked'; Severity = 'Hint' } }
            '6'  { return @{ Format = 'SHA-512 crypt - salted; has to be cracked'; Severity = 'Hint' } }
            'y'  { return @{ Format = 'yescrypt - salted and memory-hard; has to be cracked'; Severity = 'Hint' } }
            default {
                return @{ Format = "Crypt hash, scheme `$$id`$ - has to be cracked"; Severity = 'Hint' }
            }
        }
    }

    # 32 hex characters: which of the two depends on the attribute it came from.
    if ($text -match '^[0-9a-fA-F]{32}$') {
        if ($Attribute -ieq 'sambaLMPassword') {
            return @{ Format = 'LM hash - two seven-character halves, cracked in minutes whatever the password'; Severity = 'Finding' }
        }
        return @{ Format = 'NT hash - authenticates as it is, no cracking needed'; Severity = 'Finding' }
    }

    # DES crypt: thirteen characters of the crypt alphabet, no prefix. Checked after the
    # hex case, because a 13 character value cannot be 32 hex characters anyway, and after
    # the $id$ case, because $1$... is longer than 13 but would match the alphabet.
    #
    # A thirteen character password of letters and digits has the same shape and is read as
    # a DES hash. Both are findings, so the verdict holds either way, and the shape is the
    # documented one - there is nothing else in the value to tell them apart.
    if ($text -match '^[./0-9A-Za-z]{13}$') {
        return @{ Format = 'DES crypt - eight characters at most, cracked in hours'; Severity = 'Finding' }
    }

    # Nothing matched a hash shape. A value that no hash format recognises is most often the
    # password itself - set by hand, by a script, or by an appliance that does not hash -
    # and it is sometimes an encoding of it, base64 above all, which is no protection
    # either. The sentence says which of the two it has not ruled out, and the verdict is
    # the same for both.
    if ($scheme) {
        return @{ Format = "Unrecognised format (scheme {$scheme}) - inspect the value"; Severity = 'Hint' }
    }
    return @{ Format = 'Cleartext or an encoding of it - no hash format matches this value'; Severity = 'Finding' }
}

function Test-UnixPasswordUsableAsIs {
    <#
    .SYNOPSIS
    Whether any of the formats on an object can be used without cracking anything.

    .DESCRIPTION
    The counterpart to Get-UnixPasswordFormat, kept beside it so the wording and the verdict
    that reads it cannot drift apart. Used by the finding trigger that decides whether the
    attribute row itself is a finding: a readable $6$ hash and a readable cleartext password
    are not the same discovery, and six pattern-less triggers used to grade them the same.

    .PARAMETER Format
    The passwordFormat values the check put on the object.

    .OUTPUTS
    [bool]
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string[]]$Format
    )

    foreach ($entry in @($Format)) {
        if ([string]::IsNullOrWhiteSpace($entry)) { continue }
        # Cleartext and an NT hash need nothing; LM, DES and an unsalted digest need hours.
        if ($entry -match 'Cleartext|NT hash|LM hash|DES crypt|Unsalted digest') { return $true }
    }
    return $false
}
