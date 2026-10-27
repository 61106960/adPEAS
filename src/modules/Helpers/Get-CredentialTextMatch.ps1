# The pattern tables of the free-text credential search, shared by Get-PasswordInDescription
# and Get-DeletedObjectAccess so the two cannot drift apart. Constant lookup tables, defined
# once when the module loads - not session state.

# One token for every language variant of the word, used by all three pattern
# lists below so they cannot drift apart. It replaces a bare 'passw\S*', which
# was documented as covering Norwegian "passord" and Esperanto "pasvorto" but
# cannot: neither word contains "passw". Two consequences, both silent - a
# Norwegian description holding a real password was never matched, and the
# Norwegian exclusion terms further down (lengde, utloep, maa, boer) could
# never fire either, because they were anchored to the same impossible prefix.
#   sw\S*   password, passwd, passwort, passwuert   (EN/DE/LU)
#   sord    passord                                 (NO)
#   vorto   pasvorto                                (EO)
$Script:CredentialTextPasswordToken = 'pas(?:sw\S*|sord|vorto)'

# A value that is no value: a row of asterisks or an angle-bracket placeholder.
# Part of every assignment pattern rather than a test on the whole attribute,
# which is what it used to be - a masked value anywhere in an attribute skipped
# the attribute, and "pwd: Sommer2024, old: password=****" was not reported.
$Script:CredentialTextRealValue = '(?!\*+(?:\s|$))(?!<[^>]+>)\S{3,}'

# Tier 1: High-confidence patterns (password assignment with value)
$Script:CredentialTextTier1Patterns = @(
    @{ Pattern = $Script:CredentialTextPasswordToken + '\s*[=:]\s*["''][^"'']{3,}["'']'; Description = "Password-variant assignment (quoted)" }
    @{ Pattern = $Script:CredentialTextPasswordToken + '\s*[=:]\s*(?!["''])' + $Script:CredentialTextRealValue; Description = "Password-variant assignment (unquoted)" }
    @{ Pattern = 'pwd\s*[=:]\s*' + $Script:CredentialTextRealValue; Description = "Pwd assignment" }
    @{ Pattern = 'pw\s*[=:]\s*' + $Script:CredentialTextRealValue; Description = "PW assignment" }
    @{ Pattern = '\bpass\s*[=:]\s*' + $Script:CredentialTextRealValue; Description = "Pass assignment" }
    @{ Pattern = 'kennwort\s*[=:]\s*' + $Script:CredentialTextRealValue; Description = "Kennwort assignment (German)" }
    @{ Pattern = '\bparol[ae]?\s*[=:]\s*' + $Script:CredentialTextRealValue; Description = "Parola/parole/parol assignment (RO/LV/IT)" }
    # The userinfo part of a URL, RFC 3986: scheme://user:password@host. Written
    # into a homepage or url attribute, or into a description, it is the
    # credential itself. A user name alone (user@host) or an empty password
    # (user:@host) does not match, and neither does a port (host:8080/).
    @{ Pattern = '[a-z][a-z0-9+.-]*://[^\s/:@]+:(?!\*+@)(?!<[^>]+>@)[^\s/@]+@'; Description = "Credentials embedded in a URL" }
)

# Tier 2: Lower-confidence patterns (generic credential mentions)
$Script:CredentialTextTier2Patterns = @(
    @{ Pattern = $Script:CredentialTextPasswordToken; Description = "Password-variant mention (EN/DE/NO/LU/EO)" }
    @{ Pattern = '\bparol[ae]?\b'; Description = "Parola/parole/parol mention (RO/LV/IT)" }
    @{ Pattern = '\bcred(ential)?s?\b'; Description = "Credential mention" }
    @{ Pattern = '\b(secret|token)\s*[=:]\s*\S{5,}'; Description = "Secret/token assignment" }
)

# Exclusion patterns (skip if line matches these - password policy text, help, etc.)
# Conservative approach: better to show a false positive than to hide a real password
# Only exact terms - no wildcards for foreign words we haven't verified in real AD data
$Script:CredentialTextExclusionPatterns = @(
    # Policy/guideline text (EN/DE/IT/RO)
    # Every concatenation is parenthesized on purpose: in PowerShell the comma
    # binds tighter than +, so "$pwToken + 'a', $pwToken + 'b'" parses as
    # "$pwToken + @('a', ...)" and collapses the whole list into one glued
    # string. The exclusions then match nothing at all.
    ($Script:CredentialTextPasswordToken + '\s*(policy|policies|requirement|guideline|richtlinie|anforderung)'),
    '\bparol[ae]?\s*(policy|politica|cerinta)',
    # Modal verbs: "password must/should..." (EN/DE/NO/IT/RO)
    # Norwegian letters are written as regex \u escapes to keep this file pure ASCII:
    # \u00E5 = a with ring, \u00F8 = o with stroke
    ($Script:CredentialTextPasswordToken + '\s+(must|should|cannot|shall|muss|soll|darf|kann|m\u00E5|b\u00F8r|deve|trebuie)\s+'),
    # Technical terms: length, complexity, expiry (EN/DE/NO/IT)
    ($Script:CredentialTextPasswordToken + '\s+(length|complexity|history|age|expir|wechsel|ablauf|historie|lengde|utl\u00F8p|lunghezza|scadenza)'),
    # Reset/change/recover (EN/IT/RO)
    ($Script:CredentialTextPasswordToken + '\s+(reset|change|recover|forgot|reimpost|cambiar|schimb)'),
    '\bparol[ae]?\s+(reset|change|reimpost|cambiar|schimbar)',
    # Relative: "minimum/maximum password"
    ('(minimum|maximum)\s+' + $Script:CredentialTextPasswordToken),
    # Imperative: "set/change/update your password" (EN)
    ('(set|change|update|reset)\s+(your|the|a)\s+' + $Script:CredentialTextPasswordToken),
    # Prompts
    ('Enter\s+(your\s+)?' + $Script:CredentialTextPasswordToken),
    ($Script:CredentialTextPasswordToken + '\s+prompt'),
    # Replication: "Members in this group can have their passwords replicated to
    # all read-only domain controllers in the domain" is the description the
    # Allowed and Denied RODC Password Replication Groups ship with - a hint in
    # every domain, measured.
    ($Script:CredentialTextPasswordToken + '\s+replicat')
)

# A second, much narrower list. The two kinds of exclusion above and below are
# not the same thing. The ones above describe the *sentence* - it reads like
# policy or help text - and that is a reason to distrust a bare mention, never a
# reason to ignore an assignment standing next to it. The ones here describe the
# *value*: the syntax is an assignment, but what was assigned is a row of
# asterisks or an angle-bracket placeholder. The assignment patterns already
# pass over such a value; this list keeps the mention beside it from becoming a
# hint, since "Password: ********" says only that a password exists.
$Script:CredentialTextPlaceholderPatterns = @(
    ($Script:CredentialTextPasswordToken + '\s*[=:]\s*\*+(?:\s|$)'),
    ($Script:CredentialTextPasswordToken + '\s*[=:]\s*<[^>]+>'),
    'pwd\s*[=:]\s*\*+(?:\s|$)',
    'pwd\s*[=:]\s*<[^>]+>',
    '\bpass\s*[=:]\s*\*+(?:\s|$)',
    '\bpass\s*[=:]\s*<[^>]+>',
    'kennwort\s*[=:]\s*\*+(?:\s|$)',
    'kennwort\s*[=:]\s*<[^>]+>',
    '://[^\s/:@]+:\*+@',
    '://[^\s/:@]+:<[^>]+>@'
)

# The attributes these patterns are run over - $Script:CredentialTextBaseAttributes,
# -ExchangeAttributes, -CloudAttributes and -UrlAttributes - are defined in
# adPEAS-FindingDefinitions.ps1, which builds the triggers on them and loads first.

function Get-CredentialTextMatch {
    <#
    .SYNOPSIS
    Decides whether the free-text attributes of one object hold a credential.

    .DESCRIPTION
    Two tiers. Tier 1 is an assignment with a value ("password=Secret123") or credentials in
    the userinfo part of a URL; tier 2 is a word that only mentions a password or a
    credential. Tier 2 is not applied to the link and path attributes, and policy or help
    wording ($Script:CredentialTextExclusionPatterns) and a masked or placeholder value
    ($Script:CredentialTextPlaceholderPatterns) keep a mention from counting - never an
    assignment.

    Every attribute is looked at and the strongest hit wins: a bare mention in description
    does not decide the object when info carries an assignment.

    .PARAMETER Attributes
    The values to examine, in the order they are to be looked at: hashtables with Name and
    Value, Value already joined to one string.

    .PARAMETER Label
    Names the object in the log lines.

    .OUTPUTS
    PSCustomObject with Tier (0 nothing, 1 assignment, 2 mention) and Attribute (the name of
    the attribute that decided it, $null for tier 0).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [object[]]$Attributes = @(),

        [Parameter(Mandatory = $false)]
        [string]$Label
    )

    # Look at every attribute before reporting, and keep the strongest hit.
    # Reporting on the first hit meant description was allowed to decide the
    # severity for the whole account: a bare mention there ("password reset
    # by helpdesk") broke the loop as a Hint, and an actual assignment in
    # info was never examined. The account was filed one tier too low and
    # the credential the check exists to find went unreported.
    $bestTier = 0
    $bestAttrName = $null

    foreach ($attr in @($Attributes)) {
        if (-not $attr) { continue }
        $attrValue = [string]$attr.Value

        # Tier 1 is decided before the prose exclusions are consulted.
        #
        # The exclusions used to run first and skipped the whole attribute
        # on a hit, which is the opposite of what this check is for. Policy
        # wording and a real credential live in the same description all the
        # time - "Passwort muss geaendert werden. Passwort = Winter2024!",
        # "Password complexity required; password: Herbst2024" - and every
        # one of those was dropped without a word, because the modal verb or
        # the word "complexity" matched an exclusion. Three of five
        # realistic strings carrying an actual assignment were lost that way.
        #
        # An exclusion says "this reads like policy text", which is a reason
        # to distrust a bare mention, never a reason to ignore an assignment
        # with a value next to it. So it only downgrades tier 2 now.
        $isTier1 = $false
        foreach ($t1 in $Script:CredentialTextTier1Patterns) {
            if ($attrValue -imatch $t1.Pattern) {
                $isTier1 = $true
                Write-Log "[Get-CredentialTextMatch] TIER1 match on $Label ($($attr.Name)): $($t1.Description)"
                break
            }
        }

        if ($isTier1) {
            # Nothing outranks a tier 1 hit, so stop looking.
            $bestTier = 1
            $bestAttrName = $attr.Name
            break
        }

        # A link mentions what it links to; that is not a credential.
        if ($Script:CredentialTextUrlAttributes -contains $attr.Name) { continue }

        # A masked or bracketed value is not a credential, and the mention
        # beside it only says that a password exists - after tier 1, so that
        # a masked value no longer hides a real assignment next to it.
        $isPlaceholder = $false
        foreach ($phPattern in $Script:CredentialTextPlaceholderPatterns) {
            if ($attrValue -imatch $phPattern) {
                $isPlaceholder = $true
                Write-Log "[Get-CredentialTextMatch] Placeholder value on $Label ($($attr.Name)): '$phPattern'"
                break
            }
        }
        if ($isPlaceholder) { continue }

        # No assignment here, so policy wording is what it looks like.
        $excluded = $false
        foreach ($exPattern in $Script:CredentialTextExclusionPatterns) {
            if ($attrValue -match $exPattern) {
                $excluded = $true
                Write-Log "[Get-CredentialTextMatch] Excluded $Label ($($attr.Name)): matches exclusion '$exPattern'"
                break
            }
        }
        if ($excluded) { continue }

        # Check Tier 2 patterns (Hint)
        $isTier2 = $false
        foreach ($t2 in $Script:CredentialTextTier2Patterns) {
            if ($attrValue -imatch $t2.Pattern) {
                $isTier2 = $true
                Write-Log "[Get-CredentialTextMatch] TIER2 match on $Label ($($attr.Name)): $($t2.Description)"
                break
            }
        }

        # Remember the first tier 2 hit, but keep reading: a later attribute
        # may still hold an assignment.
        if ($isTier2 -and $bestTier -eq 0) {
            $bestTier = 2
            $bestAttrName = $attr.Name
        }
    }

    return [PSCustomObject]@{
        Tier      = $bestTier
        Attribute = $bestAttrName
    }
}
