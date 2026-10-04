<#
.SYNOPSIS
    Central input validation functions for adPEAS.

.DESCRIPTION
    Provides secure input validation and sanitization functions to prevent:
    - LDAP Injection attacks (RFC 4515 escaping)
    - UNC Path traversal attacks
    - Invalid computer/domain name injection
    - Command injection via parameter manipulation

    All validation functions follow the principle of whitelist validation
    (allow known-good patterns) rather than blacklist (block known-bad).

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

#region LDAP Escaping (RFC 4515)

<#
.SYNOPSIS
    Escapes special characters in LDAP filter values according to RFC 4515.

.DESCRIPTION
    LDAP filters use special characters that must be escaped when they appear
    in filter values. This function escapes all characters defined in RFC 4515
    Section 3 to prevent LDAP injection attacks.

    Characters that MUST be escaped:
    - * (asterisk)     -> \2a
    - ( (left paren)   -> \28
    - ) (right paren)  -> \29
    - \ (backslash)    -> \5c
    - NUL (0x00)       -> \00

    Additionally, any non-ASCII characters are hex-escaped for safety.

.PARAMETER Value
    The string value to escape for use in an LDAP filter.

.EXAMPLE
    Escape-LDAPFilterValue -Value "john*"
    # Returns: john\2a

.EXAMPLE
    Escape-LDAPFilterValue -Value "CN=Test (Group)"
    # Returns: CN=Test \28Group\29

.EXAMPLE
    # Safe LDAP filter construction
    $escapedName = Escape-LDAPFilterValue -Value $userInput
    $filter = "(sAMAccountName=$escapedName)"

.OUTPUTS
    [string] The escaped value safe for use in LDAP filters.

.NOTES
    ALWAYS use this function when incorporating user input into LDAP filters!

    WRONG (vulnerable):
        $filter = "(sAMAccountName=$userInput)"

    CORRECT (safe):
        $escaped = Escape-LDAPFilterValue -Value $userInput
        $filter = "(sAMAccountName=$escaped)"
#>
function Escape-LDAPFilterValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    process {
        if ([string]::IsNullOrEmpty($Value)) {
            return $Value
        }

        # RFC 4515 Section 3 - Characters that MUST be escaped in LDAP filter values
        # Build result character by character for complete control
        $result = [System.Text.StringBuilder]::new($Value.Length * 2)

        foreach ($char in $Value.ToCharArray()) {
            switch ($char) {
                # RFC 4515 required escapes
                '*'  { [void]$result.Append('\2a'); break }
                '('  { [void]$result.Append('\28'); break }
                ')'  { [void]$result.Append('\29'); break }
                '\'  { [void]$result.Append('\5c'); break }
                "`0" { [void]$result.Append('\00'); break }  # NUL character

                default {
                    # Check for non-printable or non-ASCII characters
                    $charCode = [int]$char
                    if ($charCode -lt 32 -or $charCode -gt 126) {
                        # Hex-encode non-printable/non-ASCII
                        $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$char)
                        foreach ($byte in $bytes) {
                            [void]$result.Append('\')
                            [void]$result.Append($byte.ToString('x2'))
                        }
                    }
                    else {
                        [void]$result.Append($char)
                    }
                }
            }
        }

        return $result.ToString()
    }
}

<#
.SYNOPSIS
    Escapes a Distinguished Name for use in LDAP filter values.

.DESCRIPTION
    When a DN is used as a VALUE in an LDAP filter (e.g., memberOf=<DN>),
    it needs RFC 4515 escaping for the filter context.

    IMPORTANT: This function is for DNs used INSIDE filter assertions.
    It applies RFC 4515 filter value escaping, which handles:
    - * ( ) \ NUL and non-ASCII characters

    Note: RFC 4514 DN escaping (for DN construction) uses different rules
    and escapes: , + " \ < > ; and leading/trailing spaces.
    AD typically returns properly escaped DNs, so when re-using AD-returned
    DNs in filters, only RFC 4515 escaping is needed.

.PARAMETER DistinguishedName
    The DN to escape for use in an LDAP filter value.

.EXAMPLE
    $escapedDN = Escape-LDAPFilterDN -DistinguishedName "CN=Test (User),OU=Users,DC=contoso,DC=com"
    $filter = "(memberOf=$escapedDN)"

.OUTPUTS
    [string] The escaped DN safe for use in LDAP filters.
#>
function Escape-LDAPFilterDN {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [string]$DistinguishedName
    )

    process {
        if ([string]::IsNullOrEmpty($DistinguishedName)) {
            return $DistinguishedName
        }

        # DNs from AD are already RFC 4514 escaped. RFC 4514 uses backslash-escaping
        # for special chars: \, \+ \" \\ \< \> \; \# and \XX hex pairs.
        # We must NOT double-escape those backslashes. We only need to escape
        # the RFC 4515 filter-specific characters: * ( ) NUL
        # and any non-ASCII characters.
        $result = [System.Text.StringBuilder]::new($DistinguishedName.Length * 2)
        $chars = $DistinguishedName.ToCharArray()
        $i = 0

        while ($i -lt $chars.Length) {
            $char = $chars[$i]

            if ($char -eq '\') {
                # Check if this backslash is part of an existing RFC 4514 escape sequence
                if (($i + 2) -lt $chars.Length) {
                    $next1 = $chars[$i + 1]
                    $next2 = $chars[$i + 2]
                    # RFC 4514 hex pair: \XX where X is [0-9a-fA-F]
                    $isHex1 = ($next1 -ge '0' -and $next1 -le '9') -or ($next1 -ge 'a' -and $next1 -le 'f') -or ($next1 -ge 'A' -and $next1 -le 'F')
                    $isHex2 = ($next2 -ge '0' -and $next2 -le '9') -or ($next2 -ge 'a' -and $next2 -le 'f') -or ($next2 -ge 'A' -and $next2 -le 'F')
                    if ($isHex1 -and $isHex2) {
                        # Existing hex escape - pass through unchanged
                        [void]$result.Append($chars[$i])
                        [void]$result.Append($chars[$i + 1])
                        [void]$result.Append($chars[$i + 2])
                        $i += 3
                        continue
                    }
                }
                if (($i + 1) -lt $chars.Length) {
                    $next = $chars[$i + 1]
                    # RFC 4514 special char escapes: \, \+ \" \\ \< \> \; \#
                    if ($next -eq ',' -or $next -eq '+' -or $next -eq '"' -or $next -eq '\' -or
                        $next -eq '<' -or $next -eq '>' -or $next -eq ';' -or $next -eq '#' -or $next -eq ' ') {
                        # Existing special char escape - pass through unchanged
                        [void]$result.Append($chars[$i])
                        [void]$result.Append($chars[$i + 1])
                        $i += 2
                        continue
                    }
                }
                # Standalone backslash (not part of RFC 4514 escape) - escape for RFC 4515
                [void]$result.Append('\5c')
            }
            elseif ($char -eq '*') {
                [void]$result.Append('\2a')
            }
            elseif ($char -eq '(') {
                [void]$result.Append('\28')
            }
            elseif ($char -eq ')') {
                [void]$result.Append('\29')
            }
            elseif ($char -eq "`0") {
                [void]$result.Append('\00')
            }
            else {
                $charCode = [int]$char
                if ($charCode -lt 32 -or $charCode -gt 126) {
                    $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$char)
                    foreach ($byte in $bytes) {
                        [void]$result.Append('\')
                        [void]$result.Append($byte.ToString('x2'))
                    }
                }
                else {
                    [void]$result.Append($char)
                }
            }
            $i++
        }

        return $result.ToString()
    }
}

#endregion

#region LDAP DN Construction (RFC 4514)

<#
.SYNOPSIS
    Escapes a single DN component value according to RFC 4514.

.DESCRIPTION
    RFC 4514 governs the string representation of a Distinguished Name, and its rules are
    NOT the rules of RFC 4515 filter escaping. Use this function when CONSTRUCTING a DN or
    an RDN - for example the NewName of a ModifyDNRequest. To place a DN into a filter
    value, use Escape-LDAPFilterDN instead.

    Escaped anywhere in the value:
    - , + " \ < > ;                -> backslash-prefixed
    - control characters (< 0x20)  -> \XX hex pair

    Escaped only at a specific position:
    - leading #                    -> \#  (a leading # introduces a hex-encoded BER value)
    - leading space                -> backslash-space
    - trailing space               -> backslash-space

.PARAMETER Value
    The unescaped attribute value, e.g. 'Doe, Jane'.

.EXAMPLE
    Escape-LDAPDNComponent -Value 'Doe, Jane'
    # Returns: Doe\, Jane

.EXAMPLE
    # Safe RDN construction for a ModifyDNRequest
    $newRDN = 'CN=' + (Escape-LDAPDNComponent -Value $NewName)

.OUTPUTS
    [string] The escaped value, safe to use as the value half of an RDN.

.NOTES
    Do NOT pass an AD-returned DN or RDN through this function. Those are already RFC 4514
    escaped, and escaping them a second time turns CN=Doe\, Jane into CN=Doe\\\, Jane,
    which files the object under a different name than intended.
#>
function Escape-LDAPDNComponent {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    process {
        if ([string]::IsNullOrEmpty($Value)) {
            return $Value
        }

        # Deliberately an if/elseif chain rather than a switch: 'continue' inside a switch
        # that sits in a loop continues the LOOP, so a switch-based escaper reads as if it
        # skipped characters it actually appended.
        $specials = ',+"\<>;'
        $result = [System.Text.StringBuilder]::new($Value.Length * 2)
        $lastIndex = $Value.Length - 1

        for ($i = 0; $i -lt $Value.Length; $i++) {
            $char = $Value[$i]

            if ($specials.IndexOf($char) -ge 0) {
                [void]$result.Append('\')
                [void]$result.Append($char)
            }
            elseif ($char -eq ' ' -and ($i -eq 0 -or $i -eq $lastIndex)) {
                [void]$result.Append('\ ')
            }
            elseif ($char -eq '#' -and $i -eq 0) {
                [void]$result.Append('\#')
            }
            elseif ([int]$char -lt 32) {
                [void]$result.Append('\')
                [void]$result.Append(([int]$char).ToString('X2'))
            }
            else {
                [void]$result.Append($char)
            }
        }

        return $result.ToString()
    }
}

<#
.SYNOPSIS
    Splits a Distinguished Name into its leading RDN and parent DN, honouring RFC 4514 escapes.

.DESCRIPTION
    A DN cannot be split on ',': RFC 4514 allows an escaped comma inside an attribute value,
    so 'CN=Doe\, Jane,OU=Finance,DC=contoso,DC=com' has four components, not five. Splitting
    naively yields the parent 'Jane,OU=Finance,DC=contoso,DC=com', which does not exist.

    The .NET type X500DistinguishedName is not an alternative: it throws outright on an
    escaped comma, reverses component order, and truncates a trailing escaped space.

.PARAMETER DistinguishedName
    The DN to split, as returned by AD (already RFC 4514 escaped).

.EXAMPLE
    $parts = Split-LDAPDN -DistinguishedName 'CN=Doe\, Jane,OU=Finance,DC=contoso,DC=com'
    $parts.RDN       # CN=Doe\, Jane                 (still escaped - reuse verbatim)
    $parts.RDNType   # CN
    $parts.RDNValue  # Doe, Jane                     (unescaped - for display only)
    $parts.Parent    # OU=Finance,DC=contoso,DC=com

.OUTPUTS
    [PSCustomObject] with RDN, RDNType, RDNValue and Parent, or $null when the DN cannot be
    parsed. Parent is an empty string for a single-component DN.

.NOTES
    RDN is returned verbatim so it can be handed straight back to AD. RDNValue is unescaped
    and is for display only - never build a DN from it without re-escaping.

    Multi-valued RDNs ('CN=a+SN=b,DC=x') return $null rather than a partial parse. AD permits
    them in theory and never creates them in practice, and silently mis-parsing one is worse
    than refusing it.
#>
function Split-LDAPDN {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [string]$DistinguishedName
    )

    process {
        if ([string]::IsNullOrWhiteSpace($DistinguishedName)) {
            return $null
        }

        # (?:[^,\\+]|\\.)* consumes escape pairs atomically, so the capture stops at the first
        # UNescaped comma - the same idiom as the leaf-RDN match in
        # Get-ExchangeRBACAssignments.ps1. An unescaped '+' is excluded from the class on
        # purpose: RFC 4514 reserves it as the multi-valued RDN separator, so a DN containing
        # one fails the match as a whole and the function returns $null.
        if ($DistinguishedName -notmatch '^([A-Za-z][A-Za-z0-9-]*)=((?:[^,\\+]|\\.)*)(?:,(.*))?$') {
            Write-Log "[Split-LDAPDN] Rejected: not a parseable single-valued DN - '$DistinguishedName'"
            return $null
        }

        $rdnType = $Matches[1]
        $rdnValue = $Matches[2]
        $parent = ''
        if ($Matches.ContainsKey(3)) {
            $parent = $Matches[3]
        }

        # RFC 4514 unescape, for display only: \XX is a hex pair, \<char> is that character.
        $unescaped = [System.Text.StringBuilder]::new($rdnValue.Length)
        $valueChars = $rdnValue.ToCharArray()
        $j = 0

        while ($j -lt $valueChars.Length) {
            if ($valueChars[$j] -ne '\') {
                [void]$unescaped.Append($valueChars[$j])
                $j++
                continue
            }

            if (($j + 2) -lt $valueChars.Length) {
                $hexPair = [string]$valueChars[$j + 1] + [string]$valueChars[$j + 2]
                if ($hexPair -match '^[0-9A-Fa-f]{2}$') {
                    [void]$unescaped.Append([char][Convert]::ToInt32($hexPair, 16))
                    $j += 3
                    continue
                }
            }
            if (($j + 1) -lt $valueChars.Length) {
                [void]$unescaped.Append($valueChars[$j + 1])
                $j += 2
                continue
            }

            # Trailing lone backslash - keep it rather than dropping it silently.
            [void]$unescaped.Append('\')
            $j++
        }

        return [PSCustomObject]@{
            RDN      = "$rdnType=$rdnValue"
            RDNType  = $rdnType
            RDNValue = $unescaped.ToString()
            Parent   = $parent
        }
    }
}

#endregion

#region Computer Name Validation

<#
.SYNOPSIS
    Validates a computer name against Windows/NetBIOS naming rules.

.DESCRIPTION
    Validates computer names using whitelist approach based on:
    - RFC 1123 (Internet host naming)
    - Microsoft NetBIOS naming conventions
    - Windows computer naming restrictions

    Valid names:
    - 1-15 characters for NetBIOS, up to 63 for DNS
    - Alphanumeric characters (a-z, A-Z, 0-9)
    - Hyphens (but not at start or end)
    - Cannot be all digits
    - Cannot contain: \ / : * ? " < > |

.PARAMETER ComputerName
    The computer name to validate.

.PARAMETER AllowFQDN
    If specified, allows fully qualified domain names (e.g., server.contoso.com).

.PARAMETER AllowIPAddress
    If specified, allows IPv4 addresses.

.EXAMPLE
    Test-ValidComputerName -ComputerName "DC01"
    # Returns: $true

.EXAMPLE
    Test-ValidComputerName -ComputerName "server.contoso.com" -AllowFQDN
    # Returns: $true

.EXAMPLE
    Test-ValidComputerName -ComputerName "../../etc"
    # Returns: $false (path traversal attempt)

.OUTPUTS
    [bool] $true if valid, $false otherwise.
#>
function Test-ValidComputerName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [string]$ComputerName,

        [Parameter(Mandatory = $false)]
        [switch]$AllowFQDN,

        [Parameter(Mandatory = $false)]
        [switch]$AllowIPAddress
    )

    process {
        if ([string]::IsNullOrWhiteSpace($ComputerName)) {
            return $false
        }

        # Trim whitespace
        $name = $ComputerName.Trim()

        # Check for path traversal attempts
        if ($name -match '\.\.' -or $name -match '[\\/]') {
            Write-Log "[Test-ValidComputerName] Rejected: Path traversal pattern detected in '$name'"
            return $false
        }

        # Check for shell metacharacters
        if ($name -match '[;&|`$<>]') {
            Write-Log "[Test-ValidComputerName] Rejected: Shell metacharacters detected in '$name'"
            return $false
        }

        # Check for IPv6 addresses (IPv4 is handled in the dot-check below)
        if ($AllowIPAddress) {
            $ipResult = $null
            if ([System.Net.IPAddress]::TryParse($name, [ref]$ipResult)) {
                if ($ipResult.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
                    return $true
                }
            }
        }

        # Check if name contains dots (potential FQDN or IP)
        if ($name -match '\.') {
            # Reject IPv4 addresses unless -AllowIPAddress is set
            # This prevents IPs from being accepted via the FQDN path
            $ipv4Pattern = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
            if ($name -match $ipv4Pattern) {
                if ($AllowIPAddress) {
                    return $true
                }
                Write-Log "[Test-ValidComputerName] Rejected: IP address not allowed, got '$name'"
                return $false
            }

            if (-not $AllowFQDN) {
                Write-Log "[Test-ValidComputerName] Rejected: FQDN not allowed, got '$name'"
                return $false
            }

            # FQDN validation: series of labels separated by dots (at least one dot required)
            # Each label: 1-63 chars, alphanumeric + hyphen, no start/end hyphen
            $fqdnPattern = '^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
            if ($name -match $fqdnPattern) {
                return $true
            }
            Write-Log "[Test-ValidComputerName] Rejected: Invalid FQDN format '$name'"
            return $false
        }

        # NetBIOS/single-label name validation
        # Length: 1-15 characters
        if ($name.Length -lt 1 -or $name.Length -gt 15) {
            Write-Log "[Test-ValidComputerName] Rejected: Length out of range (1-15) for '$name'"
            return $false
        }

        # Must start with alphanumeric
        if ($name -notmatch '^[a-zA-Z0-9]') {
            Write-Log "[Test-ValidComputerName] Rejected: Must start with alphanumeric '$name'"
            return $false
        }

        # Must end with alphanumeric
        if ($name -notmatch '[a-zA-Z0-9]$') {
            Write-Log "[Test-ValidComputerName] Rejected: Must end with alphanumeric '$name'"
            return $false
        }

        # Only alphanumeric, hyphens, and underscores allowed
        if ($name -notmatch '^[a-zA-Z0-9_-]+$') {
            Write-Log "[Test-ValidComputerName] Rejected: Invalid characters in '$name'"
            return $false
        }

        # Cannot be all digits
        if ($name -match '^\d+$') {
            Write-Log "[Test-ValidComputerName] Rejected: Cannot be all digits '$name'"
            return $false
        }

        return $true
    }
}

#endregion

#region UNC Path Validation

<#
.SYNOPSIS
    Validates a UNC path for security.

.DESCRIPTION
    Validates UNC paths using whitelist approach to prevent:
    - Path traversal attacks (../)
    - Redirect to external hosts
    - Invalid path formats
    - Shell metacharacter injection

.PARAMETER UNCPath
    The UNC path to validate.

.PARAMETER AllowedHosts
    Optional array of allowed hostnames/IPs. If specified, only these hosts are allowed.

.PARAMETER AllowedShares
    Optional array of allowed share names. If specified, only these shares are allowed.

.EXAMPLE
    Test-ValidUNCPath -UNCPath "\\dc01\SYSVOL"
    # Returns: $true

.EXAMPLE
    Test-ValidUNCPath -UNCPath "\\dc01\..\C$"
    # Returns: $false (path traversal)

.EXAMPLE
    Test-ValidUNCPath -UNCPath "\\dc01\SYSVOL" -AllowedShares @("SYSVOL", "NETLOGON")
    # Returns: $true

.OUTPUTS
    [bool] $true if valid, $false otherwise.
#>
function Test-ValidUNCPath {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [string]$UNCPath,

        [Parameter(Mandatory = $false)]
        [string[]]$AllowedHosts,

        [Parameter(Mandatory = $false)]
        [string[]]$AllowedShares
    )

    process {
        if ([string]::IsNullOrWhiteSpace($UNCPath)) {
            return $false
        }

        # Must start with \\
        if ($UNCPath -notmatch '^\\\\') {
            Write-Log "[Test-ValidUNCPath] Rejected: Must start with \\\\ - '$UNCPath'"
            return $false
        }

        # Check for path traversal
        if ($UNCPath -match '\.\.') {
            Write-Log "[Test-ValidUNCPath] Rejected: Path traversal detected in '$UNCPath'"
            return $false
        }

        # Check for shell metacharacters
        if ($UNCPath -match '[;&|`<>]') {
            Write-Log "[Test-ValidUNCPath] Rejected: Shell metacharacters in '$UNCPath'"
            return $false
        }

        # Parse UNC path: \\host\share[\path]
        if ($UNCPath -notmatch '^\\\\([^\\]+)\\([^\\]+)') {
            Write-Log "[Test-ValidUNCPath] Rejected: Invalid UNC format '$UNCPath'"
            return $false
        }

        $uncHost = $Matches[1]
        $share = $Matches[2]

        # Validate host part
        if (-not (Test-ValidComputerName -ComputerName $uncHost -AllowFQDN -AllowIPAddress)) {
            Write-Log "[Test-ValidUNCPath] Rejected: Invalid host in '$UNCPath'"
            return $false
        }

        # Check allowed hosts if specified
        if ($AllowedHosts -and $AllowedHosts.Count -gt 0) {
            $hostAllowed = $false
            foreach ($allowedHost in $AllowedHosts) {
                if ($uncHost -ieq $allowedHost) {
                    $hostAllowed = $true
                    break
                }
            }
            if (-not $hostAllowed) {
                Write-Log "[Test-ValidUNCPath] Rejected: Host '$uncHost' not in allowed list"
                return $false
            }
        }

        # Validate share name (alphanumeric, hyphen, underscore, dot, dollar for admin shares)
        # Dots allowed for shares like "Data.2024" or "Backup.Archive"
        if ($share -notmatch '^[a-zA-Z0-9_.-]+\$?$') {
            Write-Log "[Test-ValidUNCPath] Rejected: Invalid share name '$share'"
            return $false
        }

        # Check allowed shares if specified
        if ($AllowedShares -and $AllowedShares.Count -gt 0) {
            $shareAllowed = $false
            foreach ($allowedShare in $AllowedShares) {
                if ($share -ieq $allowedShare) {
                    $shareAllowed = $true
                    break
                }
            }
            if (-not $shareAllowed) {
                Write-Log "[Test-ValidUNCPath] Rejected: Share '$share' not in allowed list"
                return $false
            }
        }

        return $true
    }
}

#endregion
