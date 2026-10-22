# The script and configuration files this check greps, in one place. It stood in three:
# the custom path, the domain scan and docs/04-Security-Checks.md, and all three differed -
# the documentation named neither .ps1 nor .psm1 nor .cnf, and .ps1 is both the most common
# logon script today and the biggest source of tier 2 noise. A reader could not tell what
# the section covered.
#
# .xml is deliberately not in here: it is the preference-file half of the check, queried
# separately because those files are parsed as XML rather than grepped.
$Script:CredentialScanExtensions = @(
    '*.txt', '*.bat', '*.ini', '*.conf', '*.cnf', '*.cmd', '*.vbs', '*.vbe', '*.kix',
    '*.ps1', '*.psm1',
    # The files a credential is written into besides scripts: the GPO comment file an
    # administrator types into, application and deployment configuration, an exported
    # registry file - an AutoAdminLogon .reg carries DefaultPassword in clear - and setup
    # information, a sysprep.inf's AdminPassword among it. Not GptTmpl.inf, which is
    # skipped by name (see $Script:CredentialScanSkippedFiles). Not *.pol: Registry.pol is
    # binary and is parsed for password values on its own.
    '*.cmtx', '*.config', '*.reg', '*.json', '*.yml', '*.yaml', '*.psd1', '*.inf',
    # A VNC viewer's connection file, which keeps the host and the VNC password - see
    # Get-VNCFileCredential.
    '*.vnc'
)

# Files the grep leaves out although their extension is on the list. Every GptTmpl.inf
# with a password policy names MinimumPasswordAge and friends, which would put a mention
# on every such policy in the domain, and the security template holds no secret of its
# own - its settings are read by the checks that own them.
$Script:CredentialScanSkippedFiles = @('GptTmpl.inf')

function Get-ReportedLineKey {
    <#
    .SYNOPSIS
    The whole line a regex match sits in, for the "already reported" bookkeeping.

    .DESCRIPTION
    The net use detector runs a regex over the file rather than over single lines, so what
    it has in hand is the command and not the line around it. The duplicate guard compares
    whole lines, and a key that is only part of one is a substring of every longer line
    that repeats it - which is how a second credential on such a line came to be dropped.

    .PARAMETER Lines
    The file's lines, as the caller split them.

    .PARAMETER Match
    The matched text to locate.

    .OUTPUTS
    [string] the trimmed line that contains the match, or the trimmed match if no line does.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string[]]$Lines,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Match
    )

    foreach ($line in @($Lines)) {
        if ($null -eq $line) { continue }
        if ($line.Contains($Match)) { return $line.Trim() }
    }
    # A match that spans a line break has no single line to key on; its own text is then
    # the honest key, and the old behaviour for that case.
    return $Match.Trim()
}

function Get-WinlogonCredential {
    <#
    .SYNOPSIS
    One entry per plaintext Winlogon password in a Group Policy Preferences Registry.xml.

    .DESCRIPTION
    Every DefaultPassword or AltDefaultPassword item under the Winlogon key that carries a
    value is returned, with the user and domain name of its own set. The scan used to keep
    one value of each name per file - the last one - so a file that deploys two accounts
    reported one of them. It also looked only at files that say AutoAdminLogon somewhere,
    and a GPO that deploys the user name and the password while AutoAdminLogon is switched
    on by another GPO puts the password into SYSVOL all the same.

    Names are paired within the element that holds the items, the file or a collection.
    A single user name there goes with every password in it; as many names as passwords
    pair in document order, which is how each set is written; otherwise the nearest name
    before the password is taken, or the first one after it.

    .PARAMETER XmlContent
    The parsed Registry.xml.

    .OUTPUTS
    PSCustomObject with UserName and Password, one per password item that has a value.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [xml]$XmlContent
    )

    function Select-SetValue {
        param($Candidates, $Anchor, $Passwords)
        $candidates = @($Candidates)
        if ($candidates.Count -eq 0) { return '' }
        if ($candidates.Count -eq @($Passwords).Count) {
            $rank = @($Passwords | Where-Object { $_.Position -lt $Anchor.Position }).Count
            return $candidates[$rank].Value
        }
        $before = @($candidates | Where-Object { $_.Position -lt $Anchor.Position })
        if ($before.Count -gt 0) { return $before[$before.Count - 1].Value }
        return $candidates[0].Value
    }

    $winlogonItems = @()
    $position = 0
    foreach ($prop in $XmlContent.GetElementsByTagName('Properties')) {
        $position++
        $keyPath = ([string]$prop.GetAttribute('key')).Trim('\')
        if ($keyPath -notmatch '\\Windows NT\\CurrentVersion\\Winlogon$') { continue }
        $valueName = [string]$prop.GetAttribute('name')
        if (-not ($valueName -match '^(?<set>(Alt)?)Default(?<part>UserName|Password|DomainName)$')) { continue }

        # The element that holds the Registry item - the file root or a collection. An
        # XmlNode enumerates its children, so it is compared by reference below, never
        # with -eq.
        $holder = $null
        if ($prop.ParentNode) { $holder = $prop.ParentNode.ParentNode }
        $winlogonItems += [PSCustomObject]@{
            Position = $position
            Holder   = $holder
            Set      = $Matches['set']
            Part     = $Matches['part']
            Value    = [string]$prop.GetAttribute('value')
        }
    }

    foreach ($passwordItem in @($winlogonItems | Where-Object { $_.Part -eq 'password' })) {
        if (-not $passwordItem.Value) { continue }
        $sameSet = @($winlogonItems | Where-Object {
            $_.Set -eq $passwordItem.Set -and [object]::ReferenceEquals($_.Holder, $passwordItem.Holder)
        })
        # An emptied password still marks its place in the sequence of sets.
        $passwords = @($sameSet | Where-Object { $_.Part -eq 'password' })
        $user   = Select-SetValue -Candidates @($sameSet | Where-Object { $_.Part -eq 'username' }) -Anchor $passwordItem -Passwords $passwords
        $domain = Select-SetValue -Candidates @($sameSet | Where-Object { $_.Part -eq 'domainname' }) -Anchor $passwordItem -Passwords $passwords

        # A name that already says its domain is not prefixed a second time.
        $fullName = $user
        if ($user -and $domain -and $user -notmatch '[\\@]') { $fullName = "$domain\$user" }

        [PSCustomObject]@{
            UserName = $fullName
            Password = $passwordItem.Value
        }
    }
}

function Get-VNCFileCredential {
    <#
    .SYNOPSIS
    The VNC passwords in a file a VNC product writes, decrypted.

    .DESCRIPTION
    A VNC viewer's connection file (.vnc) holds the host and, when the connection was saved
    with it, the password; the .ini of UltraVNC and TightVNC holds the server's. Both write
    it as 16 hex digits (18 for UltraVNC), DES-encrypted with the key every VNC
    installation shares - see ConvertFrom-VNCPassword. The generic grep reported such a line
    as a password assignment and showed the hex, which is not the password.

    Only a .vnc file, or an .ini whose name says VNC, is read this way: elsewhere sixteen
    hex digits after "Password=" are as likely a hash or a key.

    .PARAMETER FileName
    The file's name, which decides whether it is read.

    .PARAMETER Lines
    The file's lines.

    .OUTPUTS
    PSCustomObject with Line (the trimmed line), Setting, VNCHost and Password, one per
    password line that decrypts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Lines
    )

    if ($FileName -notmatch '(?i)(\.vnc$|vnc[^\\]*\.ini$)') { return }

    $vncHost = $null
    foreach ($line in @($Lines)) {
        if ([string]$line -match '^\s*Host\s*=\s*(\S+)') { $vncHost = $Matches[1]; break }
    }

    foreach ($line in @($Lines)) {
        $trimmed = ([string]$line).Trim()
        if ($trimmed -notmatch '(?i)^(Password|PasswordViewOnly|ControlPassword|passwd|passwd2)\s*=\s*([0-9A-F]{16}([0-9A-F]{2})?)$') { continue }
        $setting = $Matches[1]
        $password = ConvertFrom-VNCPassword -Hex $Matches[2]
        if ($null -eq $password) { continue }
        [PSCustomObject]@{
            Line     = $trimmed
            Setting  = $setting
            VNCHost  = $vncHost
            Password = $password
        }
    }
}

function Get-RegistryPasswordCredential {
    <#
    .SYNOPSIS
    The registry values a policy writes whose name says they hold a password, as
    credential objects.

    .DESCRIPTION
    A GPO that deploys a string value named like a password - Password, ProxyPassword,
    ServiceAccountPassword, Pwd - puts that password into SYSVOL in clear text, in
    Registry.pol for an Administrative Template and in Registry.xml for a preference item.

    Only string types count: a DWORD such as RequirePassword or PasswordComplexity
    switches a setting and holds no secret. The Winlogon DefaultPassword and
    AltDefaultPassword are left out, because Get-WinlogonCredential reports them with the
    account they belong to. So are a preference item switched off in the editor, one that
    deletes the value, and the "**del." pseudo-values of Registry.pol.

    The password of a VNC product (Test-VNCPasswordRecord) is decrypted - see
    ConvertFrom-VNCPassword - and returned as a VNC Password, whatever its type: TightVNC
    and TigerVNC store it as REG_BINARY, RealVNC as hex in a REG_SZ. It used to show as the
    hex it is stored as, which is not the password, or not at all.

    .PARAMETER Records
    Records from Parse-PRegRecords or Parse-RegistryXml.

    .PARAMETER FilePath
    The file the records were read from.

    .OUTPUTS
    PSCustomObject with CredentialType, FilePath, RegistryValue and Password, one per
    matching value.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        $Records,

        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    foreach ($record in @($Records)) {
        if (-not $record) { continue }
        $valueName = [string]$record.ValueName

        if (Test-VNCPasswordRecord -Record $record) {
            if ($record.PSObject.Properties['Disabled'] -and $record.Disabled) { continue }
            if ($record.PSObject.Properties['Action'] -and $record.Action -eq 'D') { continue }
            # Registry.pol hands a REG_BINARY on as bytes, Registry.xml writes it as hex.
            $vncPassword = $null
            if ($record.PSObject.Properties['ValueBytes'] -and $record.ValueBytes) {
                $vncPassword = ConvertFrom-VNCPassword -Bytes $record.ValueBytes
            } elseif ($record.ValueString) {
                $vncPassword = ConvertFrom-VNCPassword -Hex ([string]$record.ValueString)
            }
            if ($null -ne $vncPassword) {
                [PSCustomObject]@{
                    CredentialType = 'VNC Password'
                    FilePath       = $FilePath
                    RegistryValue  = (@($record.Hive, $record.Key, $valueName) | Where-Object { $_ }) -join '\'
                    Password       = $vncPassword
                }
                continue
            }
        }

        if ($valueName -notmatch '(?i)(password|passwd|pwd)$' -or $valueName -match '^\*\*') { continue }
        # Registry.xml carries the type as the name, Registry.pol as the number (UInt32):
        # REG_SZ 1, REG_EXPAND_SZ 2, REG_MULTI_SZ 7.
        $isString = if ($record.Type -is [string]) {
            $record.Type -match '^REG_(EXPAND_|MULTI_)?SZ$'
        } else {
            @(1, 2, 7) -contains [int64]$record.Type
        }
        if (-not $isString -or -not $record.ValueString) { continue }
        if ($record.PSObject.Properties['Disabled'] -and $record.Disabled) { continue }
        if ($record.PSObject.Properties['Action'] -and $record.Action -eq 'D') { continue }
        if ([string]$record.Key -match '\\Windows NT\\CurrentVersion\\Winlogon\\?$' -and $valueName -match '^(Alt)?DefaultPassword$') { continue }

        [PSCustomObject]@{
            CredentialType = 'Registry Value'
            FilePath       = $FilePath
            RegistryValue  = (@($record.Hive, $record.Key, $valueName) | Where-Object { $_ }) -join '\'
            Password       = [string]$record.ValueString
        }
    }
}

function Get-UnattendCredential {
    <#
    .SYNOPSIS
    The passwords in a Windows answer file (unattend.xml, autounattend.xml and the like).

    .DESCRIPTION
    An answer file configures Windows Setup, and four of its settings carry a password:
    the built-in administrator's (UserAccounts/AdministratorPassword), a local account's
    (LocalAccounts/LocalAccount/Password), the automatic logon's (AutoLogon/Password) and
    the account that joins the machine to the domain (UnattendedJoin,
    Identification/Credentials).

    Windows SIM can "hide" the first three, and Microsoft says plainly that it "does not
    provide encryption or other security benefits": the value becomes Base64 of the
    UTF-16LE password with the setting's name appended - AdministratorPassword or Password -
    and PlainText becomes false. Microsoft's own example decodes to "Password12346Password".
    The domain account cannot be hidden at all: "Domain passwords ... may still be available
    as clear text in an answer file."

    Recognised by its root element - unattend - and not by its file name, which is
    whatever the deployment chose.

    .PARAMETER XmlContent
    The parsed XML file.

    .OUTPUTS
    PSCustomObject with UserName, Password and Setting, one per password that has a value.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [xml]$XmlContent
    )

    $root = $XmlContent.DocumentElement
    if (-not $root -or $root.LocalName -ne 'unattend') { return }

    # By local name throughout: every element sits in the unattend namespace, and the
    # components declare wcm and xsi prefixes of their own.
    $child = {
        param($node, [string]$name)
        if (-not $node) { return $null }
        @($node.ChildNodes | Where-Object { $_.LocalName -eq $name })[0]
    }
    $reveal = {
        param($passwordNode, [string]$suffix)
        if (-not $passwordNode) { return $null }
        $valueNode = & $child $passwordNode 'Value'
        $text = if ($valueNode) { [string]$valueNode.InnerText } else { [string]$passwordNode.InnerText }
        if ([string]::IsNullOrEmpty($text)) { return $null }

        $plainNode = & $child $passwordNode 'PlainText'
        if ($plainNode -and ([string]$plainNode.InnerText).Trim() -ieq 'false') {
            try {
                $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($text))
                if ($decoded.EndsWith($suffix) -and $decoded.Length -gt $suffix.Length) {
                    $decoded = $decoded.Substring(0, $decoded.Length - $suffix.Length)
                }
                return $decoded
            } catch {
                # Marked hidden and not Base64: shown as it stands rather than dropped.
                return $text
            }
        }
        return $text
    }
    $all = { param([string]$name) @($root.SelectNodes("//*[local-name()='$name']")) }

    # The local accounts are named .\name: the machine being set up owns them, and the
    # domain account of the same name - which Resolve-CredentialAccount would otherwise
    # look up - is not the account they mean. The administrator password belongs to the
    # built-in account whatever it is called.
    foreach ($node in (& $all 'AdministratorPassword')) {
        $password = & $reveal $node 'AdministratorPassword'
        if ($null -eq $password) { continue }
        [PSCustomObject]@{ UserName = '.\Administrator'; Password = $password; Setting = 'UserAccounts/AdministratorPassword' }
    }

    foreach ($node in (& $all 'LocalAccount')) {
        $password = & $reveal (& $child $node 'Password') 'Password'
        if ($null -eq $password) { continue }
        $nameNode = & $child $node 'Name'
        $userName = if ($nameNode -and $nameNode.InnerText) { ".\$($nameNode.InnerText)" } else { '' }
        [PSCustomObject]@{ UserName = $userName; Password = $password; Setting = 'LocalAccounts/LocalAccount' }
    }

    foreach ($node in (& $all 'AutoLogon')) {
        $password = & $reveal (& $child $node 'Password') 'Password'
        if ($null -eq $password) { continue }
        $userNode = & $child $node 'Username'
        $domainNode = & $child $node 'Domain'
        $userName = if ($userNode) { [string]$userNode.InnerText } else { '' }
        # With a domain the automatic logon is a domain account; without one, a local one.
        if ($userName) {
            if ($domainNode -and $domainNode.InnerText) { $userName = "$($domainNode.InnerText)\$userName" }
            else { $userName = ".\$userName" }
        }
        [PSCustomObject]@{ UserName = $userName; Password = $password; Setting = 'AutoLogon' }
    }

    foreach ($node in (& $all 'Credentials')) {
        # The domain join account, under UnattendedJoin's Identification. Credentials
        # elsewhere in an answer file are not a password setting.
        if (-not $node.ParentNode -or $node.ParentNode.LocalName -ne 'Identification') { continue }
        $passwordNode = & $child $node 'Password'
        if (-not $passwordNode -or [string]::IsNullOrEmpty([string]$passwordNode.InnerText)) { continue }
        $userNode = & $child $node 'Username'
        $domainNode = & $child $node 'Domain'
        $userName = if ($userNode) { [string]$userNode.InnerText } else { '' }
        if ($domainNode -and $domainNode.InnerText -and $userName) { $userName = "$($domainNode.InnerText)\$userName" }
        [PSCustomObject]@{ UserName = $userName; Password = [string]$passwordNode.InnerText; Setting = 'UnattendedJoin/Identification/Credentials' }
    }
}

function Get-CredentialExposure {
    <#
    .SYNOPSIS
    Detects credential exposure in SYSVOL (GPP Passwords), NETLOGON scripts, or custom paths.

    .DESCRIPTION
    Performs comprehensive credential leakage detection:
    - Group Policy Preferences (GPP) passwords (cpassword attribute, MS14-025)
    - AutoAdminLogon passwords in Registry.xml (plaintext!)
    - VNC passwords in .vnc connection files, VNC .ini files and registry values, decrypted
      (one DES key shared by every VNC installation)
    - NETLOGON/SYSVOL scripts with hardcoded credentials
    - VBScript Encoded (.vbe) file decoding
    - Custom UNC paths or local directories

    GPP Password Decryption:
    Microsoft published the AES-256 key used for cpassword encryption in MS14-025.
    All GPP passwords found will be automatically decrypted.

    Uses a two-tier detection system (Snaffler-inspired):
    - Tier 1 (Finding/Red): High-confidence patterns with extractable values
    - Tier 2 (Hint/Yellow): Lower-confidence patterns needing manual review

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .PARAMETER Path
    Custom UNC path or local directory to scan instead of SYSVOL/NETLOGON.
    When specified, skips LDAP connection and domain-based scanning.
    Supports UNC paths (\\server\share) and local paths (C:\Scripts).

    .EXAMPLE
    Get-CredentialExposure
    Scans SYSVOL/NETLOGON of the current or specified domain.

    .EXAMPLE
    Get-CredentialExposure -Domain "contoso.com" -Credential (Get-Credential)
    Scans SYSVOL/NETLOGON with explicit credentials.

    .EXAMPLE
    Get-CredentialExposure -Path "\\fileserver\scripts"
    Scans a custom UNC path for credentials (uses current user context).

    .EXAMPLE
    Get-CredentialExposure -Path "\\fileserver\scripts" -Credential (Get-Credential)
    Scans a custom UNC path with explicit credentials for authentication.

    .EXAMPLE
    Get-CredentialExposure -Path "C:\AdminScripts"
    Scans a local directory for credentials.

    .NOTES
    Category: Creds
    Author: Alexander Sturz (@_61106960_)
    Reference:
    - MS14-025: https://support.microsoft.com/en-us/kb/2962486
    - GPP AES Key published by Microsoft in 2014
    - Snaffler: https://github.com/SnaffCon/Snaffler
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [string]$Path
    )

    begin {
        Write-Log "[Get-CredentialExposure] Starting check"
    }

    process {
        try {
            # Mode 1: Custom Path scanning (standalone mode)
            if ($Path) {
                Show-Line "Scanning Custom Path for Credentials" -Class "Note"
                Show-Line "Target: $Path" -Class "Hint"
                Show-EmptyLine

                # Check if UNC path and credentials provided - use temporary drive mapping
                $useTempDrive = $false
                $tempDriveLetter = $null
                $scanPath = $Path

                if ($Path -match '^\\\\' -and $Credential) {
                    Write-Log "[Get-CredentialExposure] UNC path with credentials - creating temporary drive mapping"

                    # Find an available drive letter (starting from Z: going down)
                    $usedDrives = (Get-PSDrive -PSProvider FileSystem).Name
                    $tempDriveLetter = ([char[]](90..65) | Where-Object { [string]$_ -notin $usedDrives } | Select-Object -First 1)

                    if ($tempDriveLetter) {
                        try {
                            $null = New-PSDrive -Name $tempDriveLetter -PSProvider FileSystem -Root $Path -Credential $Credential -ErrorAction Stop
                            $scanPath = "${tempDriveLetter}:\"
                            $useTempDrive = $true
                            Write-Log "[Get-CredentialExposure] Mapped $Path to ${tempDriveLetter}:"
                        }
                        catch {
                            Show-Line "Failed to connect to $Path with provided credentials: $_" -Class "Finding"
                            return
                        }
                    }
                    else {
                        Show-Line "No available drive letter for UNC mapping" -Class "Finding"
                        return
                    }
                }
                elseif ($Path -match '^\\\\') {
                    # UNC path without credentials - test access with current user
                    if (-not (Test-Path $Path)) {
                        Show-Line "Cannot access path: $Path (try using -Credential for authentication)" -Class "Finding"
                        return
                    }
                }
                elseif (-not (Test-Path $Path)) {
                    Show-Line "Cannot access path: $Path" -Class "Finding"
                    return
                }

                try {

                # Define patterns for custom path scan (same as SYSVOL scan)
                $tier1Patterns = @(
                    @{ Pattern = 'passw(or)?d\s*[=:]\s*["''][^"'']{3,}["'']'; Description = "Password assignment (quoted)" },
                    @{ Pattern = 'passw(or)?d\s*[=:]\s*(?!["''])\S{3,}'; Description = "Password assignment (unquoted)" },
                    @{ Pattern = '[-/]passw(or)?d\s+\S{3,}'; Description = "Password parameter" },
                    @{ Pattern = 'psexec.{0,100}\s-p\s+\S+'; Description = "PSExec with password" },
                    @{ Pattern = 'schtasks.{0,300}/rp\s+\S+'; Description = "Schtasks with password" },
                    @{ Pattern = 'net\s+user\s+\S+\s+\S+\s+/add'; Description = "Net user creation" },
                    @{ Pattern = 'cmdkey\s+/add:[^\s]+.*?/pass:\S+'; Description = "Cmdkey with password" },
                    @{ Pattern = 'connectionstring.{1,200}passw'; Description = "DB connection string" },
                    @{ Pattern = 'ConvertTo-SecureString\s+["''][^"'']+["'']'; Description = "SecureString conversion" },
                    @{ Pattern = 'api[_-]?key\s*[=:]\s*["''][^"'']{10,}["'']'; Description = "API key assignment" },
                    @{ Pattern = '\$cred(ential)?\s*=.*password'; Description = "Credential variable" },
                    # The short forms, which carry a value just as often in a script as the
                    # spelled-out word does. Get-PasswordInDescription has had them for a while;
                    # this module, with otherwise the same lists, never did - so "pwd=Hunter2"
                    # was at best a tier 2 mention of the word beside it, and behind an exclusion
                    # it was nothing at all.
                    #
                    # Last in the list on purpose: the loop takes the first pattern that matches
                    # and names the finding after it, and "/pass:Hunter2" is part of a cmdkey
                    # line that has a pattern of its own with a better name.
                    @{ Pattern = 'pwd\s*[=:]\s*\S{3,}'; Description = "Pwd assignment" },
                    @{ Pattern = 'pw\s*[=:]\s*\S{3,}'; Description = "PW assignment" },
                    @{ Pattern = '\bpass\s*[=:]\s*\S{3,}'; Description = "Pass assignment" },
                    @{ Pattern = 'kennwort\s*[=:]\s*\S{3,}'; Description = "Kennwort assignment (German)" },
                    @{ Pattern = 'passord\s*[=:]\s*\S{3,}'; Description = "Passord assignment (Norwegian)" }
                )
                $tier2Patterns = @(
                    # Ordered most specific first: the list is first-match-wins, and the generic
                    # "passw(or)?d" also matches "passwd" and an XML password element, so those two
                    # descriptions could never be produced while it came first.
                    @{ Pattern = "<passw[^>]*>[^<]+</passw"; Description = "XML password element" },
                    @{ Pattern = "passwd"; Description = "Passwd mention" },
                    @{ Pattern = "passw(or)?d"; Description = "Password mention" },
                    @{ Pattern = "credential"; Description = "Credential mention" },
                    @{ Pattern = "(secret|token)\s*[=:]\s*\S{5,}"; Description = "Secret/token assignment" }
                )
                $exclusionPatterns = @(
                    'passw(or)?d\s*(policy|policies|requirement|guideline)',
                    'passw(or)?d\s+(must|should|cannot|shall)\s+(be|contain|have|include)',
                    'passw(or)?d\s+(length|complexity|history|age|expir)',
                    'passw(or)?d\s+(reset|change|recover|forgot)',
                    '(minimum|maximum)\s+passw(or)?d',
                    '(set|change|update|reset)\s+(your|the|a)\s+passw(or)?d',
                    '^\s*(REM|::|''|#)\s+.*passw',
                    'echo\s+.*passw(or)?d.*help',
                    'usage:.*passw(or)?d',
                    'Enter\s+(your\s+)?passw(or)?d',
                    'passw(or)?d\s+prompt'
                )

                # These describe the VALUE rather than the prose around it: the syntax is an
                # assignment, but what was assigned is a row of asterisks or an
                # angle-bracket placeholder, so there is no credential whatever the pattern
                # says. That makes them the one list allowed to silence a line outright -
                # the exclusions above only decide against a bare mention. Two of them used
                # to sit in that list, where they did the right thing for the wrong reason.
                # Same split as Get-PasswordInDescription, which needed it first.
                $placeholderPatterns = @(
                    'passw(or)?d\s*[=:]\s*["'']?\*+["'']?\s*$',
                    'passw(or)?d\s*[=:]\s*["'']?<[^>]+>',
                    'pwd\s*[=:]\s*["'']?\*+["'']?\s*$',
                    'pwd\s*[=:]\s*["'']?<[^>]+>',
                    '[-/]pass(word)?[:\s]+["'']?\*+["'']?\s*$',
                    '[-/]pass(word)?[:\s]+["'']?<[^>]+>'
                )
                $netUsePattern = "net use (?<devicename>(\w|\*|LPT\d):?) (?<path>\\\\?.*?)(( (?<user>/user:((?<domain>[\w.]*)\\)?(?<username>\S*)))|( /(p(ersistent)?|P(ERSISTENT)?):(no|NO|yes|YES))|( (?<password>(?!/)\S*))|( /(delete|DELETE))|( /(savecred|SAVECRED))|( /(smartcard|SMARTCARD)))+"

                # Scan XML files for GPP passwords and AutoAdminLogon
                $xmlFiles = Get-ChildItem -Force -Path $scanPath -Recurse -Include "*.xml" -ErrorAction SilentlyContinue
                if (@($xmlFiles).Count -gt 0) {
                    Write-Log "[Get-CredentialExposure] Found $(@($xmlFiles).Count) XML file(s) in custom path"
                    foreach ($xmlFile in $xmlFiles) {
                        try {
                            [xml]$xmlContent = Get-Content -Path $xmlFile.Fullname -ErrorAction Stop
                            $fileName = Split-Path $xmlFile.FullName -Leaf

                            if ($xmlContent.InnerXml -match 'cpassword') {
                                $xmlContent.GetElementsByTagName('Properties') | ForEach-Object {
                                    if ($_.cpassword -and $_.cpassword -ne '') {
                                        $cpassword = $_.cpassword
                                        $decryptedPassword = ConvertFrom-GPPPassword -EncryptedPassword $cpassword
                                        $username = ""
                                        if ($_.userName) { $username = $_.userName }
                                        elseif ($_.accountName) { $username = $_.accountName }
                                        elseif ($_.newName) { $username = $_.newName }
                                        elseif ($_.runAs) { $username = $_.runAs }
                                        # Create credential object for proper display
                                        $credObj = [PSCustomObject]@{
                                            CredentialType = "GPP Password"
                                            FilePath = $xmlFile.Fullname
                                            UserName = $username
                                            Password = $decryptedPassword
                                        }
                                        # What the name stands for in the directory - see the domain scan below.
                                        $accountInAD = Resolve-CredentialAccount -UserName $username -FileName $fileName -FileTime $xmlFile.LastWriteTime
                                        if ($accountInAD) { $credObj | Add-Member -NotePropertyName 'accountInAD' -NotePropertyValue $accountInAD -Force }
                                        Show-Line "Found GPP credential" -Class Finding
                                        $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPPCredential' -Force
                                        $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'GPP Password' -Force
                                        Show-Object $credObj -Class Finding
                                    }
                                }
                            }
                            # Its own if, not an elseif of the cpassword branch above. A
                            # Registry.xml that carries both - GPP registry items with a
                            # cpassword and the Winlogon values - reported only the first,
                            # and whoever rolls out AutoAdminLogon by GPP usually rolls out
                            # several items in one file. The plaintext password was the
                            # heavier of the two findings, and the one that went missing.
                            #
                            # Every Winlogon password in the file, each with its own account -
                            # see Get-WinlogonCredential.
                            if ($fileName -match 'Registry\.xml') {
                                foreach ($winlogonCredential in @(Get-WinlogonCredential -XmlContent $xmlContent)) {
                                    $fullUsername = $winlogonCredential.UserName
                                    # Create credential object for proper display
                                    $credObj = [PSCustomObject]@{
                                        CredentialType = "AutoAdminLogon"
                                        FilePath = $xmlFile.Fullname
                                        UserName = $fullUsername
                                        Password = $winlogonCredential.Password
                                    }
                                    $accountInAD = Resolve-CredentialAccount -UserName $fullUsername -FileName $fileName -FileTime $xmlFile.LastWriteTime
                                    if ($accountInAD) { $credObj | Add-Member -NotePropertyName 'accountInAD' -NotePropertyValue $accountInAD -Force }
                                    Show-Line "Found AutoAdminLogon credential" -Class Finding
                                    $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPPCredential' -Force
                                    $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'AutoAdminLogon' -Force
                                    Show-Object $credObj -Class Finding
                                }

                                # Any other value the preference item writes whose name says
                                # it is a password - see Get-RegistryPasswordCredential.
                                foreach ($credObj in @(Get-RegistryPasswordCredential -Records @(Parse-RegistryXml -XmlFilePath $xmlFile.FullName) -FilePath $xmlFile.FullName)) {
                                    Show-Line $(if ($credObj.CredentialType -eq 'VNC Password') { 'Found a VNC password in a registry value deployed by Group Policy' } else { 'Found a password in a registry value deployed by Group Policy' }) -Class Finding
                                    $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPPCredential' -Force
                                    $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue ([string]$credObj.CredentialType) -Force
                                    Show-Object $credObj -Class Finding
                                }
                            }

                            # A Windows answer file - see Get-UnattendCredential.
                            foreach ($unattendCredential in @(Get-UnattendCredential -XmlContent $xmlContent)) {
                                $credObj = [PSCustomObject]@{
                                    CredentialType  = "Unattend Answer File"
                                    FilePath        = $xmlFile.Fullname
                                    UnattendSetting = $unattendCredential.Setting
                                    UserName        = $unattendCredential.UserName
                                    Password        = $unattendCredential.Password
                                }
                                $accountInAD = Resolve-CredentialAccount -UserName $unattendCredential.UserName -FileName $fileName -FileTime $xmlFile.LastWriteTime
                                if ($accountInAD) { $credObj | Add-Member -NotePropertyName 'accountInAD' -NotePropertyValue $accountInAD -Force }
                                Show-Line "Found a password in a Windows answer file" -Class Finding
                                $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPPCredential' -Force
                                $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'Unattend' -Force
                                Show-Object $credObj -Class Finding
                            }
                        }
                        catch {
                            Write-Log "[Get-CredentialExposure] Error parsing $($xmlFile.Fullname): $_"
                        }
                    }
                }

                # And the Administrative Template files, which are binary and which no other
                # pass reads for credentials.
                foreach ($polFile in @(Get-ChildItem -Force -Path $scanPath -Recurse -Include 'Registry.pol' -ErrorAction SilentlyContinue)) {
                    try {
                        $polHive = if ($polFile.FullName -match '\\Machine\\') { 'HKLM' } else { 'HKCU' }
                        foreach ($credObj in @(Get-RegistryPasswordCredential -Records @(Parse-PRegRecords -PolFilePath $polFile.FullName -Hive $polHive) -FilePath $polFile.FullName)) {
                            Show-Line $(if ($credObj.CredentialType -eq 'VNC Password') { 'Found a VNC password in a registry value deployed by Group Policy' } else { 'Found a password in a registry value deployed by Group Policy' }) -Class Finding
                            $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPPCredential' -Force
                            $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue ([string]$credObj.CredentialType) -Force
                            Show-Object $credObj -Class Finding
                        }
                    }
                    catch {
                        Write-Log "[Get-CredentialExposure] Error parsing $($polFile.FullName): $_"
                    }
                }

                # Scan script/config files
                $searchExtensions = $Script:CredentialScanExtensions
                $files = @(Get-ChildItem -Force -Path $scanPath -Recurse -Include $searchExtensions -ErrorAction SilentlyContinue |
                    Where-Object { $Script:CredentialScanSkippedFiles -notcontains $_.Name })

                if (@($files).Count -gt 0) {
                    Write-Log "[Get-CredentialExposure] Found $(@($files).Count) script/config file(s) in custom path"
                    foreach ($file in $files) {
                        try {
                            $fileContent = $null
                            if ($file.Extension -eq ".vbe") {
                                try {
                                    $encodedContent = Get-Content -Path $file.FullName -Raw -ErrorAction Stop
                                    $fileContent = ConvertFrom-VBE -EncodedScript $encodedContent
                                    Write-Log "[Get-CredentialExposure] Decoded VBE file: $($file.Name)"
                                }
                                catch {
                                    Write-Log "[Get-CredentialExposure] Failed to decode VBE file: $($file.Name)"
                                    continue
                                }
                            }
                            else {
                                $fileContent = Get-Content -Path $file.FullName -Raw -ErrorAction Stop
                            }
                            if (-not $fileContent) { continue }

                            $lines = $fileContent -split "`n"
                            $reportedLines = @{}

                            # VNC passwords, decrypted - see Get-VNCFileCredential. Their
                            # lines are reported, so the grep below does not show the hex.
                            foreach ($vncCredential in @(Get-VNCFileCredential -FileName $file.Name -Lines $lines)) {
                                $credObj = [PSCustomObject]@{
                                    CredentialType = 'VNC Password'
                                    FilePath       = $file.FullName
                                    VNCHost        = $vncCredential.VNCHost
                                    VNCSetting     = $vncCredential.Setting
                                    Password       = $vncCredential.Password
                                }
                                Show-Line "Found a VNC password" -Class Finding
                                $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SYSVOLCredential' -Force
                                $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'VNC Password' -Force
                                Show-Object $credObj -Class Finding
                                $reportedLines[$vncCredential.Line] = $true
                            }

                            # Check net use credentials
                            $netUseMatches = [Regex]::Matches($fileContent, $netUsePattern)
                            foreach ($match in $netUseMatches) {
                                $foundUsername = $match.Groups["username"].Value
                                $foundPassword = $match.Groups["password"].Value
                                $foundDomain = $match.Groups["domain"].Value
                                if ($foundUsername -and $foundPassword) {
                                    $fullUser = if ($foundDomain) { "$foundDomain\$foundUsername" } else { $foundUsername }
                                    # Create credential object for proper display
                                    $credObj = [PSCustomObject]@{
                                        CredentialType = "Net Use"
                                        FilePath = $file.FullName
                                        UserName = $fullUser
                                        Password = $foundPassword
                                    }
                                    $accountInAD = Resolve-CredentialAccount -UserName $fullUser -FileName $file.Name -FileTime $file.LastWriteTime
                                    if ($accountInAD) { $credObj | Add-Member -NotePropertyName 'accountInAD' -NotePropertyValue $accountInAD -Force }
                                    Show-Line "Found net use credential" -Class Finding
                                    # SYSVOLCredential, as in the domain scan: a net use
                                    # line is a script line. GPPCredential is the preference
                                    # files' section, and its help text was the wrong one.
                                    $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SYSVOLCredential' -Force
                                    $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'Net Use' -Force
                                    Show-Object $credObj -Class Finding
                                    # The whole line, not the match. The guard below compares
                                    # lines, and a net use match covers only the command - as
                                    # a key it was a substring of any later line that
                                    # repeated the same command with more on it, and that
                                    # line was then dropped with whatever else it carried.
                                    $reportedLines[(Get-ReportedLineKey -Lines $lines -Match $match.Value)] = $true
                                }
                            }

                            # Two-tier detection on each line
                            foreach ($line in $lines) {
                                $trimmedLine = $line.Trim()
                                if ([string]::IsNullOrWhiteSpace($trimmedLine)) { continue }

                                # One report per line, decided by the line itself.
                                #
                                # This was a substring test, and before that a -like, where a
                                # reported password containing * or ? matched unrelated later
                                # lines. Contains fixed the wildcard half and kept the
                                # asymmetry: a short key is a substring of every longer line
                                # that contains it, so a second line carrying a different
                                # credential was dropped because an earlier one was a prefix
                                # of it. Every key is a whole trimmed line now, which makes
                                # equality the right test - and the net use branch above
                                # stores the line it matched in rather than the match.
                                if ($reportedLines.ContainsKey($trimmedLine)) { continue }

                                # A masked or bracketed value is not a credential however
                                # much the syntax around it looks like an assignment.
                                $isPlaceholder = $false
                                foreach ($phPattern in $placeholderPatterns) {
                                    if ($trimmedLine -imatch $phPattern) { $isPlaceholder = $true; break }
                                }
                                if ($isPlaceholder) { continue }

                                # Tier 1 is decided before the prose exclusions are
                                # consulted - see the longer note on the domain scan path,
                                # which carries the same two steps in the same order.
                                $tier1Match = $false
                                foreach ($pattern in $tier1Patterns) {
                                    if ($trimmedLine -match $pattern.Pattern) {
                                        # Create credential object for proper display
                                        $credObj = [PSCustomObject]@{
                                            CredentialType = $pattern.Description
                                            FilePath = $file.FullName
                                            MatchedLine = $trimmedLine
                                        }
                                        # Pattern hits in a script file are SYSVOLCredential, the same as in the
                                        # domain scan. Tagging them GPPCredential here routed them to the wrong help text.
                                        Show-Line "Found credential pattern" -Class Finding
                                        $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SYSVOLCredential' -Force
                                        $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue $pattern.Description -Force
                                        Show-Object $credObj -Class Finding
                                        $reportedLines[$trimmedLine] = $true
                                        $tier1Match = $true
                                        break
                                    }
                                }
                                if ($tier1Match) { continue }

                                # No assignment on this line, so wording that reads like
                                # policy text is what it looks like - and here it does mean
                                # the line can be dropped.
                                $isExcluded = $false
                                foreach ($exclusion in $exclusionPatterns) {
                                    if ($trimmedLine -match $exclusion) { $isExcluded = $true; break }
                                }
                                if ($isExcluded) { continue }

                                foreach ($pattern in $tier2Patterns) {
                                    if ($trimmedLine -match $pattern.Pattern) {
                                        # Create credential object for proper display (lower severity)
                                        $credObj = [PSCustomObject]@{
                                            CredentialType = "$($pattern.Description) (needs review)"
                                            FilePath = $file.FullName
                                            MatchedLine = $trimmedLine
                                        }
                                        Show-Line "Found possible sensitive information" -Class Hint
                                            $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SYSVOLCredential' -Force
                                            $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue $pattern.Description -Force
                                            Show-Object $credObj -Class Hint
                                        $reportedLines[$trimmedLine] = $true
                                        break
                                    }
                                }
                            }
                        }
                        catch {
                            Write-Log "[Get-CredentialExposure] Error analyzing $($file.Name): $_"
                        }
                    }
                }
                else {
                    Show-Line "No script/config files found in path" -Class "Note"
                }

                }
                finally {
                    # Cleanup: Remove temporary drive mapping if created (always runs, even on error)
                    if ($useTempDrive -and $tempDriveLetter) {
                        try {
                            Remove-PSDrive -Name $tempDriveLetter -Force -ErrorAction SilentlyContinue
                            Write-Log "[Get-CredentialExposure] Removed temporary drive mapping ${tempDriveLetter}:"
                        }
                        catch {
                            Write-Log "[Get-CredentialExposure] Failed to remove temporary drive: $_"
                        }
                    }
                }

                return
            }

            # Mode 2: Domain-based SYSVOL/NETLOGON scanning
            # Ensure LDAP connection (displays error if needed). The three parameters it
            # takes, named one by one rather than splatted from $PSBoundParameters: -Path is
            # also a parameter of this check, and an empty string for it is falsy enough to
            # fall past the Mode 1 branch above while still sitting in $PSBoundParameters -
            # which made the splat throw here instead of scanning the domain.
            $connectionParams = @{}
            if ($PSBoundParameters.ContainsKey('Domain'))     { $connectionParams['Domain'] = $Domain }
            if ($PSBoundParameters.ContainsKey('Server'))     { $connectionParams['Server'] = $Server }
            if ($PSBoundParameters.ContainsKey('Credential')) { $connectionParams['Credential'] = $Credential }

            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            $dcServer = $Script:LDAPContext.Server

            # ===== Single SYSVOL scan: Mount once, enumerate once, analyze all =====
            Show-SubHeader "Searching for credentials in Group Policy files..." -ObjectType "GPPCredential"

            # Pre-load GPO linkage and name mapping (LDAP queries - must run before SMB block)
            $gpoLinkage = Get-GPOLinkage
            $gpoNameMap = @{}
            $connectionParams = @{}
            if ($Domain) { $connectionParams['Domain'] = $Domain }
            if ($Server) { $connectionParams['Server'] = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }
            $allGPOs = @(Get-DomainGPO @connectionParams)
            foreach ($gpo in $allGPOs) {
                if ($gpo.Name) {
                    $gpoNameMap[$gpo.Name.ToUpper()] = $gpo.DisplayName
                }
            }

            # Track SYSVOL access status
            $Script:sysvolAccessible = $false

            $domainFQDN = $Script:LDAPContext.Domain
            Invoke-SMBAccess -Description "Scanning SYSVOL for credentials and sensitive information" -ScriptBlock {
                $sysvolBase = "\\$dcServer\SYSVOL\$domainFQDN"
                $gppFindingsCount = 0
                $sysvolFindingsCount = 0

                if (-not (Test-Path $sysvolBase)) {
                    # Reported once, after the SMB block, where Test-SysvolAccessible can tell
                    # "not reachable at all" from "reachable but this read failed". Emitting it
                    # here as well printed the identical red line twice.
                    Write-Log "[Get-CredentialExposure] SYSVOL path not accessible: $sysvolBase"
                }
                else {
                    $Script:sysvolAccessible = $true
                    Write-Log "[Get-CredentialExposure] SYSVOL accessible: $sysvolBase"

                    # Use cached SYSVOL file listing (builds cache on first call, reuses on subsequent calls)
                    # One walk for both halves: the preference files are parsed as XML, the
                    # rest is grepped, and splitting them locally costs nothing.
                    $allExtensions = @('*.xml') + $Script:CredentialScanExtensions + @('Registry.pol')
                    $allFiles = @(Get-CachedSYSVOLFiles -Filter $allExtensions -SYSVOLPath $sysvolBase)

                    # Split into XML and script files locally (no additional SMB round-trips)
                    $xmlFiles = @($allFiles | Where-Object { $_.Extension -eq '.xml' })
                    $polFiles = @($allFiles | Where-Object { $_.Name -ieq 'Registry.pol' })
                    $scriptFiles = @($allFiles | Where-Object { $_.Extension -ne '.xml' -and $_.Name -ine 'Registry.pol' -and
                        $Script:CredentialScanSkippedFiles -notcontains $_.Name })

                    Write-Log "[Get-CredentialExposure] Split: $($xmlFiles.Count) XML, $($scriptFiles.Count) script/config"

                    # ===== Part 1: GPP Password Search (XML files) =====
                    if ($xmlFiles.Count -gt 0) {
                        Write-Log "[Get-CredentialExposure] Analyzing $($xmlFiles.Count) XML file(s)..."

                        $totalXmlFiles = @($xmlFiles).Count
                        $currentXmlIndex = 0
                        foreach ($xmlFile in $xmlFiles) {
                            $currentXmlIndex++
                            if ($totalXmlFiles -gt $Script:ProgressThreshold) {
                                Show-Progress -Activity "Scanning SYSVOL for GPP credentials" -Current $currentXmlIndex -Total $totalXmlFiles -ObjectName $xmlFile.Name
                            }
                            try {
                                Write-Log "[Get-CredentialExposure] Reading XML: $($xmlFile.FullName)"
                                [xml]$xmlContent = Get-Content -Path $xmlFile.Fullname -ErrorAction Stop
                                $fileName = Split-Path $xmlFile.FullName -Leaf

                                # Extract GPO GUID from SYSVOL path for linkage resolution
                                $fileGpoGUID = $null
                                $fileGpoName = $null
                                # Three-valued like every other GPO check: $null when the
                                # linkage could not be resolved, @() when it resolved and this
                                # policy is linked nowhere. The row is then emitted either way
                                # below - "Not linked" is a statement about where a plaintext
                                # password applies, not an absence, and this check was the one
                                # place that let it vanish instead.
                                $fileLinkedOUs = $null
                                if ($xmlFile.FullName -match '\\Policies\\(\{[^}]+\})\\') {
                                    $fileGpoGUID = $Matches[1].ToUpper()
                                    $fileGpoName = if ($gpoNameMap[$fileGpoGUID]) { $gpoNameMap[$fileGpoGUID] } else { $fileGpoGUID }
                                    if ($null -ne $gpoLinkage) {
                                        $fileLinkedOUs = @()
                                        if ($gpoLinkage.ContainsKey($fileGpoGUID)) {
                                            $fileLinkedOUs = @($gpoLinkage[$fileGpoGUID])
                                        }
                                    }
                                }
                                # A credential found outside a GPO folder has no linkage
                                # question at all, which is why the row is suppressed for it
                                # rather than printed as Unknown.
                                $fileLinkedOUsDisplay = $fileLinkedOUs
                                if ($fileGpoGUID -and $null -eq $fileLinkedOUs) {
                                    $fileLinkedOUsDisplay = 'Unknown - linkage could not be resolved'
                                }

                                # Check 1: cpassword attribute (GPP encrypted passwords)
                                if ($xmlContent.InnerXml -match 'cpassword') {
                                    $xmlContent.GetElementsByTagName('Properties') | ForEach-Object {
                                        if ($_.cpassword -and $_.cpassword -ne '') {
                                            $cpassword = $_.cpassword
                                            $decryptedPassword = ConvertFrom-GPPPassword -EncryptedPassword $cpassword

                                            $username = ""
                                            if ($_.userName) { $username = $_.userName }
                                            elseif ($_.accountName) { $username = $_.accountName }
                                            elseif ($_.newName) { $username = $_.newName }
                                            elseif ($_.runAs) { $username = $_.runAs }

                                            $credObj = [PSCustomObject]@{
                                                CredentialType = "GPP Password"
                                                FilePath = $xmlFile.Fullname
                                                UserName = $username
                                                Password = $decryptedPassword
                                            }
                                            # What the name stands for in the directory. The
                                            # password of an account that is gone, disabled or
                                            # changed since the file was written is history,
                                            # and the finding alone could not tell it from one
                                            # that still works.
                                            $accountInAD = Resolve-CredentialAccount -UserName $username -FileName $fileName -FileTime $xmlFile.LastWriteTime
                                            if ($accountInAD) { $credObj | Add-Member -NotePropertyName 'accountInAD' -NotePropertyValue $accountInAD -Force }
                                            if ($fileGpoName) { $credObj | Add-Member -NotePropertyName 'GPOName' -NotePropertyValue $fileGpoName -Force }
                                            if ($fileGpoGUID) { $credObj | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $fileLinkedOUsDisplay -Force }
                                            Show-Line "Found GPP credential" -Class Finding
                                            $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPPCredential' -Force
                                            $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'GPP Password' -Force
                                            Show-Object $credObj -Class Finding
                                            $gppFindingsCount++
                                        }
                                    }
                                }
                                # Check 2: AutoAdminLogon in Registry.xml (plaintext passwords!)
                                #
                                # Independent of check 1, and it used to be an elseif of it:
                                # a Registry.xml holding both a cpassword item and the
                                # Winlogon values reported the cpassword alone. The
                                # deduplication that elseif was standing in for happens
                                # through the differing CredentialType anyway.
                                #
                                # Every Winlogon password in the file, each with its own
                                # account, and also in a file that does not name AutoAdminLogon
                                # itself - see Get-WinlogonCredential.
                                if ($fileName -match 'Registry\.xml') {
                                    foreach ($winlogonCredential in @(Get-WinlogonCredential -XmlContent $xmlContent)) {
                                        $fullUsername = $winlogonCredential.UserName
                                        $credObj = [PSCustomObject]@{
                                            CredentialType = "AutoAdminLogon"
                                            FilePath = $xmlFile.Fullname
                                            UserName = $fullUsername
                                            Password = $winlogonCredential.Password
                                        }
                                        $accountInAD = Resolve-CredentialAccount -UserName $fullUsername -FileName $fileName -FileTime $xmlFile.LastWriteTime
                                        if ($accountInAD) { $credObj | Add-Member -NotePropertyName 'accountInAD' -NotePropertyValue $accountInAD -Force }
                                        if ($fileGpoName) { $credObj | Add-Member -NotePropertyName 'GPOName' -NotePropertyValue $fileGpoName -Force }
                                        if ($fileGpoGUID) { $credObj | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $fileLinkedOUsDisplay -Force }
                                        Show-Line "Found AutoAdminLogon credential" -Class Finding
                                        $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPPCredential' -Force
                                        $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'AutoAdminLogon' -Force
                                        Show-Object $credObj -Class Finding
                                        $gppFindingsCount++
                                    }

                                    # Check 3: any other value the preference item writes
                                    # whose name says it is a password.
                                    foreach ($credObj in @(Get-RegistryPasswordCredential -Records @(Parse-RegistryXml -XmlFilePath $xmlFile.FullName) -FilePath $xmlFile.FullName)) {
                                        if ($fileGpoName) { $credObj | Add-Member -NotePropertyName 'GPOName' -NotePropertyValue $fileGpoName -Force }
                                        if ($fileGpoGUID) { $credObj | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $fileLinkedOUsDisplay -Force }
                                        Show-Line $(if ($credObj.CredentialType -eq 'VNC Password') { 'Found a VNC password in a registry value deployed by Group Policy' } else { 'Found a password in a registry value deployed by Group Policy' }) -Class Finding
                                        $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPPCredential' -Force
                                        $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue ([string]$credObj.CredentialType) -Force
                                        Show-Object $credObj -Class Finding
                                        $gppFindingsCount++
                                    }
                                }

                                # Check 4: a Windows answer file, by its root element - see
                                # Get-UnattendCredential. Parsed as XML like the preference
                                # files, so the script grep never saw it.
                                foreach ($unattendCredential in @(Get-UnattendCredential -XmlContent $xmlContent)) {
                                    $credObj = [PSCustomObject]@{
                                        CredentialType  = "Unattend Answer File"
                                        FilePath        = $xmlFile.Fullname
                                        UnattendSetting = $unattendCredential.Setting
                                        UserName        = $unattendCredential.UserName
                                        Password        = $unattendCredential.Password
                                    }
                                    $accountInAD = Resolve-CredentialAccount -UserName $unattendCredential.UserName -FileName $fileName -FileTime $xmlFile.LastWriteTime
                                    if ($accountInAD) { $credObj | Add-Member -NotePropertyName 'accountInAD' -NotePropertyValue $accountInAD -Force }
                                    if ($fileGpoName) { $credObj | Add-Member -NotePropertyName 'GPOName' -NotePropertyValue $fileGpoName -Force }
                                    if ($fileGpoGUID) { $credObj | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $fileLinkedOUsDisplay -Force }
                                    Show-Line "Found a password in a Windows answer file" -Class Finding
                                    $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPPCredential' -Force
                                    $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'Unattend' -Force
                                    Show-Object $credObj -Class Finding
                                    $gppFindingsCount++
                                }
                            }
                            catch {
                                Write-Log "[Get-CredentialExposure] Error parsing $($xmlFile.Fullname): $_"
                                Register-SYSVOLFileGap -Path $xmlFile.FullName -ErrorRecord $_
                            }
                        }
                        if ($totalXmlFiles -gt $Script:ProgressThreshold) {
                            Show-Progress -Activity "Scanning SYSVOL for GPP credentials" -Completed
                        }
                    }

                    # ===== Part 1b: Passwords in Administrative Template registry values =====
                    # Registry.pol is binary and no other pass reads it for credentials. A
                    # template that writes a password value puts it there in clear text.
                    foreach ($polFile in $polFiles) {
                        try {
                            $polHive = if ($polFile.FullName -match '\\Machine\\') { 'HKLM' } else { 'HKCU' }
                            $polRecords = @(Parse-PRegRecords -PolFilePath $polFile.FullName -Hive $polHive)
                            foreach ($credObj in @(Get-RegistryPasswordCredential -Records $polRecords -FilePath $polFile.FullName)) {
                                if ($polFile.FullName -match '\\Policies\\(\{[^}]+\})\\') {
                                    $polGpoGUID = $Matches[1].ToUpper()
                                    $credObj | Add-Member -NotePropertyName 'GPOName' -NotePropertyValue $(if ($gpoNameMap[$polGpoGUID]) { $gpoNameMap[$polGpoGUID] } else { $polGpoGUID }) -Force
                                    # Three-valued, as above: unresolved is not linked nowhere.
                                    $polLinkedOUs = 'Unknown - linkage could not be resolved'
                                    if ($null -ne $gpoLinkage) {
                                        $polLinkedOUs = @()
                                        if ($gpoLinkage.ContainsKey($polGpoGUID)) { $polLinkedOUs = @($gpoLinkage[$polGpoGUID]) }
                                    }
                                    $credObj | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $polLinkedOUs -Force
                                }
                                Show-Line $(if ($credObj.CredentialType -eq 'VNC Password') { 'Found a VNC password in a registry value deployed by Group Policy' } else { 'Found a password in a registry value deployed by Group Policy' }) -Class Finding
                                $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPPCredential' -Force
                                $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue ([string]$credObj.CredentialType) -Force
                                Show-Object $credObj -Class Finding
                                $gppFindingsCount++
                            }
                        }
                        catch {
                            Write-Log "[Get-CredentialExposure] Error parsing $($polFile.FullName): $_"
                            Register-SYSVOLFileGap -Path $polFile.FullName -ErrorRecord $_
                        }
                    }

                    if ($gppFindingsCount -eq 0) {
                        # A folder the scan account may not read contributes no findings and
                        # used to be indistinguishable from a folder with nothing in it. Say
                        # so, and do not paint the conclusion green over it. The same for a
                        # preference file or a Registry.pol that was listed and not read.
                        $gppClass = "Secure"
                        if (Show-SYSVOLCoverageNote -FileFilter @('*.xml', 'Registry.pol')) { $gppClass = "Note" }
                        Show-Line "No GPP credentials found in SYSVOL" -Class $gppClass
                    }

                    # ===== Part 2: Sensitive Information Search (script/config files) =====
                    Show-SubHeader "Searching for sensitive information in SYSVOL/NETLOGON..." -ObjectType "SYSVOLCredential"

                    if ($scriptFiles.Count -gt 0) {
                        Write-Log "[Get-CredentialExposure] Analyzing $($scriptFiles.Count) script/config file(s)..."

                        # Two-Tier Credential Detection System (Snaffler-inspired)
                        $tier1Patterns = @(
                            @{ Pattern = 'passw(or)?d\s*[=:]\s*["''][^"'']{3,}["'']'; Description = "Password assignment (quoted)" },
                            @{ Pattern = 'passw(or)?d\s*[=:]\s*(?!["''])\S{3,}'; Description = "Password assignment (unquoted)" },
                            @{ Pattern = '[-/]passw(or)?d\s+\S{3,}'; Description = "Password parameter" },
                            @{ Pattern = 'psexec.{0,100}\s-p\s+\S+'; Description = "PSExec with password" },
                            @{ Pattern = 'schtasks.{0,300}/rp\s+\S+'; Description = "Schtasks with password" },
                            @{ Pattern = 'net\s+user\s+\S+\s+\S+\s+/add'; Description = "Net user creation" },
                            @{ Pattern = 'cmdkey\s+/add:[^\s]+.*?/pass:\S+'; Description = "Cmdkey with password" },
                            @{ Pattern = 'connectionstring.{1,200}passw'; Description = "DB connection string" },
                            @{ Pattern = 'ConvertTo-SecureString\s+["''][^"'']+["'']'; Description = "SecureString conversion" },
                            @{ Pattern = 'api[_-]?key\s*[=:]\s*["''][^"'']{10,}["'']'; Description = "API key assignment" },
                            @{ Pattern = '\$cred(ential)?\s*=.*password'; Description = "Credential variable" },
                            # The short forms, which carry a value just as often in a script as the
                            # spelled-out word does. Get-PasswordInDescription has had them for a while;
                            # this module, with otherwise the same lists, never did - so "pwd=Hunter2"
                            # was at best a tier 2 mention of the word beside it, and behind an exclusion
                            # it was nothing at all.
                            #
                            # Last in the list on purpose: the loop takes the first pattern that matches
                            # and names the finding after it, and "/pass:Hunter2" is part of a cmdkey
                            # line that has a pattern of its own with a better name.
                            @{ Pattern = 'pwd\s*[=:]\s*\S{3,}'; Description = "Pwd assignment" },
                            @{ Pattern = 'pw\s*[=:]\s*\S{3,}'; Description = "PW assignment" },
                            @{ Pattern = '\bpass\s*[=:]\s*\S{3,}'; Description = "Pass assignment" },
                            @{ Pattern = 'kennwort\s*[=:]\s*\S{3,}'; Description = "Kennwort assignment (German)" },
                            @{ Pattern = 'passord\s*[=:]\s*\S{3,}'; Description = "Passord assignment (Norwegian)" }
                        )

                        $tier2Patterns = @(
                            # Ordered most specific first: the list is first-match-wins, and the generic
                            # "passw(or)?d" also matches "passwd" and an XML password element, so those two
                            # descriptions could never be produced while it came first.
                            @{ Pattern = "<passw[^>]*>[^<]+</passw"; Description = "XML password element" },
                            @{ Pattern = "passwd"; Description = "Passwd mention" },
                            @{ Pattern = "passw(or)?d"; Description = "Password mention" },
                            @{ Pattern = "credential"; Description = "Credential mention" },
                            @{ Pattern = "(secret|token)\s*[=:]\s*\S{5,}"; Description = "Secret/token assignment" }
                        )

                        $exclusionPatterns = @(
                            'passw(or)?d\s*(policy|policies|requirement|guideline)',
                            'passw(or)?d\s+(must|should|cannot|shall)\s+(be|contain|have|include)',
                            'passw(or)?d\s+(length|complexity|history|age|expir)',
                            'passw(or)?d\s+(reset|change|recover|forgot)',
                            '(minimum|maximum)\s+passw(or)?d',
                            '(set|change|update|reset)\s+(your|the|a)\s+passw(or)?d',
                            '^\s*(REM|::|''|#)\s+.*passw',
                            'echo\s+.*passw(or)?d.*help',
                            'usage:.*passw(or)?d',
                            'Enter\s+(your\s+)?passw(or)?d',
                            'passw(or)?d\s+prompt'
                        )

                        # These describe the VALUE rather than the prose around it: the syntax is an
                        # assignment, but what was assigned is a row of asterisks or an
                        # angle-bracket placeholder, so there is no credential whatever the pattern
                        # says. That makes them the one list allowed to silence a line outright -
                        # the exclusions above only decide against a bare mention. Two of them used
                        # to sit in that list, where they did the right thing for the wrong reason.
                        # Same split as Get-PasswordInDescription, which needed it first.
                        $placeholderPatterns = @(
                            'passw(or)?d\s*[=:]\s*["'']?\*+["'']?\s*$',
                            'passw(or)?d\s*[=:]\s*["'']?<[^>]+>',
                            'pwd\s*[=:]\s*["'']?\*+["'']?\s*$',
                            'pwd\s*[=:]\s*["'']?<[^>]+>',
                            '[-/]pass(word)?[:\s]+["'']?\*+["'']?\s*$',
                            '[-/]pass(word)?[:\s]+["'']?<[^>]+>'
                        )

                        $netUsePattern = "net use (?<devicename>(\w|\*|LPT\d):?) (?<path>\\\\?.*?)(( (?<user>/user:((?<domain>[\w.]*)\\)?(?<username>\S*)))|( /(p(ersistent)?|P(ERSISTENT)?):(no|NO|yes|YES))|( (?<password>(?!/)\S*))|( /(delete|DELETE))|( /(savecred|SAVECRED))|( /(smartcard|SMARTCARD)))+"

                        $totalScriptFiles = @($scriptFiles).Count
                        $currentScriptIndex = 0
                        foreach ($file in $scriptFiles) {
                            $currentScriptIndex++
                            if ($totalScriptFiles -gt $Script:ProgressThreshold) {
                                Show-Progress -Activity "Scanning SYSVOL for sensitive information" -Current $currentScriptIndex -Total $totalScriptFiles -ObjectName $file.Name
                            }
                            try {
                                Write-Log "[Get-CredentialExposure] Reading script/config: $($file.FullName)"

                                # Extract GPO GUID from SYSVOL path for linkage resolution
                                $fileGpoGUID = $null
                                $fileGpoName = $null
                                # Same three-valued handling as the XML branch above.
                                $fileLinkedOUs = $null
                                if ($file.FullName -match '\\Policies\\(\{[^}]+\})\\') {
                                    $fileGpoGUID = $Matches[1].ToUpper()
                                    $fileGpoName = if ($gpoNameMap[$fileGpoGUID]) { $gpoNameMap[$fileGpoGUID] } else { $fileGpoGUID }
                                    if ($null -ne $gpoLinkage) {
                                        $fileLinkedOUs = @()
                                        if ($gpoLinkage.ContainsKey($fileGpoGUID)) {
                                            $fileLinkedOUs = @($gpoLinkage[$fileGpoGUID])
                                        }
                                    }
                                }
                                $fileLinkedOUsDisplay = $fileLinkedOUs
                                if ($fileGpoGUID -and $null -eq $fileLinkedOUs) {
                                    $fileLinkedOUsDisplay = 'Unknown - linkage could not be resolved'
                                }

                                $fileContent = $null

                                if ($file.Extension -eq ".vbe") {
                                    try {
                                        $encodedContent = Get-Content -Path $file.FullName -Raw -ErrorAction Stop
                                        $fileContent = ConvertFrom-VBE -EncodedScript $encodedContent
                                        Write-Log "[Get-CredentialExposure] Decoded VBE file: $($file.Name)"
                                    }
                                    catch {
                                        Write-Log "[Get-CredentialExposure] Failed to decode VBE file: $($file.Name)"
                                        Register-SYSVOLFileGap -Path $file.FullName -ErrorRecord $_
                                        continue
                                    }
                                }
                                else {
                                    $fileContent = Get-Content -Path $file.FullName -Raw -ErrorAction Stop
                                }

                                if (-not $fileContent) { continue }

                                $lines = $fileContent -split "`n"
                                $reportedLines = @{}

                                # VNC passwords, decrypted - see Get-VNCFileCredential. Their
                                # lines are reported, so the grep below does not show the hex.
                                foreach ($vncCredential in @(Get-VNCFileCredential -FileName $file.Name -Lines $lines)) {
                                    $credObj = [PSCustomObject]@{
                                        CredentialType = 'VNC Password'
                                        FilePath       = $file.FullName
                                        VNCHost        = $vncCredential.VNCHost
                                        VNCSetting     = $vncCredential.Setting
                                        Password       = $vncCredential.Password
                                    }
                                    if ($fileGpoName) { $credObj | Add-Member -NotePropertyName 'GPOName' -NotePropertyValue $fileGpoName -Force }
                                    if ($fileGpoGUID) { $credObj | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $fileLinkedOUsDisplay -Force }
                                    Show-Line "Found a VNC password" -Class Finding
                                    $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SYSVOLCredential' -Force
                                    $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'VNC Password' -Force
                                    Show-Object $credObj -Class Finding
                                    $reportedLines[$vncCredential.Line] = $true
                                    $sysvolFindingsCount++
                                }

                                # Check for net use credentials
                                $netUseMatches = [Regex]::Matches($fileContent, $netUsePattern)
                                foreach ($match in $netUseMatches) {
                                    $foundUsername = $match.Groups["username"].Value
                                    $foundPassword = $match.Groups["password"].Value
                                    $foundDomain = $match.Groups["domain"].Value

                                    if ($foundUsername -and $foundPassword) {
                                        $fullUser = if ($foundDomain) { "$foundDomain\$foundUsername" } else { $foundUsername }
                                        $credObj = [PSCustomObject]@{
                                            CredentialType = "Net Use"
                                            FilePath = $file.FullName
                                            UserName = $fullUser
                                            Password = $foundPassword
                                        }
                                        $accountInAD = Resolve-CredentialAccount -UserName $fullUser -FileName $file.Name -FileTime $file.LastWriteTime
                                        if ($accountInAD) { $credObj | Add-Member -NotePropertyName 'accountInAD' -NotePropertyValue $accountInAD -Force }
                                        if ($fileGpoName) { $credObj | Add-Member -NotePropertyName 'GPOName' -NotePropertyValue $fileGpoName -Force }
                                        if ($fileGpoGUID) { $credObj | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $fileLinkedOUsDisplay -Force }
                                        Show-Line "Found net use credential" -Class Finding
                                        $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SYSVOLCredential' -Force
                                        $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'Net Use' -Force
                                        Show-Object $credObj -Class Finding
                                        # The whole line rather than the match - see the
                                        # custom path above for what the difference cost.
                                        $reportedLines[(Get-ReportedLineKey -Lines $lines -Match $match.Value)] = $true
                                        $sysvolFindingsCount++
                                    }
                                }

                                # Two-tier credential detection on each line
                                foreach ($line in $lines) {
                                    $trimmedLine = $line.Trim()
                                    if ([string]::IsNullOrWhiteSpace($trimmedLine)) { continue }

                                    # One report per line - see the custom path above.
                                    if ($reportedLines.ContainsKey($trimmedLine)) { continue }

                                    # A masked or bracketed value is not a credential
                                    # however much the syntax around it looks like an
                                    # assignment.
                                    $isPlaceholder = $false
                                    foreach ($phPattern in $placeholderPatterns) {
                                        if ($trimmedLine -imatch $phPattern) { $isPlaceholder = $true; break }
                                    }
                                    if ($isPlaceholder) { continue }

                                    # Tier 1 is decided before the prose exclusions are
                                    # consulted. They used to run first and drop the line
                                    # outright, which is the opposite of what this check is
                                    # for: policy wording and a real credential share a
                                    # line all the time, and a script line is long enough
                                    # for both. "echo Set the password: Winter2024" matched
                                    # an exclusion and never reached the assignment pattern
                                    # that would have caught it, and the comment exclusion
                                    # dropped every commented-out line carrying "passw" -
                                    # including a net use with a password on it, which is
                                    # readable whether the line runs or not.
                                    #
                                    # Get-PasswordInDescription turned the same two steps
                                    # around for the same reason: an exclusion says "this
                                    # reads like policy text", which is a reason to distrust
                                    # a bare mention and never a reason to ignore an
                                    # assignment with a value next to it.
                                    $tier1Match = $false
                                    foreach ($pattern in $tier1Patterns) {
                                        if ($trimmedLine -match $pattern.Pattern) {
                                            $credObj = [PSCustomObject]@{
                                                CredentialType = $pattern.Description
                                                FilePath = $file.FullName
                                                MatchedLine = $trimmedLine
                                            }
                                            if ($fileGpoName) { $credObj | Add-Member -NotePropertyName 'GPOName' -NotePropertyValue $fileGpoName -Force }
                                            if ($fileGpoGUID) { $credObj | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $fileLinkedOUsDisplay -Force }
                                            Show-Line "Found credential pattern" -Class Finding
                                            $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SYSVOLCredential' -Force
                                            $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue $pattern.Description -Force
                                            Show-Object $credObj -Class Finding
                                            $reportedLines[$trimmedLine] = $true
                                            $tier1Match = $true
                                            $sysvolFindingsCount++
                                            break
                                        }
                                    }
                                    if ($tier1Match) { continue }

                                    # No assignment on this line, so wording that reads
                                    # like policy text is what it looks like - and here it
                                    # does mean the line can be dropped.
                                    $isExcluded = $false
                                    foreach ($exclusion in $exclusionPatterns) {
                                        if ($trimmedLine -match $exclusion) {
                                            $isExcluded = $true
                                            Write-Log "[Get-CredentialExposure] Excluded by pattern: $trimmedLine"
                                            break
                                        }
                                    }
                                    if ($isExcluded) { continue }

                                    foreach ($pattern in $tier2Patterns) {
                                        if ($trimmedLine -match $pattern.Pattern) {
                                            $credObj = [PSCustomObject]@{
                                                CredentialType = "$($pattern.Description) (needs review)"
                                                FilePath = $file.FullName
                                                MatchedLine = $trimmedLine
                                            }
                                            if ($fileGpoName) { $credObj | Add-Member -NotePropertyName 'GPOName' -NotePropertyValue $fileGpoName -Force }
                                            if ($fileGpoGUID) { $credObj | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $fileLinkedOUsDisplay -Force }
                                            Show-Line "Found possible sensitive information" -Class Hint
                                            $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SYSVOLCredential' -Force
                                            $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue $pattern.Description -Force
                                            Show-Object $credObj -Class Hint
                                            $reportedLines[$trimmedLine] = $true
                                            $sysvolFindingsCount++
                                            break
                                        }
                                    }
                                }
                            }
                            catch {
                                Write-Log "[Get-CredentialExposure] Error analyzing $($file.Name): $_"
                                Register-SYSVOLFileGap -Path $file.FullName -ErrorRecord $_
                            }
                        }
                        if ($totalScriptFiles -gt $Script:ProgressThreshold) {
                            Show-Progress -Activity "Scanning SYSVOL for sensitive information" -Completed
                        }

                        if ($sysvolFindingsCount -eq 0) {
                            $scriptClass = "Secure"
                            if (Show-SYSVOLCoverageNote -FileFilter $Script:CredentialScanExtensions) { $scriptClass = "Note" }
                            Show-Line "No sensitive information found in SYSVOL/NETLOGON scripts" -Class $scriptClass
                        }
                    }
                    else {
                        # No script files at all. That is only a clean result if the scan was
                        # allowed to look everywhere.
                        $scriptClass = "Secure"
                        if (Show-SYSVOLCoverageNote -FileFilter $Script:CredentialScanExtensions) { $scriptClass = "Note" }
                        Show-Line "No sensitive information found in SYSVOL/NETLOGON scripts" -Class $scriptClass
                    }
                }
            }

            # Check if SYSVOL was accessible
            $sysvolAccessible = $Script:sysvolAccessible
            $Script:sysvolAccessible = $null

            if (-not $sysvolAccessible) {
                if ((Test-SysvolAccessible) -eq $false) {
                    Show-Line "Skipped - SYSVOL not accessible" -Class "Hint"
                } else {
                    Show-Line "SYSVOL access failed - credentials were not searched for" -Class "Finding"
                }
            }

        } catch {
            Write-Log "[Get-CredentialExposure] Error: $_" -Level Error
            Show-Line "Error during check - credentials in SYSVOL and NETLOGON could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-CredentialExposure] Check completed"
    }
}
