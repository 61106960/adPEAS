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
    '*.ps1', '*.psm1'
)

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

function Get-CredentialExposure {
    <#
    .SYNOPSIS
    Detects credential exposure in SYSVOL (GPP Passwords), NETLOGON scripts, or custom paths.

    .DESCRIPTION
    Performs comprehensive credential leakage detection:
    - Group Policy Preferences (GPP) passwords (cpassword attribute, MS14-025)
    - AutoAdminLogon passwords in Registry.xml (plaintext!)
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
                            if ($fileName -match 'Registry\.xml' -and $xmlContent.InnerXml -match 'AutoAdminLogon') {
                                $autoLogonUser = $null
                                $autoLogonPassword = $null
                                $autoLogonDomain = $null
                                foreach ($prop in $xmlContent.GetElementsByTagName('Properties')) {
                                    if ($prop.name -match 'DefaultUserName') { $autoLogonUser = $prop.value }
                                    if ($prop.name -match 'DefaultPassword') { $autoLogonPassword = $prop.value }
                                    if ($prop.name -match 'DefaultDomainName') { $autoLogonDomain = $prop.value }
                                }
                                if ($autoLogonPassword -and $autoLogonPassword -ne '') {
                                    $fullUsername = if ($autoLogonDomain) { "$autoLogonDomain\$autoLogonUser" } else { $autoLogonUser }
                                    # Create credential object for proper display
                                    $credObj = [PSCustomObject]@{
                                        CredentialType = "AutoAdminLogon"
                                        FilePath = $xmlFile.Fullname
                                        UserName = $fullUsername
                                        Password = $autoLogonPassword
                                    }
                                    $accountInAD = Resolve-CredentialAccount -UserName $fullUsername -FileName $fileName -FileTime $xmlFile.LastWriteTime
                                    if ($accountInAD) { $credObj | Add-Member -NotePropertyName 'accountInAD' -NotePropertyValue $accountInAD -Force }
                                    Show-Line "Found AutoAdminLogon credential" -Class Finding
                                        $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPPCredential' -Force
                                        $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'AutoAdminLogon' -Force
                                        Show-Object $credObj -Class Finding
                                }
                            }
                        }
                        catch {
                            Write-Log "[Get-CredentialExposure] Error parsing $($xmlFile.Fullname): $_"
                        }
                    }
                }

                # Scan script/config files
                $searchExtensions = $Script:CredentialScanExtensions
                $files = Get-ChildItem -Force -Path $scanPath -Recurse -Include $searchExtensions -ErrorAction SilentlyContinue

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
                                        $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPPCredential' -Force
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
                    $allExtensions = @('*.xml') + $Script:CredentialScanExtensions
                    $allFiles = @(Get-CachedSYSVOLFiles -Filter $allExtensions -SYSVOLPath $sysvolBase)

                    # Split into XML and script files locally (no additional SMB round-trips)
                    $xmlFiles = @($allFiles | Where-Object { $_.Extension -eq '.xml' })
                    $scriptFiles = @($allFiles | Where-Object { $_.Extension -ne '.xml' })

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
                                if ($fileName -match 'Registry\.xml' -and $xmlContent.InnerXml -match 'AutoAdminLogon') {
                                    $autoLogonUser = $null
                                    $autoLogonPassword = $null
                                    $autoLogonDomain = $null

                                    foreach ($prop in $xmlContent.GetElementsByTagName('Properties')) {
                                        if ($prop.name -match 'DefaultUserName') { $autoLogonUser = $prop.value }
                                        if ($prop.name -match 'DefaultPassword') { $autoLogonPassword = $prop.value }
                                        if ($prop.name -match 'DefaultDomainName') { $autoLogonDomain = $prop.value }
                                    }

                                    if ($autoLogonPassword -and $autoLogonPassword -ne '') {
                                        $fullUsername = if ($autoLogonDomain) { "$autoLogonDomain\$autoLogonUser" } else { $autoLogonUser }
                                        $credObj = [PSCustomObject]@{
                                            CredentialType = "AutoAdminLogon"
                                            FilePath = $xmlFile.Fullname
                                            UserName = $fullUsername
                                            Password = $autoLogonPassword
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
                                }
                            }
                            catch {
                                Write-Log "[Get-CredentialExposure] Error parsing $($xmlFile.Fullname): $_"
                            }
                        }
                        if ($totalXmlFiles -gt $Script:ProgressThreshold) {
                            Show-Progress -Activity "Scanning SYSVOL for GPP credentials" -Completed
                        }
                    }

                    if ($gppFindingsCount -eq 0) {
                        # A folder the scan account may not read contributes no findings and
                        # used to be indistinguishable from a folder with nothing in it. Say
                        # so, and do not paint the conclusion green over it.
                        $gppClass = "Secure"
                        if (Show-SYSVOLCoverageNote) { $gppClass = "Note" }
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
                                        continue
                                    }
                                }
                                else {
                                    $fileContent = Get-Content -Path $file.FullName -Raw -ErrorAction Stop
                                }

                                if (-not $fileContent) { continue }

                                $lines = $fileContent -split "`n"
                                $reportedLines = @{}

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
                            }
                        }
                        if ($totalScriptFiles -gt $Script:ProgressThreshold) {
                            Show-Progress -Activity "Scanning SYSVOL for sensitive information" -Completed
                        }

                        if ($sysvolFindingsCount -eq 0) {
                            $scriptClass = "Secure"
                            if (Show-SYSVOLCoverageNote) { $scriptClass = "Note" }
                            Show-Line "No sensitive information found in SYSVOL/NETLOGON scripts" -Class $scriptClass
                        }
                    }
                    else {
                        # No script files at all. That is only a clean result if the scan was
                        # allowed to look everywhere.
                        $scriptClass = "Secure"
                        if (Show-SYSVOLCoverageNote) { $scriptClass = "Note" }
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
        }
    }

    end {
        Write-Log "[Get-CredentialExposure] Check completed"
    }
}
