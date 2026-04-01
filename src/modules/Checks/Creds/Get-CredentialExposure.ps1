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
                    @{ Pattern = '\$cred(ential)?\s*=.*password'; Description = "Credential variable" }
                )
                $tier2Patterns = @(
                    @{ Pattern = "passw(or)?d"; Description = "Password mention" },
                    @{ Pattern = "passwd"; Description = "Passwd mention" },
                    @{ Pattern = "credential"; Description = "Credential mention" },
                    @{ Pattern = "<passw[^>]*>[^<]+</passw"; Description = "XML password element" },
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
                    'passw(or)?d\s*:\s*\*+',
                    'passw(or)?d\s*:\s*<[^>]+>',
                    'Enter\s+(your\s+)?passw(or)?d',
                    'passw(or)?d\s+prompt'
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
                                            credentialType = "GPP Password"
                                            filePath = $xmlFile.Fullname
                                            userName = $username
                                            password = $decryptedPassword
                                        }
                                        Show-Line "Found GPP credential" -Class Finding
                                        $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPPCredential' -Force
                                        $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'GPP Password' -Force
                                        Show-Object $credObj
                                    }
                                }
                            }
                            elseif ($fileName -match 'Registry\.xml' -and $xmlContent.InnerXml -match 'AutoAdminLogon') {
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
                                        credentialType = "AutoAdminLogon"
                                        filePath = $xmlFile.Fullname
                                        userName = $fullUsername
                                        password = $autoLogonPassword
                                    }
                                    Show-Line "Found AutoAdminLogon credential" -Class Finding
                                        $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPPCredential' -Force
                                        $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'AutoAdminLogon' -Force
                                        Show-Object $credObj
                                }
                            }
                        }
                        catch {
                            Write-Log "[Get-CredentialExposure] Error parsing $($xmlFile.Fullname): $_"
                        }
                    }
                }

                # Scan script/config files
                $searchExtensions = @('*.txt','*.bat','*.ini','*.conf','*.cnf','*.cmd','*.vbs','*.vbe','*.kix','*.ps1','*.psm1')
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
                                        credentialType = "Net Use"
                                        filePath = $file.FullName
                                        userName = $fullUser
                                        password = $foundPassword
                                    }
                                    Show-Line "Found net use credential" -Class Finding
                                        $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPPCredential' -Force
                                        $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'Net Use' -Force
                                        Show-Object $credObj
                                    $reportedLines[$match.Value] = $true
                                }
                            }

                            # Two-tier detection on each line
                            foreach ($line in $lines) {
                                $trimmedLine = $line.Trim()
                                if ([string]::IsNullOrWhiteSpace($trimmedLine)) { continue }

                                $alreadyReported = $false
                                foreach ($reported in $reportedLines.Keys) {
                                    if ($trimmedLine -like "*$reported*") { $alreadyReported = $true; break }
                                }
                                if ($alreadyReported) { continue }

                                $isExcluded = $false
                                foreach ($exclusion in $exclusionPatterns) {
                                    if ($trimmedLine -match $exclusion) { $isExcluded = $true; break }
                                }
                                if ($isExcluded) { continue }

                                $tier1Match = $false
                                foreach ($pattern in $tier1Patterns) {
                                    if ($trimmedLine -match $pattern.Pattern) {
                                        # Create credential object for proper display
                                        $credObj = [PSCustomObject]@{
                                            credentialType = $pattern.Description
                                            filePath = $file.FullName
                                            matchedLine = $trimmedLine
                                        }
                                        Show-Line "Found credential pattern" -Class Finding
                                        $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPPCredential' -Force
                                        $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue $pattern.Description -Force
                                        Show-Object $credObj
                                        $reportedLines[$trimmedLine] = $true
                                        $tier1Match = $true
                                        break
                                    }
                                }
                                if ($tier1Match) { continue }

                                foreach ($pattern in $tier2Patterns) {
                                    if ($trimmedLine -match $pattern.Pattern) {
                                        # Create credential object for proper display (lower severity)
                                        $credObj = [PSCustomObject]@{
                                            credentialType = "$($pattern.Description) (needs review)"
                                            filePath = $file.FullName
                                            matchedLine = $trimmedLine
                                        }
                                        Show-Line "Found possible sensitive information" -Class Hint
                                            $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPPCredential' -Force
                                            $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue $pattern.Description -Force
                                            Show-Object $credObj
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
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
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
                    Show-Line "SYSVOL access failed - cannot search for credentials - SMB access failed (authentication/network issue)" -Class "Finding"
                }
                else {
                    $Script:sysvolAccessible = $true
                    Write-Log "[Get-CredentialExposure] SYSVOL accessible: $sysvolBase"

                    # Use cached SYSVOL file listing (builds cache on first call, reuses on subsequent calls)
                    $allExtensions = @('*.xml','*.txt','*.bat','*.ini','*.conf','*.cnf','*.cmd','*.vbs','*.vbe','*.kix')
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
                                $fileLinkedOUs = @()
                                if ($xmlFile.FullName -match '\\Policies\\(\{[^}]+\})\\') {
                                    $fileGpoGUID = $Matches[1].ToUpper()
                                    $fileGpoName = if ($gpoNameMap[$fileGpoGUID]) { $gpoNameMap[$fileGpoGUID] } else { $fileGpoGUID }
                                    if ($gpoLinkage -and $gpoLinkage.ContainsKey($fileGpoGUID)) {
                                        $fileLinkedOUs = $gpoLinkage[$fileGpoGUID]
                                    }
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
                                                credentialType = "GPP Password"
                                                filePath = $xmlFile.Fullname
                                                userName = $username
                                                password = $decryptedPassword
                                            }
                                            if ($fileGpoName) { $credObj | Add-Member -NotePropertyName 'gpoName' -NotePropertyValue $fileGpoName -Force }
                                            if ($fileLinkedOUs.Count -gt 0) { $credObj | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $fileLinkedOUs -Force }
                                            Show-Line "Found GPP credential" -Class Finding
                                            $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPPCredential' -Force
                                            $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'GPP Password' -Force
                                            Show-Object $credObj
                                            $gppFindingsCount++
                                        }
                                    }
                                }
                                # Check 2: AutoAdminLogon in Registry.xml (plaintext passwords!)
                                elseif ($fileName -match 'Registry\.xml' -and $xmlContent.InnerXml -match 'AutoAdminLogon') {
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
                                            credentialType = "AutoAdminLogon"
                                            filePath = $xmlFile.Fullname
                                            userName = $fullUsername
                                            password = $autoLogonPassword
                                        }
                                        if ($fileGpoName) { $credObj | Add-Member -NotePropertyName 'gpoName' -NotePropertyValue $fileGpoName -Force }
                                        if ($fileLinkedOUs.Count -gt 0) { $credObj | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $fileLinkedOUs -Force }
                                        Show-Line "Found AutoAdminLogon credential" -Class Finding
                                        $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'GPPCredential' -Force
                                        $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'AutoAdminLogon' -Force
                                        Show-Object $credObj
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
                        Show-Line "No GPP credentials found in SYSVOL" -Class "Secure"
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
                            @{ Pattern = '\$cred(ential)?\s*=.*password'; Description = "Credential variable" }
                        )

                        $tier2Patterns = @(
                            @{ Pattern = "passw(or)?d"; Description = "Password mention" },
                            @{ Pattern = "passwd"; Description = "Passwd mention" },
                            @{ Pattern = "credential"; Description = "Credential mention" },
                            @{ Pattern = "<passw[^>]*>[^<]+</passw"; Description = "XML password element" },
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
                            'passw(or)?d\s*:\s*\*+',
                            'passw(or)?d\s*:\s*<[^>]+>',
                            'Enter\s+(your\s+)?passw(or)?d',
                            'passw(or)?d\s+prompt'
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
                                $fileLinkedOUs = @()
                                if ($file.FullName -match '\\Policies\\(\{[^}]+\})\\') {
                                    $fileGpoGUID = $Matches[1].ToUpper()
                                    $fileGpoName = if ($gpoNameMap[$fileGpoGUID]) { $gpoNameMap[$fileGpoGUID] } else { $fileGpoGUID }
                                    if ($gpoLinkage -and $gpoLinkage.ContainsKey($fileGpoGUID)) {
                                        $fileLinkedOUs = $gpoLinkage[$fileGpoGUID]
                                    }
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
                                            credentialType = "Net Use"
                                            filePath = $file.FullName
                                            userName = $fullUser
                                            password = $foundPassword
                                        }
                                        if ($fileGpoName) { $credObj | Add-Member -NotePropertyName 'gpoName' -NotePropertyValue $fileGpoName -Force }
                                        if ($fileLinkedOUs.Count -gt 0) { $credObj | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $fileLinkedOUs -Force }
                                        Show-Line "Found net use credential" -Class Finding
                                        $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SYSVOLCredential' -Force
                                        $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue 'Net Use' -Force
                                        Show-Object $credObj
                                        $reportedLines[$match.Value] = $true
                                        $sysvolFindingsCount++
                                    }
                                }

                                # Two-tier credential detection on each line
                                foreach ($line in $lines) {
                                    $trimmedLine = $line.Trim()
                                    if ([string]::IsNullOrWhiteSpace($trimmedLine)) { continue }

                                    $alreadyReported = $false
                                    foreach ($reported in $reportedLines.Keys) {
                                        if ($trimmedLine -like "*$reported*") {
                                            $alreadyReported = $true
                                            break
                                        }
                                    }
                                    if ($alreadyReported) { continue }

                                    $isExcluded = $false
                                    foreach ($exclusion in $exclusionPatterns) {
                                        if ($trimmedLine -match $exclusion) {
                                            $isExcluded = $true
                                            Write-Log "[Get-CredentialExposure] Excluded by pattern: $trimmedLine"
                                            break
                                        }
                                    }
                                    if ($isExcluded) { continue }

                                    $tier1Match = $false
                                    foreach ($pattern in $tier1Patterns) {
                                        if ($trimmedLine -match $pattern.Pattern) {
                                            $credObj = [PSCustomObject]@{
                                                credentialType = $pattern.Description
                                                filePath = $file.FullName
                                                matchedLine = $trimmedLine
                                            }
                                            if ($fileGpoName) { $credObj | Add-Member -NotePropertyName 'gpoName' -NotePropertyValue $fileGpoName -Force }
                                            if ($fileLinkedOUs.Count -gt 0) { $credObj | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $fileLinkedOUs -Force }
                                            Show-Line "Found credential pattern" -Class Finding
                                            $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SYSVOLCredential' -Force
                                            $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue $pattern.Description -Force
                                            Show-Object $credObj
                                            $reportedLines[$trimmedLine] = $true
                                            $tier1Match = $true
                                            $sysvolFindingsCount++
                                            break
                                        }
                                    }
                                    if ($tier1Match) { continue }

                                    foreach ($pattern in $tier2Patterns) {
                                        if ($trimmedLine -match $pattern.Pattern) {
                                            $credObj = [PSCustomObject]@{
                                                credentialType = "$($pattern.Description) (needs review)"
                                                filePath = $file.FullName
                                                matchedLine = $trimmedLine
                                            }
                                            if ($fileGpoName) { $credObj | Add-Member -NotePropertyName 'gpoName' -NotePropertyValue $fileGpoName -Force }
                                            if ($fileLinkedOUs.Count -gt 0) { $credObj | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $fileLinkedOUs -Force }
                                            Show-Line "Found possible sensitive information" -Class Hint
                                            $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SYSVOLCredential' -Force
                                            $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue $pattern.Description -Force
                                            Show-Object $credObj
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
                            Show-Line "No sensitive information found in SYSVOL/NETLOGON scripts" -Class "Secure"
                        }
                    }
                    else {
                        Show-Line "No sensitive information found in SYSVOL/NETLOGON scripts" -Class "Secure"
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
                    Show-Line "SYSVOL access failed - cannot search for credentials - SMB access failed (authentication/network issue)" -Class "Finding"
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
