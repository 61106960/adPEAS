<#
.SYNOPSIS
    Reusable build engine for single-file PowerShell releases.

.DESCRIPTION
    Everything in this file is project independent. It knows PowerShell, not adPEAS:
    what a comment token is, which lines belong to a string literal, how to write a file
    the way Windows PowerShell 5.1 can read it back, how to compress and sign one, and how
    to pack one into a console executable.

    What belongs in the project instead: which modules exist, what they are called, which
    variables carry the version, which functions have content embedded into them. That
    lives in Build-Config.psd1, and Build-Release.ps1 puts the two together.

    The split exists so this file can be copied into another project unchanged - and so a
    fix made there can be copied back without a merge.

    The engine is dot-sourced, not imported as a module: a build script that needs a module
    installed before it can build is a dependency the projects this serves do not want.

.NOTES
    Author: Alexander Sturz (@_61106960_)

    Contract:
      - Functions never write to the host except where noted (progress lines).
      - Functions that can fail report through Write-Error and return $null, so the
        caller decides whether to stop. $ErrorActionPreference = 'Stop' in the caller
        turns that into an abort.
#>

# =============================================================================
# FILE I/O
# =============================================================================

<#
.SYNOPSIS
    Reads a source file as UTF-8, independent of PowerShell version.
.DESCRIPTION
    Get-Content without -Encoding is version-dependent: Windows PowerShell 5.1 falls back
    to the system ANSI code page for files that have no BOM, which corrupts every non-ASCII
    character in the source modules (e.g. an em dash becomes three characters, one of which
    PowerShell treats as a string delimiter). PowerShell 7+ assumes UTF-8 instead.
    ReadAllText honors a BOM when present and decodes as UTF-8 otherwise, in both versions.
#>
function Read-BuildFile {
    param(
        [Parameter(Mandatory=$true)] [string]$Path
    )
    return [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
}

<#
.SYNOPSIS
    Writes a build artifact: UTF-8 with BOM, atomically, with a retry for locked files.
.DESCRIPTION
    Writes to a temp file first, then swaps it onto the target in one operation.

    The BOM is not optional. Out-File -Encoding UTF8 is version-dependent - Windows
    PowerShell 5.1 emits a BOM, PowerShell 7+ does not. A build produced under PowerShell 7
    would therefore be unreadable for a Windows PowerShell 5.1 target: without a BOM it
    decodes the file as ANSI and every non-ASCII character breaks, which can abort parsing.
#>
function Write-BuildFile {
    param(
        [Parameter(Mandatory=$true)] [string]$Path,
        [Parameter(Mandatory=$true)] [AllowEmptyString()] [string]$Content,
        [int]$MaxRetries = 5,
        [int]$RetryDelayMs = 500
    )
    $tempPath = "$Path.tmp.$PID"
    try {
        if (-not $Content.EndsWith("`n")) {
            $Content += "`r`n"
        }
        [System.IO.File]::WriteAllText($tempPath, $Content, (New-Object System.Text.UTF8Encoding($true)))

        for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
            try {
                # File.Replace does the swap in one operation. Deleting the target and then
                # moving onto it leaves a window where neither exists: if the move then
                # fails on every retry, the finally block below removes the temp file too
                # and the artifact is gone entirely - the old one deleted, the new one
                # never written.
                #
                # [NullString]::Value, not $null, for the backup-file argument. PowerShell
                # turns a $null bound to a [string] parameter into the empty string, and
                # File.Replace rejects that as a malformed path.
                if ([System.IO.File]::Exists($Path)) {
                    [System.IO.File]::Replace($tempPath, $Path, [NullString]::Value)
                } else {
                    [System.IO.File]::Move($tempPath, $Path)
                }
                return
            }
            catch [System.IO.IOException], [System.UnauthorizedAccessException] {
                # Both are needed. A file held open by another process raises IOException
                # ("used by another process"), but a file an indexer or scanner has locked
                # for writing raises UnauthorizedAccessException ("access to the path is
                # denied") - catching only the first means the retry loop this function
                # exists for never runs for half the cases it is written to survive.
                if ($attempt -lt $MaxRetries) {
                    Write-Host "[Build]   File locked, retrying in $($RetryDelayMs)ms... (attempt $attempt/$MaxRetries)" -ForegroundColor Yellow
                    Start-Sleep -Milliseconds $RetryDelayMs
                    $RetryDelayMs = [Math]::Min($RetryDelayMs * 2, 5000)
                }
                else {
                    throw
                }
            }
        }
    }
    finally {
        if (Test-Path $tempPath) {
            Remove-Item -Path $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}

# =============================================================================
# SOURCE ASSEMBLY
# =============================================================================

<#
.SYNOPSIS
    Reads the version out of the entry script.
.PARAMETER Content
    The entry script's text.
.PARAMETER VariableName
    The script variable holding it, without the $Script: prefix - e.g. 'adPEASVersion'
    for '$Script:adPEASVersion = "2.4.1"'.
#>
function Get-BuildSourceVersion {
    param(
        [Parameter(Mandatory=$true)] [string]$Content,
        [Parameter(Mandatory=$true)] [string]$VariableName
    )
    $pattern = '\$Script:' + [regex]::Escape($VariableName) + ' = "([^"]*)"'
    $matches = [regex]::Matches($Content, $pattern)

    if ($matches.Count -eq 0) {
        Write-Error "[Build] Could not find `$Script:$VariableName in the entry script"
        return $null
    }
    # More than one assignment means the build would silently pick whichever comes first,
    # which is how a version in an example or a comment ends up stamped on a release.
    if ($matches.Count -gt 1) {
        Write-Error "[Build] `$Script:$VariableName is assigned $($matches.Count) times in the entry script - cannot tell which one is the version"
        return $null
    }
    return $matches[0].Groups[1].Value
}

<#
.SYNOPSIS
    Collects the module list from the dot-source block of an entry script.
.DESCRIPTION
    Reads the same lines the entry script uses in development mode, so the build and a
    dot-sourced run always load the same files in the same order. Categories come from
    comment headers ("# Core Modules") and decide the order sections are emitted in.
.OUTPUTS
    An ordered hashtable: category name -> array of module paths relative to the source
    root. $null if nothing was found.
#>
function Get-BuildModuleList {
    param(
        [Parameter(Mandatory=$true)] [string]$Content,
        [Parameter(Mandatory=$true)] [string[]]$Categories,
        [string]$PathVariable = 'Script:ScriptPath'
    )
    $result = [ordered]@{}
    foreach ($category in $Categories) { $result[$category] = @() }

    $categoryPattern = '^\s+#\s+(' + (($Categories | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')\s+Modules'
    $sourcePattern = '^\s+\.\s+"\$' + [regex]::Escape($PathVariable) + '\\(.+)"'

    $currentCategory = $null
    foreach ($line in ($Content -split '\r?\n')) {
        if ($line -match $categoryPattern) {
            $currentCategory = $Matches[1]
            continue
        }
        if ($line -match $sourcePattern) {
            $modulePath = $Matches[1]
            if ($currentCategory) {
                $result[$currentCategory] += $modulePath
            } else {
                Write-Warning "[Build] Module without category: $modulePath"
            }
        }
    }

    $total = 0
    foreach ($category in $Categories) { $total += $result[$category].Count }
    if ($total -eq 0) {
        Write-Error "[Build] No modules found in the entry script - check the category comments and the dot-source format"
        return $null
    }
    return $result
}

<#
.SYNOPSIS
    Checks that every module file listed exists, and that no source file was forgotten.
.DESCRIPTION
    A file on disk that no one listed is absent from every artifact, silently. A file
    listed that is not on disk aborts the build later with a bare I/O error. Both are
    cheaper to find here, by name.
#>
function Test-BuildModuleList {
    param(
        [Parameter(Mandatory=$true)] $ModuleList,
        [Parameter(Mandatory=$true)] [string]$SourceRoot,
        [Parameter(Mandatory=$true)] [string]$ModuleDirectory
    )
    $listed = @()
    foreach ($category in $ModuleList.Keys) { $listed += $ModuleList[$category] }

    $problems = @()

    $duplicates = @($listed | Group-Object | Where-Object { $_.Count -gt 1 })
    foreach ($duplicate in $duplicates) {
        $problems += "listed $($duplicate.Count) times, would be embedded twice: $($duplicate.Name)"
    }

    foreach ($module in $listed) {
        if (-not (Test-Path (Join-Path $SourceRoot $module))) {
            $problems += "listed but not on disk: $module"
        }
    }

    $moduleRoot = Join-Path $SourceRoot $ModuleDirectory
    if (Test-Path $moduleRoot) {
        $prefix = (Resolve-Path $SourceRoot).Path
        foreach ($file in (Get-ChildItem -Path $moduleRoot -Filter *.ps1 -Recurse)) {
            $relative = $file.FullName.Substring($prefix.Length + 1)
            if ($relative -notin $listed) {
                $problems += "on disk but never built: $relative"
            }
        }
    }

    return $problems
}

# =============================================================================
# MINIFICATION
# =============================================================================
#
# These replace what used to be plain regexes over the whole assembled file. A regex does
# not tell code from the string literals a build is full of - an embedded HTML report is
# hundreds of kilobytes of CSS, JavaScript and markup sitting inside a here-string, and a
# pattern like "^[ \t]*#" deletes every CSS id selector in it. The readable variant, built
# without minification, stays correct meanwhile, so testing that one finds nothing.
#
# So comments are removed by token and calls by AST node, neither of which can see into a
# string, and the line-based steps skip lines that lie inside a multi-line string literal.

<#
.SYNOPSIS
    Parses generated content, reporting a syntax error against the build stage that caused it.
.OUTPUTS
    An object with Ast and Tokens, or $null after reporting an error.
#>
function Get-BuildParse {
    param(
        [Parameter(Mandatory=$true)] [string]$Content,
        [Parameter(Mandatory=$true)] [string]$Stage
    )
    $parseTokens = $null
    $parseErrors = $null
    $parsedAst = [System.Management.Automation.Language.Parser]::ParseInput($Content, [ref]$parseTokens, [ref]$parseErrors)
    if ($parseErrors -and $parseErrors.Count -gt 0) {
        $firstError = $parseErrors[0]
        Write-Error "[Build] Generated script does not parse ($Stage) - line $($firstError.Extent.StartLineNumber): $($firstError.Message)"
        return $null
    }
    return [PSCustomObject]@{ Ast = $parsedAst; Tokens = $parseTokens }
}

<#
.SYNOPSIS
    Cuts the given extents out of the content, back to front so unapplied offsets stay valid.
#>
function Remove-BuildTextRanges {
    param(
        [Parameter(Mandatory=$true)] [string]$Content,
        [Parameter(Mandatory=$true)] [AllowEmptyCollection()] $Extents
    )
    $ordered = @($Extents | Sort-Object -Property { $_.StartOffset } -Descending)
    $builder = New-Object System.Text.StringBuilder($Content)
    foreach ($extent in $ordered) {
        [void]$builder.Remove($extent.StartOffset, ($extent.EndOffset - $extent.StartOffset))
    }
    return $builder.ToString()
}

<#
.SYNOPSIS
    Removes comments by token, so a # inside a string is never mistaken for one.
#>
function Remove-BuildComments {
    param(
        [Parameter(Mandatory=$true)] [string]$Content,
        [Parameter(Mandatory=$true)] [string]$Stage,
        [switch]$KeepRequires
    )
    $parsed = Get-BuildParse -Content $Content -Stage $Stage
    if (-not $parsed) { return $null }

    $extents = New-Object System.Collections.Generic.List[object]
    foreach ($token in $parsed.Tokens) {
        if ($token.Kind -ne [System.Management.Automation.Language.TokenKind]::Comment) { continue }
        if ($KeepRequires -and $token.Text -match '^\s*#Requires\b') { continue }
        $extents.Add($token.Extent)
    }
    return (Remove-BuildTextRanges -Content $Content -Extents $extents)
}

<#
.SYNOPSIS
    Removes calls to the named commands, by AST node.
.DESCRIPTION
    Only a call that is a statement in its own right. "$x = Write-Log ..." would leave a
    dangling assignment behind and "Write-Log ... | Something" a dangling pipeline; a
    line-based version cannot tell those apart, nor can it tell a real call from the text
    "Write-Log" written inside a here-string, which it also deletes.
#>
function Remove-BuildCommandCalls {
    param(
        [Parameter(Mandatory=$true)] [string]$Content,
        [Parameter(Mandatory=$true)] [string]$Stage,
        [Parameter(Mandatory=$true)] [string[]]$CommandName
    )
    $parsed = Get-BuildParse -Content $Content -Stage $Stage
    if (-not $parsed) { return $null }

    $wanted = $CommandName
    $calls = @($parsed.Ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -in $wanted
    }.GetNewClosure(), $true))

    $extents = New-Object System.Collections.Generic.List[object]
    foreach ($call in $calls) {
        $pipeline = $call.Parent
        if ($pipeline -isnot [System.Management.Automation.Language.PipelineAst]) { continue }
        if ($pipeline.PipelineElements.Count -ne 1) { continue }
        if ($pipeline.Parent -isnot [System.Management.Automation.Language.StatementBlockAst] -and
            $pipeline.Parent -isnot [System.Management.Automation.Language.NamedBlockAst]) { continue }
        $extents.Add($pipeline.Extent)
    }
    return (Remove-BuildTextRanges -Content $Content -Extents $extents)
}

<#
.SYNOPSIS
    The 1-based line numbers whose content belongs to a multi-line string literal.
.DESCRIPTION
    The line a string opens on still carries code before the delimiter, so its own
    indentation is code and stays editable; everything after it is content.
#>
function Get-BuildProtectedLines {
    param(
        [Parameter(Mandatory=$true)] [string]$Content,
        [Parameter(Mandatory=$true)] [string]$Stage
    )
    $parsed = Get-BuildParse -Content $Content -Stage $Stage
    if (-not $parsed) { return $null }

    $strings = @($parsed.Ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
        $node -is [System.Management.Automation.Language.ExpandableStringExpressionAst]
    }, $true))

    $protectedLines = New-Object 'System.Collections.Generic.HashSet[int]'
    foreach ($stringAst in $strings) {
        $extent = $stringAst.Extent
        if ($extent.EndLineNumber -le $extent.StartLineNumber) { continue }
        for ($line = $extent.StartLineNumber + 1; $line -le $extent.EndLineNumber; $line++) {
            [void]$protectedLines.Add($line)
        }
    }
    return $protectedLines
}

<#
.SYNOPSIS
    Drops blank lines and trailing whitespace, optionally re-indents - on code lines only.
.DESCRIPTION
    Every line inside a multi-line string is copied through byte for byte, including its
    own line terminator: embedded assets are routinely a mix of CRLF and LF, and
    normalizing them would change bytes that have to stay identical across variants.
#>
function Invoke-BuildLineTransform {
    param(
        [Parameter(Mandatory=$true)] [string]$Content,
        [Parameter(Mandatory=$true)] [string]$Stage,
        [switch]$Reindent
    )
    $protectedLines = Get-BuildProtectedLines -Content $Content -Stage $Stage
    if ($null -eq $protectedLines) { return $null }

    $parts = [regex]::Split($Content, '(\r\n|\n|\r)')
    $builder = New-Object System.Text.StringBuilder($Content.Length)
    $lineNumber = 0

    for ($i = 0; $i -lt $parts.Count; $i += 2) {
        $lineNumber++
        $text = $parts[$i]
        $terminator = if (($i + 1) -lt $parts.Count) { $parts[$i + 1] } else { '' }

        if ($protectedLines.Contains($lineNumber)) {
            [void]$builder.Append($text).Append($terminator)
            continue
        }
        if ($text -match '^\s*$') { continue }

        $text = $text -replace '[ \t]+$', ''
        if ($Reindent) {
            $text = $text -replace '^    ', "`t"
            $text = $text -replace '^\t\t+', "`t"
        }
        [void]$builder.Append($text).Append($terminator)
    }
    return $builder.ToString()
}

# =============================================================================
# CONTENT EMBEDDING
# =============================================================================

<#
.SYNOPSIS
    Rejects content that cannot be embedded in a single-quoted here-string.
.DESCRIPTION
    Such a here-string ends at the first line beginning with '@, so a line starting that
    way silently closes it early and turns the rest of the content into code. Caught by
    name here rather than left to the parse check, which would report a syntax error
    thousands of lines away from the asset that caused it.
#>
function Test-BuildEmbeddableContent {
    param(
        [Parameter(Mandatory=$true)] [string]$Content,
        [Parameter(Mandatory=$true)] [string]$Name
    )
    if ($Content -match "(?m)^\s*'@") {
        Write-Error "[Build] $Name contains a line starting with '@, which would terminate the here-string it is embedded in. Indent or reword that line."
        return $false
    }
    return $true
}

<#
.SYNOPSIS
    Builds the replacement function that returns embedded content verbatim.
#>
function New-BuildEmbeddedFunction {
    param(
        [Parameter(Mandatory=$true)] [string]$FunctionName,
        [Parameter(Mandatory=$true)] [string]$Content,
        [string]$Description = 'Content is maintained in separate files and embedded at build time.'
    )
    # Assembled with an explicit CRLF rather than written as a here-string. A here-string
    # would inherit the line endings of THIS file, so the generated wrapper - and with it
    # the bytes of every artifact - would change if a git filter or an editor ever stored
    # Build-Engine.ps1 differently. An engine meant to be copied between repositories has
    # to produce the same output in all of them.
    #
    # $Content is concatenated untouched: it is the asset, and it has to reach the
    # artifact byte for byte, mixed line endings included.
    $wrapperStart = @(
        '<#'
        '.SYNOPSIS'
        "    Returns the embedded content for $FunctionName."
        '.DESCRIPTION'
        "    $Description"
        '#>'
        "function $FunctionName {"
        "    return @'"
    ) -join "`r`n"

    $wrapperEnd = "`r`n'@`r`n}"

    return $wrapperStart + "`r`n" + $Content + $wrapperEnd
}

<#
.SYNOPSIS
    Replaces a marked region in a module with generated content.
.DESCRIPTION
    The region is marked in the source itself:

        #region BUILD:EMBED Get-HTMLTemplate
        ... development version of the function ...
        #endregion BUILD:EMBED

    A marker rather than a pattern matched against the function's doc comment, which is
    what this used to do: rewording that comment broke the match, and where the build
    only warned about it, every artifact shipped the development version - one that looks
    for template files next to itself, finds none, and returns nothing.
.OUTPUTS
    The rewritten content, or $null after reporting that the region was not found.
#>
function Set-BuildEmbedRegion {
    param(
        [Parameter(Mandatory=$true)] [string]$Content,
        [Parameter(Mandatory=$true)] [string]$RegionName,
        [Parameter(Mandatory=$true)] [string]$Replacement
    )
    $pattern = '(?s)[ \t]*#region\s+BUILD:EMBED\s+' + [regex]::Escape($RegionName) + '\b.*?#endregion\s+BUILD:EMBED[^\r\n]*'
    if ($Content -notmatch $pattern) {
        Write-Error "[Build] Region '#region BUILD:EMBED $RegionName' not found - the module cannot have its content embedded"
        return $null
    }
    return [regex]::Replace($Content, $pattern, { param($m) $Replacement }, 1)
}

<#
.SYNOPSIS
    Reads back what a built artifact actually carries in an embedded function.
.DESCRIPTION
    Used to prove that the text transformations left the embedded content alone. Returns
    $null when the function is missing or not in its embedded form.
#>
function Get-BuildEmbeddedContent {
    param(
        [Parameter(Mandatory=$true)] [string]$Path,
        [Parameter(Mandatory=$true)] [string]$FunctionName
    )
    $artifactText = Read-BuildFile -Path $Path
    $pattern = "(?s)function\s+" + [regex]::Escape($FunctionName) + "\s*\{\s*return\s+@'\r?\n(.*?)\r?\n'@"
    $match = [regex]::Match($artifactText, $pattern)
    if (-not $match.Success) { return $null }
    return $match.Groups[1].Value
}

# =============================================================================
# OBFUSCATED VARIANT
# =============================================================================

<#
.SYNOPSIS
    Wraps a script in a GZip + XOR + Base64 loader stub.
.DESCRIPTION
    Obfuscation, not encryption: the key travels with the payload. It defeats a plain
    string scan, nothing more, and the header says so.
#>
function New-BuildObfuscatedScript {
    param(
        [Parameter(Mandatory=$true)] [string]$Content,
        [Parameter(Mandatory=$true)] [string]$ProjectName,
        [Parameter(Mandatory=$true)] [string]$Version,
        [Parameter(Mandatory=$true)] [string]$Timestamp
    )
    $sourceBytes = [System.Text.Encoding]::UTF8.GetBytes($Content)

    $memoryStream = New-Object System.IO.MemoryStream
    $gzipStream = New-Object System.IO.Compression.GZipStream($memoryStream, [System.IO.Compression.CompressionMode]::Compress)
    $gzipStream.Write($sourceBytes, 0, $sourceBytes.Length)
    $gzipStream.Close()
    $compressedBytes = $memoryStream.ToArray()
    $memoryStream.Close()

    $xorKey = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($xorKey) } finally { $rng.Dispose() }

    $encryptedBytes = New-Object byte[] $compressedBytes.Length
    for ($i = 0; $i -lt $compressedBytes.Length; $i++) {
        $encryptedBytes[$i] = $compressedBytes[$i] -bxor $xorKey[$i % $xorKey.Length]
    }

    $payloadBase64 = [Convert]::ToBase64String($encryptedBytes)
    $keyBase64 = [Convert]::ToBase64String($xorKey)

    $script = @"
<#
.SYNOPSIS
    $ProjectName - Obfuscated Version
    Version: $Version
    Build: $Timestamp

.DESCRIPTION
    This is an obfuscated version of $ProjectName for authorized penetration testing.
    The payload is GZip compressed, XOR encoded, and Base64 encoded.

    AUTHORIZED SECURITY TESTING ONLY!

.NOTES
    Deobfuscation: Base64 decode -> XOR decode -> GZip decompress -> Execute
    The key is stored alongside the payload; this hides the contents from a string
    scan, it does not protect them.
#>

# Encoded payload and key
`$_k = '$keyBase64'
`$_d = '$payloadBase64'

# Decode
`$_kb = [Convert]::FromBase64String(`$_k)
`$_db = [Convert]::FromBase64String(`$_d)

# XOR decode
`$_xb = New-Object byte[] `$_db.Length
for (`$_i = 0; `$_i -lt `$_db.Length; `$_i++) {
    `$_xb[`$_i] = `$_db[`$_i] -bxor `$_kb[`$_i % `$_kb.Length]
}

# GZip decompress
`$_ms = New-Object System.IO.MemoryStream(,`$_xb)
`$_gz = New-Object System.IO.Compression.GZipStream(`$_ms, [System.IO.Compression.CompressionMode]::Decompress)
`$_sr = New-Object System.IO.StreamReader(`$_gz)
`$_sc = `$_sr.ReadToEnd()
`$_sr.Close()
`$_gz.Close()
`$_ms.Close()

# Get list of functions BEFORE loading
`$_beforeFunctions = @(Get-Command -CommandType Function -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)

# Execute in current scope
. ([ScriptBlock]::Create(`$_sc)) | Out-Null

# Get list of functions AFTER loading
`$_afterFunctions = @(Get-Command -CommandType Function -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)

# Export the new ones to global scope
`$_newFunctions = `$_afterFunctions | Where-Object { `$_ -notin `$_beforeFunctions }

foreach (`$_funcName in `$_newFunctions) {
    `$_func = Get-Command -Name `$_funcName -CommandType Function -ErrorAction SilentlyContinue
    if (`$_func) {
        Set-Item -Path "function:global:`$_funcName" -Value `$_func.ScriptBlock
    }
}

# Cleanup temporary variables
Remove-Variable -Name '_k','_d','_kb','_db','_xb','_i','_ms','_gz','_sr','_sc','_beforeFunctions','_afterFunctions','_newFunctions','_funcName','_func' -ErrorAction SilentlyContinue
"@

    # Normalized for the same reason as the embedded wrapper above: the stub comes out of a
    # here-string in this file, so its line endings would otherwise be whatever this file
    # happens to be stored with. Safe to normalize wholesale - the payload is a single
    # Base64 line and carries no content that has to stay byte-exact.
    $script = $script -replace "\r?\n", "`r`n"

    return [PSCustomObject]@{
        Script           = $script
        SourceLength     = $sourceBytes.Length
        CompressedLength = $compressedBytes.Length
    }
}

# =============================================================================
# CODE SIGNING
# =============================================================================

<#
.SYNOPSIS
    Signs the given files with Authenticode.
.DESCRIPTION
    Signing does not require the certificate to chain to a root this build host trusts.
    A self-signed or internal-CA certificate produces a perfectly valid signature; those
    are reported as signed-but-not-verifiable-here rather than as failures, because
    whether a chain verifies on the build machine says nothing about the signature.
.OUTPUTS
    An object with Signed, Total, Untrusted and UnTimestamped counts, or $null when the
    certificate could not be used at all.
#>
function Invoke-BuildCodeSigning {
    param(
        [Parameter(Mandatory=$true)] [string[]]$Path,
        [Parameter(Mandatory=$true)] [string]$CertificatePath,
        $CertPassword,
        [string]$TimestampServer
    )
    if (-not (Test-Path $CertificatePath)) {
        Write-Error "[Build] Certificate file not found: $CertificatePath"
        return $null
    }

    Write-Host "[Build]   - Loading certificate: $CertificatePath" -ForegroundColor Gray
    try {
        $certFilePath = (Resolve-Path $CertificatePath).Path

        $securePassword = $null
        if ($CertPassword) {
            $securePassword = if ($CertPassword -is [System.Security.SecureString]) {
                $CertPassword
            } else {
                ConvertTo-SecureString -String ([string]$CertPassword) -AsPlainText -Force
            }
        }

        # The X509Certificate2 constructor, not Get-PfxCertificate: that cmdlet only grew a
        # -Password parameter in PowerShell 6, so on Windows PowerShell 5.1 every attempt to
        # sign with a password-protected PFX died with "A parameter cannot be found that
        # matches parameter name Password".
        $signingCert = if ($securePassword) {
            New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certFilePath, $securePassword)
        } else {
            New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certFilePath)
        }
    }
    catch {
        Write-Error "[Build] Failed to load certificate: $_"
        return $null
    }

    # Checked outside the try above on purpose: $ErrorActionPreference is Stop in the
    # caller, so a Write-Error inside it throws and the catch re-wraps it - the EKU
    # rejection came out as "Failed to load certificate: ... does not have Code Signing
    # EKU", blaming the file for something that is true of its contents.
    $codeSigningEku = $signingCert.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq '1.3.6.1.5.5.7.3.3' }
    if (-not $codeSigningEku) {
        Write-Error "[Build] Certificate does not have Code Signing EKU (1.3.6.1.5.5.7.3.3)"
        return $null
    }
    if (-not $signingCert.HasPrivateKey) {
        Write-Error "[Build] Certificate has no private key - a PFX exported without one cannot sign"
        return $null
    }

    Write-Host "[Build]     Subject: $($signingCert.Subject)" -ForegroundColor Gray
    Write-Host "[Build]     Issuer: $($signingCert.Issuer)" -ForegroundColor Gray
    Write-Host "[Build]     Valid until: $($signingCert.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor Gray
    Write-Host "[Build]     Timestamp server: $TimestampServer" -ForegroundColor Gray

    $signed = 0
    $untrusted = 0
    $unTimestamped = 0

    foreach ($file in $Path) {
        $fileName = Split-Path $file -Leaf
        Write-Host "[Build]   - Signing $fileName..." -ForegroundColor Gray -NoNewline

        try {
            $signParams = @{
                FilePath      = $file
                Certificate   = $signingCert
                HashAlgorithm = 'SHA256'
            }
            if ($TimestampServer) { $signParams['TimestampServer'] = $TimestampServer }

            [void](Set-AuthenticodeSignature @signParams)

            # Read the result back off the file rather than trusting the return value.
            # Status answers "does this signature verify on THIS machine right now", which
            # is not the question a build is asking. Only NotSigned and HashMismatch mean
            # nothing usable was written.
            $verify = Get-AuthenticodeSignature -FilePath $file
            $hasSignature = $verify.SignerCertificate -and
                            $verify.Status -ne 'NotSigned' -and
                            $verify.Status -ne 'HashMismatch'

            if (-not $hasSignature) {
                Write-Host " FAILED ($($verify.StatusMessage))" -ForegroundColor Red
                continue
            }

            $signed++

            # A signature without a countersignature stops verifying the day the
            # certificate expires, and the timestamp server is reached over the network -
            # so this is the part that quietly goes missing on an offline build host.
            if ($TimestampServer -and -not $verify.TimeStamperCertificate) { $unTimestamped++ }

            if ($verify.Status -eq 'Valid') {
                Write-Host " OK" -ForegroundColor Green
            } else {
                $untrusted++
                Write-Host " OK (signed; not verifiable on this host: $($verify.Status))" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host " ERROR ($_)" -ForegroundColor Red
        }
    }

    return [PSCustomObject]@{
        Signed        = $signed
        Total         = @($Path).Count
        Untrusted     = $untrusted
        UnTimestamped = $unTimestamped
        NotAfter      = $signingCert.NotAfter
    }
}

# =============================================================================
# CONSOLE EXECUTABLE
# =============================================================================

<#
.SYNOPSIS
    Packs a built script into a console executable that hosts the PowerShell console host.
.DESCRIPTION
    The executable runs Microsoft.PowerShell.ConsoleShell - the console host powershell.exe
    itself is - in its own process, with the script embedded as a resource as it is. At
    start it dot-sources the script into the global scope, which is what Import-Module of a
    .ps1 does at a prompt, so functions and script state behave exactly as there: the prompt,
    tab completion, history and PSReadLine are the console host's own.

    Without arguments the executable stays at the prompt. With arguments it runs them as a
    command and exits with that command's exit code; they are joined the way
    powershell.exe -Command joins them, and a leading -Command or -c is accepted. The host
    always starts with -NoProfile, so no profile of the machine it runs on is loaded.

    Compiled with the C# compiler of the .NET Framework through CodeDom, so nothing has to
    be installed. CodeDom compilation does not exist in PowerShell 7, so the compiler runs in
    a Windows PowerShell 5.1 child process whichever edition runs the build - which also
    references the console host of Windows PowerShell 5.1, the one the executable runs on.

    The executable needs Windows PowerShell 5.1 on the machine it runs on.
.PARAMETER ScriptPath
    The built script to embed. Its file name becomes the resource name.
.PARAMETER OutputPath
    The executable to write.
.PARAMETER Title
    Product name: banner text and the assembly's title and product attributes.
.PARAMETER Version
    The build version, as the executable's informational version. Its leading numeric part
    (up to four components) becomes the file and assembly version.
.PARAMETER Description
    The assembly's description attribute.
.PARAMETER Author
    The assembly's copyright attribute.
.PARAMETER IconPath
    Optional. An .ico file to give the executable as its icon. Without it, Windows shows the
    default application icon.
.OUTPUTS
    The written executable's FileInfo, or $null when compilation failed.
#>
function New-BuildConsoleExecutable {
    param(
        [Parameter(Mandatory=$true)] [string]$ScriptPath,
        [Parameter(Mandatory=$true)] [string]$OutputPath,
        [Parameter(Mandatory=$true)] [string]$Title,
        [Parameter(Mandatory=$true)] [string]$Version,
        [string]$Description = '',
        [string]$Author = '',
        [string]$IconPath
    )

    if (-not (Test-Path -LiteralPath $ScriptPath)) {
        Write-Error "[Build] Script to embed not found: $ScriptPath"
        return $null
    }
    if ($IconPath -and -not (Test-Path -LiteralPath $IconPath)) {
        Write-Error "[Build] Icon not found: $IconPath"
        return $null
    }
    $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $windowsPowerShell)) {
        Write-Error "[Build] Windows PowerShell 5.1 not found ($windowsPowerShell) - it compiles the executable"
        return $null
    }

    # A C# string literal: backslash and quote escaped, nothing else can occur in these.
    $literal = { param([string]$Text) $Text.Replace('\', '\\').Replace('"', '\"') }

    # The file and assembly version is numeric; the build version may carry +date.
    $numericVersion = '0.0.0.0'
    if ($Version -match '^(\d+)(\.\d+){0,3}') {
        $parts = @($Matches[0].Split('.'))
        while ($parts.Count -lt 4) { $parts += '0' }
        $numericVersion = $parts -join '.'
    }

    $resourceName = Split-Path -Leaf $ScriptPath
    $source = @'
using System;
using System.IO;
using System.Reflection;
using System.Text;
using System.Management.Automation.Runspaces;

[assembly: AssemblyTitle("{TITLE}")]
[assembly: AssemblyProduct("{TITLE}")]
[assembly: AssemblyDescription("{DESCRIPTION}")]
[assembly: AssemblyCopyright("{AUTHOR}")]
[assembly: AssemblyVersion("{NUMERIC_VERSION}")]
[assembly: AssemblyFileVersion("{NUMERIC_VERSION}")]
[assembly: AssemblyInformationalVersion("{VERSION}")]

namespace BuildConsoleHost
{
    public static class Payload
    {
        // The embedded script as text, read from inside the session by the loader command.
        public static string Text
        {
            get
            {
                using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("{RESOURCE}"))
                {
                    if (stream == null) { throw new InvalidOperationException("Embedded script {RESOURCE} not found"); }
                    using (StreamReader reader = new StreamReader(stream, Encoding.UTF8, true))
                    {
                        return reader.ReadToEnd();
                    }
                }
            }
        }
    }

    public static class Program
    {
        [STAThread]
        public static int Main(string[] args)
        {
            // Dot-sourced at the top level of the session: functions and $Script: state land in
            // the global scope, as after Import-Module of the .ps1 at a prompt.
            const string load = ". ([ScriptBlock]::Create([BuildConsoleHost.Payload]::Text))";

            int skip = 0;
            if (args.Length > 0 && (args[0].Equals("-Command", StringComparison.OrdinalIgnoreCase) ||
                                    args[0].Equals("-c", StringComparison.OrdinalIgnoreCase)))
            {
                skip = 1;
            }

            string[] hostArgs;
            if (args.Length - skip == 0)
            {
                hostArgs = new string[] { "-NoLogo", "-NoProfile", "-NoExit", "-Command", load };
            }
            else
            {
                // As powershell.exe -Command: the remaining arguments are joined with spaces.
                hostArgs = new string[args.Length - skip + 4];
                hostArgs[0] = "-NoLogo";
                hostArgs[1] = "-NoProfile";
                hostArgs[2] = "-Command";
                hostArgs[3] = load + ";";
                Array.Copy(args, skip, hostArgs, 4, args.Length - skip);
            }

#pragma warning disable 618
            RunspaceConfiguration configuration = RunspaceConfiguration.Create();
#pragma warning restore 618
            return Microsoft.PowerShell.ConsoleShell.Start(configuration, "{TITLE}", "", hostArgs);
        }
    }
}
'@
    $source = $source.Replace('{TITLE}', (& $literal $Title)).
                      Replace('{DESCRIPTION}', (& $literal $Description)).
                      Replace('{AUTHOR}', (& $literal $Author)).
                      Replace('{NUMERIC_VERSION}', $numericVersion).
                      Replace('{VERSION}', (& $literal $Version)).
                      Replace('{RESOURCE}', (& $literal $resourceName))

    # Runs in the Windows PowerShell 5.1 child. The console host assembly is the child's own,
    # so the reference is the one the executable will find on the target.
    $compiler = @'
param([string]$SourcePath, [string]$ResourcePath, [string]$OutputPath, [string]$IconPath)
$ErrorActionPreference = 'Stop'
$consoleHost = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'Microsoft.PowerShell.ConsoleHost' }
if (-not $consoleHost) { [Console]::Error.WriteLine('Microsoft.PowerShell.ConsoleHost is not loaded'); exit 2 }
$provider = New-Object Microsoft.CSharp.CSharpCodeProvider
$parameters = New-Object System.CodeDom.Compiler.CompilerParameters
$parameters.GenerateExecutable = $true
$parameters.OutputAssembly = $OutputPath
$parameters.CompilerOptions = '/optimize /platform:anycpu'
if ($IconPath) { $parameters.CompilerOptions += ' /win32icon:"' + $IconPath + '"' }
[void]$parameters.ReferencedAssemblies.Add('System.dll')
[void]$parameters.ReferencedAssemblies.Add([System.Management.Automation.PSObject].Assembly.Location)
[void]$parameters.ReferencedAssemblies.Add($consoleHost.Location)
[void]$parameters.EmbeddedResources.Add($ResourcePath)
$result = $provider.CompileAssemblyFromFile($parameters, $SourcePath)
if ($result.Errors.HasErrors) {
    foreach ($compileError in $result.Errors) { [Console]::Error.WriteLine($compileError.ToString()) }
    exit 1
}
exit 0
'@

    $workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("build-exe-" + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $workDir
    try {
        $sourcePath = Join-Path $workDir 'Program.cs'
        $compilerPath = Join-Path $workDir 'Compile.ps1'
        $tempOutput = Join-Path $workDir (Split-Path -Leaf $OutputPath)
        [System.IO.File]::WriteAllText($sourcePath, $source, (New-Object System.Text.UTF8Encoding($false)))
        [System.IO.File]::WriteAllText($compilerPath, $compiler, (New-Object System.Text.UTF8Encoding($true)))

        $resourcePath = (Resolve-Path -LiteralPath $ScriptPath).Path
        # -IconPath only when there is one: Windows PowerShell 5.1 drops an empty argument
        # to a native program, and the child would then fail on a parameter without value.
        $compilerArgs = @('-NoProfile', '-NonInteractive', '-File', $compilerPath,
                          '-SourcePath', $sourcePath, '-ResourcePath', $resourcePath, '-OutputPath', $tempOutput)
        if ($IconPath) { $compilerArgs += @('-IconPath', (Resolve-Path -LiteralPath $IconPath).Path) }
        $compileOutput = & $windowsPowerShell @compilerArgs 2>&1
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0 -or -not (Test-Path -LiteralPath $tempOutput)) {
            foreach ($line in @($compileOutput)) { Write-Host "[Build]   $line" -ForegroundColor Red }
            Write-Error "[Build] Compiling $(Split-Path -Leaf $OutputPath) failed (exit code $exitCode)"
            return $null
        }

        # Written next to the target and swapped in, as Write-BuildFile does for the scripts:
        # a failed copy must not leave the previous executable deleted.
        Copy-Item -LiteralPath $tempOutput -Destination $OutputPath -Force
        return (Get-Item -LiteralPath $OutputPath)
    }
    finally {
        Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
