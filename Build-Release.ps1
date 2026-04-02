<#
.SYNOPSIS
    Build script for adPEAS v2 release versions.

.DESCRIPTION
    Combines all modules into a single standalone .ps1 file.
    Creates four versions:
    - adPEAS.ps1 (readable, with comments)
    - adPEAS_min.ps1 (minimized, compact)
    - adPEAS_ultra.ps1 (ultra-compressed, no comments)
    - adPEAS_obf.ps1 (obfuscated: GZip + XOR + Base64)

.PARAMETER License
    Path to a license.json file to embed into the build.
    If specified, the license will be Base64-encoded and embedded into the output scripts.

.PARAMETER Stable
    Creates a stable release build with a clean version number (e.g. "2.0.0").
    Without this switch, builds include a timestamp suffix (e.g. "2.0.0+20260215-1840").

.PARAMETER CodeSigningCert
    Path to a PKCS#12 (.pfx) code signing certificate file.
    If specified, all build outputs will be signed with Authenticode after the build completes.
    The certificate must have the Code Signing enhanced key usage (EKU).

.PARAMETER CertPassword
    Password for the code signing certificate (if the PFX is password-protected).
    Accepts String or SecureString.

.PARAMETER TimestampServer
    URL of a RFC 3161 timestamp server for Authenticode timestamping.
    Default: http://timestamp.digicert.com
    Timestamping ensures the signature remains valid after the certificate expires.

.EXAMPLE
    .\Build-Release.ps1

.EXAMPLE
    .\Build-Release.ps1 -Stable -License .\license.json

.EXAMPLE
    .\Build-Release.ps1 -CodeSigningCert .\codesigning.pfx

.EXAMPLE
    .\Build-Release.ps1 -CodeSigningCert .\codesigning.pfx -CertPassword "P@ss" -TimestampServer "http://timestamp.sectigo.com"

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$License,

    [Parameter(Mandatory=$false)]
    [switch]$Stable,

    [Parameter(Mandatory=$false)]
    [string]$CodeSigningCert,

    [Parameter(Mandatory=$false)]
    $CertPassword,

    [Parameter(Mandatory=$false)]
    [string]$TimestampServer = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"

# Helper: Write file with retry logic (handles Dropbox/AV/editor file locks)
# Writes to a temp file first, then moves to target to minimize lock window
function Write-BuildFile {
    param(
        [Parameter(Mandatory=$true)] [string]$Path,
        [Parameter(Mandatory=$true)] [string]$Content,
        [int]$MaxRetries = 5,
        [int]$RetryDelayMs = 500
    )
    $tempPath = "$Path.tmp.$PID"
    try {
        # Write to temp file (no lock contention)
        $Content | Out-File -FilePath $tempPath -Encoding UTF8 -ErrorAction Stop

        # Move temp to target with retry (target may be locked by Dropbox/AV)
        for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
            try {
                # Remove target first if it exists (Move-Item can't overwrite)
                if (Test-Path $Path) {
                    Remove-Item -Path $Path -Force -ErrorAction Stop
                }
                Move-Item -Path $tempPath -Destination $Path -Force -ErrorAction Stop
                return
            }
            catch [System.IO.IOException] {
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
        # Cleanup temp file if still exists
        if (Test-Path $tempPath) {
            Remove-Item -Path $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}

# Paths
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourcePath = Join-Path $ScriptRoot "src"
# Build output goes directly to project root for easy access
$ReleasePath = $ScriptRoot

Write-Host "[Build] adPEAS v2 Build Script started" -ForegroundColor Cyan
Write-Host "[Build] Source: $SourcePath" -ForegroundColor Gray
Write-Host "[Build] Output: $ReleasePath (project root)" -ForegroundColor Gray

# ========================================
# READ MODULE LIST AND VERSION FROM SOURCE
# ========================================
$MainScriptPath = Join-Path $SourcePath "adPEAS.ps1"
$MainScriptContent = Get-Content $MainScriptPath -Raw

# Extract base version from src/adPEAS.ps1
if ($MainScriptContent -match '\$Script:adPEASVersion = "([^"]*)"') {
    $BaseVersion = $Matches[1]
} else {
    Write-Error "[Build] Could not find `$Script:adPEASVersion in src/adPEAS.ps1"
    return
}

# Build timestamp and version
$BuildTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

if ($Stable) {
    $BuildVersion = $BaseVersion
    Write-Host "[Build] Build Version: $BuildVersion (stable release)" -ForegroundColor Cyan
} else {
    $BuildVersionSuffix = Get-Date -Format "yyyyMMdd-HHmm"
    $BuildVersion = "${BaseVersion}+${BuildVersionSuffix}"
    Write-Host "[Build] Build Version: $BuildVersion (dev build)" -ForegroundColor Cyan
}
Write-Host "[Build] Build Time: $BuildTimestamp" -ForegroundColor Gray

# Parse module list from dot-source lines in src/adPEAS.ps1
# Format: . "$Script:ScriptPath\modules\Category\File.ps1"
# Category comments: # Core Modules, # Helper Modules, etc.
$CoreModules = @()
$HelperModules = @()
$CheckModules = @()
$ReportingModules = @()
$CollectorModules = @()

$currentCategory = $null
foreach ($line in $MainScriptContent -split '\r?\n') {
    # Detect category comment
    if ($line -match '^\s+#\s+(Core|Helper|Check|Reporting|Collector)\s+Modules') {
        $currentCategory = $Matches[1]
        continue
    }
    # Parse dot-source line
    if ($line -match '^\s+\.\s+"\$Script:ScriptPath\\(.+)"') {
        $modulePath = $Matches[1]
        switch ($currentCategory) {
            'Core'      { $CoreModules += $modulePath }
            'Helper'    { $HelperModules += $modulePath }
            'Check'     { $CheckModules += $modulePath }
            'Reporting' { $ReportingModules += $modulePath }
            'Collector' { $CollectorModules += $modulePath }
            default     { Write-Warning "[Build] Module without category: $modulePath" }
        }
    }
}

$totalModules = $CoreModules.Count + $HelperModules.Count + $CheckModules.Count + $ReportingModules.Count + $CollectorModules.Count
Write-Host "[Build] Parsed $totalModules modules from src/adPEAS.ps1:" -ForegroundColor Gray
Write-Host "[Build]   Core: $($CoreModules.Count), Helper: $($HelperModules.Count), Check: $($CheckModules.Count), Reporting: $($ReportingModules.Count), Collector: $($CollectorModules.Count)" -ForegroundColor Gray

if ($totalModules -eq 0) {
    Write-Error "[Build] No modules found in src/adPEAS.ps1! Check module loading section format."
    return
}

# ====================
# 1. READABLE VERSION
# ====================
Write-Host "`n[Build] Creating readable version: adPEAS.ps1" -ForegroundColor Yellow

$ReadableOutput = @()

# Header
$ReadableOutput += @"
<#
.SYNOPSIS
    adPEAS v2 - Active Directory Privilege Escalation Awesome Scripts

.DESCRIPTION
    Build: $BuildTimestamp
    Version: $BuildVersion

    AUTHORIZED SECURITY TESTING ONLY!

.NOTES
    Author: Alexander Sturz (@_61106960_)

.LINK
    https://github.com/61106960/adPEAS
#>

"@

Write-Host "[Build]   - Loading Core modules..." -ForegroundColor Gray

$ReadableOutput += "`n# =============================================="
$ReadableOutput += "# CORE MODULES"
$ReadableOutput += "# ==============================================`n"

foreach ($Module in $CoreModules) {
    $ModulePath = Join-Path $SourcePath $Module
    $ModuleName = Split-Path $Module -Leaf

    Write-Host "[Build]     - $ModuleName" -ForegroundColor DarkGray

    $ReadableOutput += "# ----- $ModuleName -----`n"
    $Content = Get-Content $ModulePath -Raw
    # Remove Export-ModuleMember lines (not needed in standalone)
    $Content = $Content -replace "(?m)^.*Export-ModuleMember.*$", ""
    $ReadableOutput += $Content
    $ReadableOutput += "`n"
}

Write-Host "[Build]   - Loading Helper modules..." -ForegroundColor Gray

$ReadableOutput += "`n# =============================================="
$ReadableOutput += "# HELPER MODULES"
$ReadableOutput += "# ==============================================`n"

foreach ($Module in $HelperModules) {
    $ModulePath = Join-Path $SourcePath $Module
    $ModuleName = Split-Path $Module -Leaf

    Write-Host "[Build]     - $ModuleName" -ForegroundColor DarkGray

    $ReadableOutput += "# ----- $ModuleName -----`n"
    $Content = Get-Content $ModulePath -Raw
    $Content = $Content -replace "(?m)^.*Export-ModuleMember.*$", ""
    $ReadableOutput += $Content
    $ReadableOutput += "`n"
}

Write-Host "[Build]   - Loading Check modules..." -ForegroundColor Gray

$ReadableOutput += "`n# =============================================="
$ReadableOutput += "# CHECK MODULES"
$ReadableOutput += "# ==============================================`n"

foreach ($Module in $CheckModules) {
    $ModulePath = Join-Path $SourcePath $Module
    $ModuleName = Split-Path $Module -Leaf

    Write-Host "[Build]     - $ModuleName" -ForegroundColor DarkGray

    $ReadableOutput += "# ----- $ModuleName -----`n"
    $Content = Get-Content $ModulePath -Raw
    $Content = $Content -replace "(?m)^.*Export-ModuleMember.*$", ""
    $ReadableOutput += $Content
    $ReadableOutput += "`n"
}

Write-Host "[Build]   - Loading Reporting modules..." -ForegroundColor Gray

$ReadableOutput += "`n# =============================================="
$ReadableOutput += "# REPORTING MODULES"
$ReadableOutput += "# ==============================================`n"

# Load HTML report templates from separate files and embed them
$TemplatesDir = Join-Path $SourcePath "modules\Reporting\templates"
$HtmlTemplatePath = Join-Path $TemplatesDir "report-template.html"
$CssPath = Join-Path $TemplatesDir "report-styles.css"
$JsPath = Join-Path $TemplatesDir "report-scripts.js"

$TemplatesExist = (Test-Path $HtmlTemplatePath) -and (Test-Path $CssPath) -and (Test-Path $JsPath)

$DiffTemplatePath = Join-Path $TemplatesDir "diff-template.html"
$DiffTemplateExists = Test-Path $DiffTemplatePath

if ($TemplatesExist) {
    Write-Host "[Build]     - Loading HTML report templates from separate files..." -ForegroundColor DarkGray
    $HtmlTemplate = Get-Content $HtmlTemplatePath -Raw -Encoding UTF8
    $CssContent = Get-Content $CssPath -Raw -Encoding UTF8
    $JsContent = Get-Content $JsPath -Raw -Encoding UTF8

    # Combine templates: Replace {{CSS_CONTENT}} and {{JS_CONTENT}} placeholders
    $CombinedTemplate = $HtmlTemplate.Replace('{{CSS_CONTENT}}', $CssContent)
    $CombinedTemplate = $CombinedTemplate.Replace('{{JS_CONTENT}}', $JsContent)

    Write-Host "[Build]       CSS: $($CssContent.Length) bytes" -ForegroundColor DarkGray
    Write-Host "[Build]       JS: $($JsContent.Length) bytes" -ForegroundColor DarkGray
    Write-Host "[Build]       Combined: $($CombinedTemplate.Length) bytes" -ForegroundColor DarkGray
}

if ($DiffTemplateExists) {
    $DiffTemplateContent = Get-Content $DiffTemplatePath -Raw -Encoding UTF8
    Write-Host "[Build]       Diff template: $($DiffTemplateContent.Length) bytes" -ForegroundColor DarkGray
}

foreach ($Module in $ReportingModules) {
    $ModulePath = Join-Path $SourcePath $Module
    $ModuleName = Split-Path $Module -Leaf

    Write-Host "[Build]     - $ModuleName" -ForegroundColor DarkGray

    $ReadableOutput += "# ----- $ModuleName -----`n"
    $Content = Get-Content $ModulePath -Raw
    $Content = $Content -replace "(?m)^.*Export-ModuleMember.*$", ""

    # For Compare-adPEASReport.ps1: Replace Get-DiffHTMLTemplate function with embedded template
    if ($ModuleName -eq "Compare-adPEASReport.ps1" -and $DiffTemplateExists) {
        Write-Host "[Build]       Embedding diff template into Get-DiffHTMLTemplate function..." -ForegroundColor DarkGray

        $NewGetDiffTemplate = @"
<#
.SYNOPSIS
    Returns the diff HTML template.
.DESCRIPTION
    This function contains the embedded diff report template.
    Template is maintained in templates/diff-template.html and embedded at build time.
#>
function Get-DiffHTMLTemplate {
    return @'
$DiffTemplateContent
'@
}
"@

        # Match the dev version of Get-DiffHTMLTemplate
        $DiffPattern = '(?s)<#[\r\n]+\.SYNOPSIS[\r\n]+\s+Loads the diff HTML template from template files or embedded content\..*?function Get-DiffHTMLTemplate \{.*?return \$null[\r\n]+\}'
        if ($Content -match $DiffPattern) {
            $Content = [regex]::Replace($Content, $DiffPattern, $NewGetDiffTemplate)
            Write-Host "[Build]       Diff template embedded successfully" -ForegroundColor Green
        } else {
            Write-Warning "[Build] Could not find Get-DiffHTMLTemplate function in Compare-adPEASReport.ps1 - diff template not embedded"
        }
    }

    # For Export-HTMLReport.ps1: Replace Get-HTMLTemplate function with embedded templates
    if ($ModuleName -eq "Export-HTMLReport.ps1" -and $TemplatesExist) {
        Write-Host "[Build]       Embedding HTML templates into Get-HTMLTemplate function..." -ForegroundColor DarkGray

        # Build the new Get-HTMLTemplate function with embedded content
        $NewGetHTMLTemplate = @"
<#
.SYNOPSIS
    Returns the HTML template with CSS and JavaScript.
.DESCRIPTION
    This function contains the embedded HTML report template.
    Templates are maintained in separate files (templates/) and embedded at build time.
#>
function Get-HTMLTemplate {
    return @'
$CombinedTemplate
'@
}
"@

        # Match the dev version: Synopsis+Description block followed by function with file-loading logic
        $Pattern = '(?s)<#[\r\n]+\.SYNOPSIS[\r\n]+\s+Returns the HTML template with CSS and JavaScript\.[\r\n]+\.DESCRIPTION[\r\n]+\s+During development:.*?function Get-HTMLTemplate \{.*?return \$null[\r\n]+\}'
        if ($Content -match $Pattern) {
            $Content = [regex]::Replace($Content, $Pattern, $NewGetHTMLTemplate)
            Write-Host "[Build]       Template embedded successfully" -ForegroundColor Green
        } else {
            Write-Error "[Build] Could not find Get-HTMLTemplate function in Export-HTMLReport.ps1!"
            return
        }
    }

    $ReadableOutput += $Content
    $ReadableOutput += "`n"
}

Write-Host "[Build]   - Loading Collector modules..." -ForegroundColor Gray

$ReadableOutput += "`n# =============================================="
$ReadableOutput += "# COLLECTOR MODULES"
$ReadableOutput += "# ==============================================`n"

foreach ($Module in $CollectorModules) {
    $ModulePath = Join-Path $SourcePath $Module
    $ModuleName = Split-Path $Module -Leaf

    Write-Host "[Build]     - $ModuleName" -ForegroundColor DarkGray

    $ReadableOutput += "# ----- $ModuleName -----`n"
    $Content = Get-Content $ModulePath -Raw
    $Content = $Content -replace "(?m)^.*Export-ModuleMember.*$", ""
    $ReadableOutput += $Content
    $ReadableOutput += "`n"
}

Write-Host "[Build]   - Loading main logic..." -ForegroundColor Gray

# Main script content (already loaded above for module parsing)
$MainContent = $MainScriptContent

# Extract only relevant part (parameters and main logic, without . imports)
# Remove entire module loading section (from "Load Modules" to "Main Function")
$MainContent = $MainContent -replace "(?s)# ===== Load Modules =====.*?# ===== Main Function =====", "# ===== Main Function ====="

# Validate that the module loading section was actually removed
if ($MainContent -match '# ===== Load Modules =====') {
    Write-Error "[Build] FAILED: Module loading section was not removed! Check section markers in src/adPEAS.ps1."
    return
}

# Replace version string with build version (matches any semver pattern like "2.0.0", "3.1.2", etc.)
$MainContent = $MainContent -replace '(\$Script:adPEASVersion = ")[^"]*(")', "`${1}$BuildVersion`${2}"

# Embed license if -License parameter was provided
if ($License) {
    $LicenseFilePath = $License
    if (-not (Test-Path $LicenseFilePath)) {
        Write-Error "[Build] License file not found: $LicenseFilePath"
        return
    }
    Write-Host "[Build]   - Embedding license from: $LicenseFilePath" -ForegroundColor Gray
    try {
        $LicenseJsonRaw = Get-Content $LicenseFilePath -Raw -Encoding UTF8
        $LicenseObj = $LicenseJsonRaw | ConvertFrom-Json
        if ($LicenseObj.Licensee -and $LicenseObj.ValidUntil -and $LicenseObj.Signature) {
            $LicenseBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($LicenseJsonRaw))
            $MainContent = $MainContent -replace '\$Script:EmbeddedLicense = \$null', "`$Script:EmbeddedLicense = `"$LicenseBase64`""
            Write-Host "[Build]     Licensee: $($LicenseObj.Licensee)" -ForegroundColor Green
            Write-Host "[Build]     Valid until: $($LicenseObj.ValidUntil)" -ForegroundColor Green
        }
        else {
            Write-Error "[Build] Invalid license.json format (missing Licensee, ValidUntil, or Signature)"
            return
        }
    }
    catch {
        Write-Error "[Build] Failed to embed license: $_"
        return
    }
}
else {
    Write-Host "[Build]   - No license specified - building without embedded license" -ForegroundColor DarkGray
}

$ReadableOutput += "`n# =============================================="
$ReadableOutput += "# MAIN LOGIC"
$ReadableOutput += "# ==============================================`n"
$ReadableOutput += $MainContent

# Write readable version
$ReadableOutputPath = Join-Path $ReleasePath "adPEAS.ps1"
Write-BuildFile -Path $ReadableOutputPath -Content ($ReadableOutput -join "`n")
Write-Host "[Build] Readable version created: $ReadableOutputPath" -ForegroundColor Green

$ReadableSize = (Get-Item $ReadableOutputPath).Length / 1KB
Write-Host "[Build] Size: $([Math]::Round($ReadableSize, 2)) KB" -ForegroundColor Gray

# ====================
# 2. MINIMIZED VERSION
# ====================
Write-Host "`n[Build] Creating minimized version: adPEAS_min.ps1" -ForegroundColor Yellow

$MinContent = Get-Content $ReadableOutputPath -Raw

# Minimization (lighter than ultra, but no Synopsis preservation due to regex complexity)
Write-Host "[Build]   - Removing comments..." -ForegroundColor Gray
# Remove ALL block comments
$MinContent = $MinContent -replace "(?s)<#.*?#>", ""
# Remove line comments (except #Requires)
$MinContent = $MinContent -replace "(?m)^[ \t]*#(?!Requires).*$", ""

Write-Host "[Build]   - Removing empty lines..." -ForegroundColor Gray
# Remove multiple empty lines
$MinContent = $MinContent -replace "(?m)^\s*$\r?\n", ""

Write-Host "[Build]   - Removing excess whitespace..." -ForegroundColor Gray
# Remove trailing whitespace
$MinContent = $MinContent -replace "(?m)[ \t]+$", ""

# Write minimized version
$MinOutputPath = Join-Path $ReleasePath "adPEAS_min.ps1"
Write-BuildFile -Path $MinOutputPath -Content $MinContent
Write-Host "[Build] Minimized version created: $MinOutputPath" -ForegroundColor Green

$MinSize = (Get-Item $MinOutputPath).Length / 1KB
Write-Host "[Build] Size: $([Math]::Round($MinSize, 2)) KB" -ForegroundColor Gray

$Savings = [Math]::Round((($ReadableSize - $MinSize) / $ReadableSize) * 100, 1)
Write-Host "[Build] Savings: $Savings %" -ForegroundColor Green

# ====================
# 3. ULTRA-COMPRESSED VERSION
# ====================
Write-Host "`n[Build] Creating ultra-compressed version: adPEAS_ultra.ps1" -ForegroundColor Yellow

$UltraContent = Get-Content $ReadableOutputPath -Raw

# Ultra minimization
Write-Host "[Build]   - Removing ALL comments (incl. Synopsis)..." -ForegroundColor Gray
# Remove ALL block comments (incl. Synopsis)
$UltraContent = $UltraContent -replace "(?s)<#.*?#>", ""
# Remove ALL line comments (incl. #Requires if present)
$UltraContent = $UltraContent -replace "(?m)^[ \t]*#.*$", ""

Write-Host "[Build]   - Removing empty lines..." -ForegroundColor Gray
# Remove ALL empty lines
$UltraContent = $UltraContent -replace "(?m)^\s*$\r?\n", ""

Write-Host "[Build]   - Removing excess whitespace..." -ForegroundColor Gray
# Remove trailing whitespace
$UltraContent = $UltraContent -replace "(?m)[ \t]+$", ""
# Remove leading whitespace (except in Here-Strings - careful!)
# Only safe reduction: multiple spaces at line start to minimum
$UltraContent = $UltraContent -replace "(?m)^    ", "`t"  # 4 Spaces -> 1 Tab
$UltraContent = $UltraContent -replace "(?m)^\t\t+", "`t"  # Multiple Tabs -> 1 Tab

Write-Host "[Build]   - Removing empty function blocks..." -ForegroundColor Gray
# Remove empty begin/end blocks (careful)
$UltraContent = $UltraContent -replace "(?m)^\s*begin\s*\{\s*\}\s*$", ""
$UltraContent = $UltraContent -replace "(?m)^\s*end\s*\{\s*\}\s*$", ""

Write-Host "[Build]   - Removing Write-Log statements (verbose logging)..." -ForegroundColor Gray
# Remove Write-Log (for OPSEC - no debug/verbose output)
$UltraContent = $UltraContent -replace "(?m)^\s*Write-Log\s+.*$", ""
# Also remove any remaining Write-Verbose (legacy)
$UltraContent = $UltraContent -replace "(?m)^\s*Write-Verbose.*$", ""

# Final cleanup: double empty lines created by deletions
$UltraContent = $UltraContent -replace "(?m)^\s*$\r?\n", ""

# Write ultra-compressed version
$UltraOutputPath = Join-Path $ReleasePath "adPEAS_ultra.ps1"
Write-BuildFile -Path $UltraOutputPath -Content $UltraContent
Write-Host "[Build] Ultra-compressed version created: $UltraOutputPath" -ForegroundColor Green

$UltraSize = (Get-Item $UltraOutputPath).Length / 1KB
Write-Host "[Build] Size: $([Math]::Round($UltraSize, 2)) KB" -ForegroundColor Gray

$UltraSavings = [Math]::Round((($ReadableSize - $UltraSize) / $ReadableSize) * 100, 1)
Write-Host "[Build] Savings vs. Readable: $UltraSavings %" -ForegroundColor Green

$UltraVsMinSavings = [Math]::Round((($MinSize - $UltraSize) / $MinSize) * 100, 1)
Write-Host "[Build] Savings vs. Min: $UltraVsMinSavings %" -ForegroundColor Green

# ====================
# 4. OBFUSCATED VERSION (GZip + XOR + Base64)
# ====================
Write-Host "`n[Build] Creating obfuscated version: adPEAS_obf.ps1" -ForegroundColor Yellow

# Use ultra version as base (smallest payload)
$ObfSourceContent = Get-Content $UltraOutputPath -Raw

Write-Host "[Build]   - Compressing with GZip..." -ForegroundColor Gray

# Convert to bytes and compress with GZip
$SourceBytes = [System.Text.Encoding]::UTF8.GetBytes($ObfSourceContent)
$MemoryStream = New-Object System.IO.MemoryStream
$GZipStream = New-Object System.IO.Compression.GZipStream($MemoryStream, [System.IO.Compression.CompressionMode]::Compress)
$GZipStream.Write($SourceBytes, 0, $SourceBytes.Length)
$GZipStream.Close()
$CompressedBytes = $MemoryStream.ToArray()
$MemoryStream.Close()

$CompressionRatio = [Math]::Round(($CompressedBytes.Length / $SourceBytes.Length) * 100, 1)
Write-Host "[Build]   - Compression ratio: $CompressionRatio% of original" -ForegroundColor Gray

Write-Host "[Build]   - Applying XOR encryption..." -ForegroundColor Gray

# Generate random XOR key (16 bytes for good entropy)
$XorKey = New-Object byte[] 16
$RNG = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
$RNG.GetBytes($XorKey)
$RNG.Dispose()

# XOR encrypt the compressed data
$EncryptedBytes = New-Object byte[] $CompressedBytes.Length
for ($i = 0; $i -lt $CompressedBytes.Length; $i++) {
    $EncryptedBytes[$i] = $CompressedBytes[$i] -bxor $XorKey[$i % $XorKey.Length]
}

Write-Host "[Build]   - Encoding to Base64..." -ForegroundColor Gray

# Convert to Base64
$PayloadBase64 = [Convert]::ToBase64String($EncryptedBytes)
$KeyBase64 = [Convert]::ToBase64String($XorKey)

Write-Host "[Build]   - Generating loader stub..." -ForegroundColor Gray

# Create the obfuscated script with decoder/loader
# Auto-loads on dot-sourcing, same UX as other adPEAS variants
$ObfuscatedScript = @"
<#
.SYNOPSIS
    adPEAS v2 - Obfuscated Version
    Version: $BuildVersion
    Build: $BuildTimestamp

.DESCRIPTION
    This is an obfuscated version of adPEAS for authorized penetration testing.
    The payload is GZip compressed, XOR encrypted, and Base64 encoded.

    AUTHORIZED SECURITY TESTING ONLY!

.NOTES
    Deobfuscation: Base64 decode -> XOR decrypt -> GZip decompress -> Execute
#>

# Encoded payload and key
`$_k = '$KeyBase64'
`$_d = '$PayloadBase64'

# Decode
`$_kb = [Convert]::FromBase64String(`$_k)
`$_db = [Convert]::FromBase64String(`$_d)

# XOR decrypt
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

# Get list of functions BEFORE loading adPEAS
`$_beforeFunctions = @(Get-Command -CommandType Function -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)

# Execute in current scope (loads all adPEAS functions)
. ([ScriptBlock]::Create(`$_sc)) | Out-Null

# Get list of functions AFTER loading adPEAS
`$_afterFunctions = @(Get-Command -CommandType Function -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)

# Find NEW functions (added by adPEAS) and export them to global scope
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

# Write obfuscated version
$ObfOutputPath = Join-Path $ReleasePath "adPEAS_obf.ps1"
Write-BuildFile -Path $ObfOutputPath -Content $ObfuscatedScript
Write-Host "[Build] Obfuscated version created: $ObfOutputPath" -ForegroundColor Green

$ObfSize = (Get-Item $ObfOutputPath).Length / 1KB
Write-Host "[Build] Size: $([Math]::Round($ObfSize, 2)) KB" -ForegroundColor Gray

$ObfVsUltraSavings = [Math]::Round((($UltraSize - $ObfSize) / $UltraSize) * 100, 1)
if ($ObfVsUltraSavings -gt 0) {
    Write-Host "[Build] Savings vs. Ultra: $ObfVsUltraSavings %" -ForegroundColor Green
} else {
    Write-Host "[Build] Size increase vs. Ultra: $([Math]::Abs($ObfVsUltraSavings)) % (due to Base64 encoding overhead)" -ForegroundColor Yellow
}

# ====================
# SUMMARY
# ====================
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "BUILD COMPLETED SUCCESSFULLY" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Version: $BuildVersion" -ForegroundColor White
Write-Host "Timestamp: $BuildTimestamp" -ForegroundColor White
Write-Host "`nFiles:" -ForegroundColor White
Write-Host "  - adPEAS.ps1       : $([Math]::Round($ReadableSize, 2)) KB (readable, with comments)" -ForegroundColor Gray
Write-Host "  - adPEAS_min.ps1   : $([Math]::Round($MinSize, 2)) KB (minimized, no comments)" -ForegroundColor Gray
Write-Host "  - adPEAS_ultra.ps1 : $([Math]::Round($UltraSize, 2)) KB (ultra-compressed, NO comments)" -ForegroundColor Gray
Write-Host "  - adPEAS_obf.ps1   : $([Math]::Round($ObfSize, 2)) KB (obfuscated: GZip+XOR+Base64)" -ForegroundColor Gray
Write-Host "`nOutput directory: $ReleasePath (project root)" -ForegroundColor White
Write-Host "============================================`n" -ForegroundColor Cyan

# ====================
# 5. CODE SIGNING (optional)
# ====================
if ($CodeSigningCert) {
    Write-Host "[Build] Code Signing" -ForegroundColor Yellow

    # Validate certificate file exists
    if (-not (Test-Path $CodeSigningCert)) {
        Write-Error "[Build] Certificate file not found: $CodeSigningCert"
        return
    }

    # Load the certificate
    Write-Host "[Build]   - Loading certificate: $CodeSigningCert" -ForegroundColor Gray
    try {
        $CertParams = @{ FilePath = (Resolve-Path $CodeSigningCert).Path }

        if ($CertPassword) {
            if ($CertPassword -is [System.Security.SecureString]) {
                $CertParams['Password'] = $CertPassword
            } else {
                $CertParams['Password'] = ConvertTo-SecureString -String ([string]$CertPassword) -AsPlainText -Force
            }
        }

        $SigningCert = Get-PfxCertificate @CertParams

        # Verify it's a code signing certificate
        $CodeSigningEKU = $SigningCert.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq "1.3.6.1.5.5.7.3.3" }
        if (-not $CodeSigningEKU) {
            Write-Error "[Build] Certificate does not have Code Signing EKU (1.3.6.1.5.5.7.3.3)"
            return
        }

        Write-Host "[Build]     Subject: $($SigningCert.Subject)" -ForegroundColor Gray
        Write-Host "[Build]     Issuer: $($SigningCert.Issuer)" -ForegroundColor Gray
        Write-Host "[Build]     Valid until: $($SigningCert.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor Gray
        Write-Host "[Build]     Timestamp server: $TimestampServer" -ForegroundColor Gray
    }
    catch {
        Write-Error "[Build] Failed to load certificate: $_"
        return
    }

    # Sign all build outputs
    $FilesToSign = @(
        $ReadableOutputPath,
        $MinOutputPath,
        $UltraOutputPath,
        $ObfOutputPath
    )

    $SignedCount = 0
    foreach ($FileToSign in $FilesToSign) {
        $FileName = Split-Path $FileToSign -Leaf
        Write-Host "[Build]   - Signing $FileName..." -ForegroundColor Gray -NoNewline

        try {
            $SignParams = @{
                FilePath    = $FileToSign
                Certificate = $SigningCert
                HashAlgorithm = "SHA256"
            }

            if ($TimestampServer) {
                $SignParams['TimestampServer'] = $TimestampServer
            }

            $SignResult = Set-AuthenticodeSignature @SignParams

            if ($SignResult.Status -eq "Valid") {
                Write-Host " OK" -ForegroundColor Green
                $SignedCount++
            } else {
                Write-Host " FAILED ($($SignResult.StatusMessage))" -ForegroundColor Red
            }
        }
        catch {
            Write-Host " ERROR ($_)" -ForegroundColor Red
        }
    }

    Write-Host "`n[Build] Code Signing: $SignedCount/$($FilesToSign.Count) files signed successfully" -ForegroundColor $(if ($SignedCount -eq $FilesToSign.Count) { "Green" } else { "Yellow" })
}
