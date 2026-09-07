<#
.SYNOPSIS
    Build script for adPEAS v2 release versions.

.DESCRIPTION
    Combines all modules into a single standalone .ps1 file and produces four variants:
    - adPEAS.ps1       (readable, with comments)
    - adPEAS_min.ps1   (minimized)
    - adPEAS_ultra.ps1 (ultra-compressed, no comments, no logging)
    - adPEAS_obf.ps1   (obfuscated: GZip + XOR + Base64)

    This script is only the orchestration. The mechanics live in Build-Engine.ps1, which is
    project independent and copied between projects unchanged; everything specific to
    adPEAS - file names, module categories, which functions carry embedded assets - lives
    in Build-Config.psd1.

    To port this build to another project: copy Build-Engine.ps1 and this file as they are,
    and rewrite Build-Config.psd1.

.PARAMETER License
    Path to a license.json file to embed into the build.
    If specified, the license is Base64-encoded and embedded into the output scripts.

.PARAMETER Stable
    Creates a stable release build with a clean version number (e.g. "2.4.1").
    Without this switch, builds include a timestamp suffix (e.g. "2.4.1+20260215-1840").

.PARAMETER CodeSigningCert
    Path to a PKCS#12 (.pfx) code signing certificate file.
    If specified, all build outputs are signed with Authenticode after the build completes.
    The certificate must have the Code Signing enhanced key usage (EKU).

    Signing does not require the certificate to chain to a root this build host trusts.
    A self-signed or internal-CA certificate produces a perfectly valid signature; the
    build reports those as "signed; not verifiable on this host" rather than as failures,
    because whether a chain verifies here says nothing about the signature itself.

.PARAMETER CertPassword
    Password for the code signing certificate (if the PFX is password-protected).
    Accepts a SecureString or a plain string.

.PARAMETER TimestampServer
    URL of an RFC 3161 timestamp server for Authenticode timestamping.
    Timestamping keeps the signature valid after the certificate expires. A build that
    cannot reach the server still signs, and says so.

.PARAMETER ConfigPath
    Path to the build configuration. Defaults to Build-Config.psd1 next to this script.

.EXAMPLE
    .\Build-Release.ps1

.EXAMPLE
    .\Build-Release.ps1 -Stable

.EXAMPLE
    .\Build-Release.ps1 -License .\license.json

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
    [string]$TimestampServer,

    [Parameter(Mandatory=$false)]
    [string]$ConfigPath
)

$ErrorActionPreference = "Stop"

# ========================================
# ENGINE AND CONFIGURATION
# ========================================
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

$EnginePath = Join-Path $ScriptRoot 'Build-Engine.ps1'
if (-not (Test-Path $EnginePath)) {
    Write-Error "[Build] Build-Engine.ps1 not found next to this script"
    return
}
. $EnginePath

if (-not $ConfigPath) { $ConfigPath = Join-Path $ScriptRoot 'Build-Config.psd1' }
if (-not (Test-Path $ConfigPath)) {
    Write-Error "[Build] Build configuration not found: $ConfigPath"
    return
}
$Config = Import-PowerShellDataFile -Path $ConfigPath

$SourcePath  = Join-Path $ScriptRoot $Config.SourceRoot
$ReleasePath = if ($Config.OutputDirectory -eq '.') { $ScriptRoot } else { Join-Path $ScriptRoot $Config.OutputDirectory }
if (-not $TimestampServer) { $TimestampServer = $Config.DefaultTimestampServer }

Write-Host "[Build] $($Config.ProjectName) Build Script started" -ForegroundColor Cyan
Write-Host "[Build] Source: $SourcePath" -ForegroundColor Gray
Write-Host "[Build] Output: $ReleasePath" -ForegroundColor Gray

# ========================================
# READ MODULE LIST AND VERSION FROM SOURCE
# ========================================
$MainScriptPath = Join-Path $SourcePath $Config.EntryScript
$MainScriptContent = Read-BuildFile -Path $MainScriptPath

$BaseVersion = Get-BuildSourceVersion -Content $MainScriptContent -VariableName $Config.VersionVariable
if (-not $BaseVersion) { return }

$BuildTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
if ($Stable) {
    $BuildVersion = $BaseVersion
    Write-Host "[Build] Build Version: $BuildVersion (stable release)" -ForegroundColor Cyan
} else {
    $BuildVersion = "${BaseVersion}+$(Get-Date -Format 'yyyyMMdd-HHmm')"
    Write-Host "[Build] Build Version: $BuildVersion (dev build)" -ForegroundColor Cyan
}
Write-Host "[Build] Build Time: $BuildTimestamp" -ForegroundColor Gray

$ModuleList = Get-BuildModuleList -Content $MainScriptContent `
    -Categories $Config.ModuleSection.Categories `
    -PathVariable $Config.ModuleSection.PathVariable
if (-not $ModuleList) { return }

$TotalModules = 0
$CategorySummary = @()
foreach ($Category in $Config.ModuleSection.Categories) {
    $TotalModules += $ModuleList[$Category].Count
    $CategorySummary += "$($Category): $($ModuleList[$Category].Count)"
}
Write-Host "[Build] Parsed $TotalModules modules from $($Config.EntryScript):" -ForegroundColor Gray
Write-Host "[Build]   $($CategorySummary -join ', ')" -ForegroundColor Gray

# A module on disk that nobody listed is absent from every artifact, silently; one listed
# but missing aborts the build later with a bare I/O error. Both are cheaper to hear about
# here, by name.
$ModuleProblems = Test-BuildModuleList -ModuleList $ModuleList -SourceRoot $SourcePath -ModuleDirectory $Config.ModuleDirectory
if ($ModuleProblems.Count -gt 0) {
    foreach ($Problem in $ModuleProblems) { Write-Host "[Build]   $Problem" -ForegroundColor Red }
    Write-Error "[Build] The module list and the source tree disagree - see above"
    return
}

# ========================================
# EMBEDDED ASSETS
# ========================================
# Assembled up front so a missing or unusable asset stops the build before anything is
# written. Each entry replaces a #region BUILD:EMBED block in its module.
$EmbedContent = @{}
foreach ($Embed in $Config.Embeds) {
    $SourceFile = Join-Path $SourcePath $Embed.Source
    if (-not (Test-Path $SourceFile)) {
        Write-Error "[Build] Embedded asset not found: $SourceFile (needed by $($Embed.Function))"
        return
    }
    $Assembled = Read-BuildFile -Path $SourceFile

    foreach ($Placeholder in @($Embed.Placeholders)) {
        if (-not $Placeholder) { continue }
        $PlaceholderFile = Join-Path $SourcePath $Placeholder.Source
        if (-not (Test-Path $PlaceholderFile)) {
            Write-Error "[Build] Embedded asset not found: $PlaceholderFile (placeholder $($Placeholder.Token))"
            return
        }
        $Assembled = $Assembled.Replace($Placeholder.Token, (Read-BuildFile -Path $PlaceholderFile))
    }

    if (-not (Test-BuildEmbeddableContent -Content $Assembled -Name "The asset for $($Embed.Function)")) { return }

    $EmbedContent[$Embed.Region] = $Assembled
    Write-Host "[Build] Asset for $($Embed.Function): $($Assembled.Length) bytes" -ForegroundColor Gray
}

# ====================
# 1. READABLE VERSION
# ====================
Write-Host "`n[Build] Creating readable version: $($Config.Variants.Readable.FileName)" -ForegroundColor Yellow

$ReadableOutput = @()
$ReadableOutput += $Config.Header.Replace('{VERSION}', $BuildVersion).Replace('{TIMESTAMP}', $BuildTimestamp)

# Which module each embed belongs to, so the loop below can find them by file name
$EmbedsByModule = @{}
foreach ($Embed in $Config.Embeds) {
    $ModuleKey = ($Embed.Module -replace '/', '\')
    if (-not $EmbedsByModule.ContainsKey($ModuleKey)) { $EmbedsByModule[$ModuleKey] = @() }
    $EmbedsByModule[$ModuleKey] += $Embed
}

foreach ($Category in $Config.ModuleSection.Categories) {
    Write-Host "[Build]   - Loading $Category modules..." -ForegroundColor Gray

    $ReadableOutput += "`n# =============================================="
    $ReadableOutput += "# $($Category.ToUpper()) MODULES"
    $ReadableOutput += "# ==============================================`n"

    foreach ($Module in $ModuleList[$Category]) {
        $ModulePath = Join-Path $SourcePath $Module
        $ModuleName = Split-Path $Module -Leaf
        Write-Host "[Build]     - $ModuleName" -ForegroundColor DarkGray

        $ReadableOutput += "# ----- $ModuleName -----`n"
        $Content = Read-BuildFile -Path $ModulePath
        # Not needed in a standalone script
        $Content = $Content -replace "(?m)^.*Export-ModuleMember.*$", ""

        $ModuleKey = ($Module -replace '/', '\')
        foreach ($Embed in @($EmbedsByModule[$ModuleKey])) {
            if (-not $Embed) { continue }
            Write-Host "[Build]       Embedding asset into $($Embed.Function)..." -ForegroundColor DarkGray
            $Replacement = New-BuildEmbeddedFunction -FunctionName $Embed.Function `
                -Content $EmbedContent[$Embed.Region] -Description $Embed.Description
            $Content = Set-BuildEmbedRegion -Content $Content -RegionName $Embed.Region -Replacement $Replacement
            if ($null -eq $Content) { return }
        }

        $ReadableOutput += $Content
        $ReadableOutput += "`n"
    }
}

Write-Host "[Build]   - Loading main logic..." -ForegroundColor Gray

$MainContent = $MainScriptContent

# Drop the development module loading block - the modules are inlined above
$SectionPattern = '(?s)' + [regex]::Escape($Config.ModuleSection.Start) + '.*?' + [regex]::Escape($Config.ModuleSection.End)
$MainContent = $MainContent -replace $SectionPattern, $Config.ModuleSection.End
if ($MainContent -match [regex]::Escape($Config.ModuleSection.Start)) {
    Write-Error "[Build] FAILED: Module loading section was not removed! Check the section markers in $($Config.EntryScript)."
    return
}

# Stamp the build version
$VersionPattern = '(\$Script:' + [regex]::Escape($Config.VersionVariable) + ' = ")[^"]*(")'
$MainContent = $MainContent -replace $VersionPattern, "`${1}$BuildVersion`${2}"

# Embed license if requested
if ($License) {
    if (-not (Test-Path $License)) {
        Write-Error "[Build] License file not found: $License"
        return
    }
    # Resolve through PowerShell's provider: [System.IO.File] resolves relative paths
    # against [Environment]::CurrentDirectory, which can diverge from $PWD.
    $LicenseFilePath = (Resolve-Path $License).Path
    Write-Host "[Build]   - Embedding license from: $LicenseFilePath" -ForegroundColor Gray
    try {
        $LicenseJsonRaw = Read-BuildFile -Path $LicenseFilePath
        $LicenseObj = $LicenseJsonRaw | ConvertFrom-Json

        $MissingFields = @($Config.License.RequiredFields | Where-Object { -not $LicenseObj.$_ })
        if ($MissingFields.Count -gt 0) {
            Write-Error "[Build] Invalid license file - missing: $($MissingFields -join ', ')"
            return
        }

        $LicenseBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($LicenseJsonRaw))
        $LicensePattern = '\$Script:' + [regex]::Escape($Config.License.Variable) + ' = \$null'
        $MainContent = $MainContent -replace $LicensePattern, "`$Script:$($Config.License.Variable) = `"$LicenseBase64`""
        Write-Host "[Build]     Licensee: $($LicenseObj.Licensee)" -ForegroundColor Green
        Write-Host "[Build]     Valid until: $($LicenseObj.ValidUntil)" -ForegroundColor Green
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

# Kept in a variable as well: the other variants are derived from this same text rather
# than read back from the file, which is what lets the build compare them afterwards.
$AssembledContent = $ReadableOutput -join "`n"

$ReadableOutputPath = Join-Path $ReleasePath $Config.Variants.Readable.FileName
Write-BuildFile -Path $ReadableOutputPath -Content $AssembledContent
Write-Host "[Build] Readable version created: $ReadableOutputPath" -ForegroundColor Green

$ReadableSize = (Get-Item $ReadableOutputPath).Length / 1KB
Write-Host "[Build] Size: $([Math]::Round($ReadableSize, 2)) KB" -ForegroundColor Gray

# ====================
# 2. MINIMIZED VERSION
# ====================
Write-Host "`n[Build] Creating minimized version: $($Config.Variants.Minimized.FileName)" -ForegroundColor Yellow

$MinContent = $AssembledContent

Write-Host "[Build]   - Removing comments (by token, so strings are untouched)..." -ForegroundColor Gray
$MinContent = Remove-BuildComments -Content $MinContent -Stage 'minimized' -KeepRequires:$Config.Variants.Minimized.KeepRequires
if ($null -eq $MinContent) { return }

Write-Host "[Build]   - Removing empty lines and trailing whitespace..." -ForegroundColor Gray
$MinContent = Invoke-BuildLineTransform -Content $MinContent -Stage 'minimized'
if ($null -eq $MinContent) { return }

$MinOutputPath = Join-Path $ReleasePath $Config.Variants.Minimized.FileName
Write-BuildFile -Path $MinOutputPath -Content $MinContent
Write-Host "[Build] Minimized version created: $MinOutputPath" -ForegroundColor Green

$MinSize = (Get-Item $MinOutputPath).Length / 1KB
Write-Host "[Build] Size: $([Math]::Round($MinSize, 2)) KB" -ForegroundColor Gray
Write-Host "[Build] Savings: $([Math]::Round((($ReadableSize - $MinSize) / $ReadableSize) * 100, 1)) %" -ForegroundColor Green

# ====================
# 3. ULTRA-COMPRESSED VERSION
# ====================
Write-Host "`n[Build] Creating ultra-compressed version: $($Config.Variants.Ultra.FileName)" -ForegroundColor Yellow

$UltraContent = $AssembledContent

if ($Config.Variants.Ultra.StripCommands) {
    Write-Host "[Build]   - Removing $($Config.Variants.Ultra.StripCommands -join '/') statements..." -ForegroundColor Gray
    $UltraContent = Remove-BuildCommandCalls -Content $UltraContent -Stage 'ultra (logging)' -CommandName $Config.Variants.Ultra.StripCommands
    if ($null -eq $UltraContent) { return }
}

Write-Host "[Build]   - Removing ALL comments (incl. Synopsis)..." -ForegroundColor Gray
$UltraContent = Remove-BuildComments -Content $UltraContent -Stage 'ultra (comments)' -KeepRequires:$Config.Variants.Ultra.KeepRequires
if ($null -eq $UltraContent) { return }

Write-Host "[Build]   - Removing empty function blocks..." -ForegroundColor Gray
$UltraContent = $UltraContent -replace "(?m)^\s*begin\s*\{\s*\}\s*$", ""
$UltraContent = $UltraContent -replace "(?m)^\s*end\s*\{\s*\}\s*$", ""

Write-Host "[Build]   - Removing empty lines, trailing and leading whitespace..." -ForegroundColor Gray
# -Reindent collapses leading indentation on code lines only. It is worth about 6 % of the
# ultra artifact and roughly 1 % once the obfuscated variant gzips it - not enough to
# justify rewriting the inside of every string, which is what it used to do.
$UltraContent = Invoke-BuildLineTransform -Content $UltraContent -Stage 'ultra (lines)' -Reindent:$Config.Variants.Ultra.Reindent
if ($null -eq $UltraContent) { return }

$UltraOutputPath = Join-Path $ReleasePath $Config.Variants.Ultra.FileName
Write-BuildFile -Path $UltraOutputPath -Content $UltraContent
Write-Host "[Build] Ultra-compressed version created: $UltraOutputPath" -ForegroundColor Green

$UltraSize = (Get-Item $UltraOutputPath).Length / 1KB
Write-Host "[Build] Size: $([Math]::Round($UltraSize, 2)) KB" -ForegroundColor Gray
Write-Host "[Build] Savings vs. Readable: $([Math]::Round((($ReadableSize - $UltraSize) / $ReadableSize) * 100, 1)) %" -ForegroundColor Green
Write-Host "[Build] Savings vs. Min: $([Math]::Round((($MinSize - $UltraSize) / $MinSize) * 100, 1)) %" -ForegroundColor Green

# ====================
# 4. OBFUSCATED VERSION (GZip + XOR + Base64)
# ====================
Write-Host "`n[Build] Creating obfuscated version: $($Config.Variants.Obfuscated.FileName)" -ForegroundColor Yellow

$ObfBase = switch ($Config.Variants.Obfuscated.BasedOn) {
    'Readable'  { $MinContent }
    'Minimized' { $MinContent }
    default     { $UltraContent }
}

Write-Host "[Build]   - Compressing, encoding and generating the loader stub..." -ForegroundColor Gray
$Obfuscated = New-BuildObfuscatedScript -Content $ObfBase `
    -ProjectName $Config.ProjectName -Version $BuildVersion -Timestamp $BuildTimestamp
Write-Host "[Build]   - Compression ratio: $([Math]::Round(($Obfuscated.CompressedLength / $Obfuscated.SourceLength) * 100, 1))% of original" -ForegroundColor Gray

$ObfOutputPath = Join-Path $ReleasePath $Config.Variants.Obfuscated.FileName
Write-BuildFile -Path $ObfOutputPath -Content $Obfuscated.Script
Write-Host "[Build] Obfuscated version created: $ObfOutputPath" -ForegroundColor Green

$ObfSize = (Get-Item $ObfOutputPath).Length / 1KB
Write-Host "[Build] Size: $([Math]::Round($ObfSize, 2)) KB" -ForegroundColor Gray
$ObfVsUltraSavings = [Math]::Round((($UltraSize - $ObfSize) / $UltraSize) * 100, 1)
if ($ObfVsUltraSavings -gt 0) {
    Write-Host "[Build] Savings vs. Ultra: $ObfVsUltraSavings %" -ForegroundColor Green
} else {
    Write-Host "[Build] Size increase vs. Ultra: $([Math]::Abs($ObfVsUltraSavings)) % (Base64 overhead)" -ForegroundColor Yellow
}

# ====================
# VARIANT VERIFICATION
# ====================
#
# The embedded assets are the largest piece of string content in a build and the one the
# text transformations used to damage: the minimized variant lost every blank line inside
# them and the ultra variant 16 KB of indentation on top, so the artifacts shipped three
# different HTML reports. Nothing noticed, because each one on its own parsed, loaded and
# produced a report.
#
# Compared against the asset that went in, not just against each other, so a
# transformation that damaged all of them equally would still be caught.
Write-Host "`n[Build] Verifying that all variants carry the same embedded assets..." -ForegroundColor Yellow

$VariantPaths = @(
    @{ Name = $Config.Variants.Readable.FileName;  Path = $ReadableOutputPath }
    @{ Name = $Config.Variants.Minimized.FileName; Path = $MinOutputPath }
    @{ Name = $Config.Variants.Ultra.FileName;     Path = $UltraOutputPath }
)

$Mismatches = @()
foreach ($Embed in $Config.Embeds) {
    foreach ($Variant in $VariantPaths) {
        $Embedded = Get-BuildEmbeddedContent -Path $Variant.Path -FunctionName $Embed.Function
        if ($null -eq $Embedded) {
            $Mismatches += "$($Variant.Name): $($Embed.Function) not found or not in embedded form"
        }
        elseif ($Embedded -cne $EmbedContent[$Embed.Region]) {
            $Mismatches += "$($Variant.Name): $($Embed.Function) differs from the source asset ($($Embedded.Length) vs $($EmbedContent[$Embed.Region].Length) chars)"
        }
    }
}

if ($Mismatches.Count -gt 0) {
    foreach ($Mismatch in $Mismatches) { Write-Host "[Build]   $Mismatch" -ForegroundColor Red }
    Write-Error "[Build] Embedded assets were altered by the build. The variants would behave differently."
    return
}
Write-Host "[Build]   $($Config.Embeds.Count) asset(s) identical across all $($VariantPaths.Count) text variants" -ForegroundColor Green

# ====================
# 5. CODE SIGNING (optional)
# ====================
if ($CodeSigningCert) {
    Write-Host "`n[Build] Code Signing" -ForegroundColor Yellow

    $FilesToSign = @($ReadableOutputPath, $MinOutputPath, $UltraOutputPath, $ObfOutputPath)
    $SignResult = Invoke-BuildCodeSigning -Path $FilesToSign `
        -CertificatePath $CodeSigningCert -CertPassword $CertPassword -TimestampServer $TimestampServer
    if (-not $SignResult) { return }

    Write-Host "`n[Build] Code Signing: $($SignResult.Signed)/$($SignResult.Total) files signed" -ForegroundColor $(if ($SignResult.Signed -eq $SignResult.Total) { "Green" } else { "Red" })

    if ($SignResult.Untrusted -gt 0) {
        Write-Host "[Build]   $($SignResult.Untrusted) file(s) carry a signature this host cannot build a trust chain for." -ForegroundColor Yellow
        Write-Host "[Build]   Expected for a self-signed or internal-CA certificate - the signature is intact," -ForegroundColor Yellow
        Write-Host "[Build]   and verifies wherever the issuing root is trusted." -ForegroundColor Yellow
    }
    if ($SignResult.UnTimestamped -gt 0) {
        Write-Host "[Build]   $($SignResult.UnTimestamped) file(s) were signed WITHOUT a timestamp - could not reach $TimestampServer." -ForegroundColor Yellow
        Write-Host "[Build]   Those signatures stop verifying when the certificate expires on $($SignResult.NotAfter.ToString('yyyy-MM-dd'))." -ForegroundColor Yellow
    }

    # A build that was asked to sign and did not must not report success. Without this the
    # script ended with exit code 0 after printing "0/4", and nothing downstream - a
    # release script, CI, or a person skimming the tail of the log - had any way to know.
    if ($SignResult.Signed -ne $SignResult.Total) {
        Write-Error "[Build] Code signing failed for $($SignResult.Total - $SignResult.Signed) of $($SignResult.Total) file(s). The build artifacts exist but are not signed."
        return
    }
}

# ====================
# SUMMARY
# ====================
#
# Last, behind code signing. It used to print ahead of it, so a run that failed to sign
# announced BUILD COMPLETED SUCCESSFULLY first and reported the failure afterwards.
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "BUILD COMPLETED SUCCESSFULLY" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Version: $BuildVersion" -ForegroundColor White
Write-Host "Timestamp: $BuildTimestamp" -ForegroundColor White
Write-Host "`nFiles:" -ForegroundColor White
Write-Host "  - $($Config.Variants.Readable.FileName.PadRight(18)): $([Math]::Round($ReadableSize, 2)) KB ($($Config.Variants.Readable.Description))" -ForegroundColor Gray
Write-Host "  - $($Config.Variants.Minimized.FileName.PadRight(18)): $([Math]::Round($MinSize, 2)) KB ($($Config.Variants.Minimized.Description))" -ForegroundColor Gray
Write-Host "  - $($Config.Variants.Ultra.FileName.PadRight(18)): $([Math]::Round($UltraSize, 2)) KB ($($Config.Variants.Ultra.Description))" -ForegroundColor Gray
Write-Host "  - $($Config.Variants.Obfuscated.FileName.PadRight(18)): $([Math]::Round($ObfSize, 2)) KB ($($Config.Variants.Obfuscated.Description))" -ForegroundColor Gray
Write-Host "`nOutput directory: $ReleasePath" -ForegroundColor White
Write-Host "============================================`n" -ForegroundColor Cyan
