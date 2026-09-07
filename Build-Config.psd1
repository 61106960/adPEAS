<#
    Build configuration for adPEAS.

    Everything project-specific lives here; Build-Engine.ps1 holds the mechanics and is
    copied between projects unchanged. Build-Release.ps1 puts the two together.

    To port the build to another project: copy Build-Engine.ps1 and Build-Release.ps1 as
    they are, and rewrite this file.
#>
@{
    # --- identity -----------------------------------------------------------------
    ProjectName = 'adPEAS'
    Author      = 'Alexander Sturz (@_61106960_)'
    ProjectUrl  = 'https://github.com/61106960/adPEAS'

    # --- layout -------------------------------------------------------------------
    # Relative to the directory holding Build-Release.ps1.
    SourceRoot      = 'src'
    EntryScript     = 'adPEAS.ps1'      # relative to SourceRoot
    ModuleDirectory = 'modules'         # relative to SourceRoot, for the completeness check
    OutputDirectory = '.'

    # --- version ------------------------------------------------------------------
    # The single source of truth, read out of the entry script. Without -Stable the
    # build appends +yyyyMMdd-HHmm.
    VersionVariable = 'adPEASVersion'

    # --- module assembly ----------------------------------------------------------
    # The build reads the same dot-source lines the entry script uses in development
    # mode, so a built artifact and a dot-sourced run load the same files in the same
    # order. Categories come from the "# <Name> Modules" comments and decide the order
    # sections are emitted in.
    ModuleSection = @{
        Start        = '# ===== Load Modules ====='
        End          = '# ===== Main Function ====='
        PathVariable = 'Script:ScriptPath'
        Categories   = @('Core', 'Helper', 'Check', 'Reporting', 'Collector')
    }

    # --- variants -----------------------------------------------------------------
    Variants = @{
        Readable = @{
            FileName    = 'adPEAS.ps1'
            Description = 'readable, with comments'
        }
        Minimized = @{
            FileName      = 'adPEAS_min.ps1'
            Description   = 'minimized, no comments'
            KeepRequires  = $true
        }
        Ultra = @{
            FileName      = 'adPEAS_ultra.ps1'
            Description   = 'ultra-compressed, NO comments'
            KeepRequires  = $false
            Reindent      = $true
            # Removed by AST node, so only real calls go - not the word "Write-Log"
            # appearing inside a here-string, and never the right-hand side of an
            # assignment.
            StripCommands = @('Write-Log', 'Write-Verbose')
        }
        Obfuscated = @{
            FileName    = 'adPEAS_obf.ps1'
            Description = 'obfuscated: GZip+XOR+Base64'
            BasedOn     = 'Ultra'
        }
    }

    # --- embedded content ---------------------------------------------------------
    # Each entry replaces a #region BUILD:EMBED <Region> block in the named module with a
    # function that returns the assembled asset verbatim. The development version inside
    # that region loads the same files from disk, so both modes serve the same content.
    Embeds = @(
        @{
            Region       = 'Get-HTMLTemplate'
            Function     = 'Get-HTMLTemplate'
            Module       = 'modules\Reporting\Export-HTMLReport.ps1'
            Source       = 'modules\Reporting\templates\report-template.html'
            Placeholders = @(
                @{ Token = '{{CSS_CONTENT}}'; Source = 'modules\Reporting\templates\report-styles.css' }
                @{ Token = '{{JS_CONTENT}}';  Source = 'modules\Reporting\templates\report-scripts.js' }
            )
            Description  = 'HTML report template. Maintained in modules/Reporting/templates and embedded at build time.'
        }
        @{
            Region      = 'Get-DiffHTMLTemplate'
            Function    = 'Get-DiffHTMLTemplate'
            Module      = 'modules\Reporting\Compare-adPEASReport.ps1'
            Source      = 'modules\Reporting\templates\diff-template.html'
            Description = 'Diff report template. Maintained in modules/Reporting/templates and embedded at build time.'
        }
    )

    # --- optional license embedding -----------------------------------------------
    # Build-Release.ps1 -License <file> replaces "$Script:<Variable> = $null" with the
    # Base64 of that file. RequiredFields are checked before embedding.
    License = @{
        Variable       = 'EmbeddedLicense'
        RequiredFields = @('Licensee', 'ValidUntil', 'Signature')
    }

    # --- signing ------------------------------------------------------------------
    DefaultTimestampServer = 'http://timestamp.digicert.com'

    # --- artifact header ----------------------------------------------------------
    # {VERSION} and {TIMESTAMP} are substituted.
    Header = @'
<#
.SYNOPSIS
    adPEAS v2 - Active Directory Privilege Escalation Awesome Scripts

.DESCRIPTION
    Build: {TIMESTAMP}
    Version: {VERSION}

    AUTHORIZED SECURITY TESTING ONLY!

.NOTES
    Author: Alexander Sturz (@_61106960_)

.LINK
    https://github.com/61106960/adPEAS
#>

'@
}
