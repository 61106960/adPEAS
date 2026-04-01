<#
.SYNOPSIS
    Central scoring definitions for adPEAS HTML reports.

.DESCRIPTION
    This file contains all scoring-related definitions used by the HTML report generator.

    Scoring Formula:
    FINAL_SCORE = (BASE × IMPACT × EXPLOITABILITY × SECURITY) + CORRELATION

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

# =============================================================================
# HELPER FUNCTION: Get BaseScores from FindingDefinitions
# =============================================================================
# Extracts all BaseScore values from $Script:FindingDefinitions for JavaScript export.

function Get-FindingBaseScores {
    <#
    .SYNOPSIS
        Returns a hashtable of FindingID => BaseScore from FindingDefinitions.
    .DESCRIPTION
        Extracts BaseScore values from $Script:FindingDefinitions for use in JavaScript generation and statistics.
    #>
    $scores = @{}

    if ($null -eq $Script:FindingDefinitions) {
        Write-Warning "[Get-FindingBaseScores] FindingDefinitions not loaded"
        return $scores
    }

    foreach ($entry in $Script:FindingDefinitions.GetEnumerator()) {
        $findingId = $entry.Key
        $definition = $entry.Value

        if ($definition.ContainsKey('BaseScore')) {
            $scores[$findingId] = $definition.BaseScore
        } else {
            # Fallback based on Risk level if BaseScore not defined
            $risk = if ($definition.ContainsKey('Risk')) { $definition.Risk } else { 'Standard' }
            $scores[$findingId] = switch ($risk) {
                'Finding' { $Script:SeverityFallbackScores[$Script:SeverityClasses.Finding] }
                'Hint'    { $Script:SeverityFallbackScores[$Script:SeverityClasses.Hint] }
                'Note'    { $Script:SeverityFallbackScores[$Script:SeverityClasses.Note] }
                'Secure'  { $Script:SeverityFallbackScores[$Script:SeverityClasses.Secure] }
                default   { 0 }
            }
        }
    }

    return $scores
}

# =============================================================================
# SEVERITY FALLBACK SCORES
# =============================================================================
# Used when no keyword matches the finding title.

$Script:SeverityFallbackScores = @{
    $Script:SeverityClasses.Finding  = 35    # Red findings without keyword match
    $Script:SeverityClasses.Hint     = 15    # Yellow hints without keyword match
    $Script:SeverityClasses.Note     = 0     # Green notes
    $Script:SeverityClasses.Secure   = 0     # Secure configurations
    $Script:SeverityClasses.Standard = 0     # Standard output (no severity)
}

# =============================================================================
# IMPACT MULTIPLIERS (ACCOUNT TIER)
# =============================================================================
# Adjusts score based on the privilege level of affected accounts
# Microsoft Tiering Model: https://docs.microsoft.com/en-us/security/privileged-access-workstations/
# Tier 0: -512 (Domain Admins), -519 (Enterprise Admins), -518 (Schema Admins) - Domain Controllers
# Tier 1: -548 (Account Ops), -549 (Server Ops), -551 (Backup Ops), -550 (Print Ops) - Servers
# Tier 2: Other privileged groups - Workstations

$Script:ImpactMultipliers = @{
    'tier0' = 2.0    # Domain/Enterprise/Schema Admins - immediate domain compromise (Microsoft Tier 0)
    'tier1' = 1.5    # Operators (Account, Server, Backup, Print) - significant access (Microsoft Tier 1)
    'tier2' = 1.2    # Other privileged groups - elevated access (Microsoft Tier 2)
    'none'  = 1.0    # Standard user accounts - base impact
}

# =============================================================================
# EXPLOITABILITY MODIFIERS
# =============================================================================

# Password Age Modifiers (relative to domain maxPwdAge policy)
# Example: If maxPwdAge=90 days and password is 450 days old = 5x policy = 1.4 modifier
$Script:PasswordAgeModifiers = @{
    'multiplier_10x' = 1.6    # Password age >= 10× maxPwdAge
    'multiplier_5x'  = 1.4    # Password age >= 5× maxPwdAge
    'multiplier_3x'  = 1.3    # Password age >= 3× maxPwdAge
    'multiplier_2x'  = 1.2    # Password age >= 2× maxPwdAge
    'multiplier_1x'  = 1.1    # Password age >= 1× maxPwdAge (over policy)
    'within_policy'  = 1.0    # Password age < maxPwdAge
}

# Password Length Modifiers (based on domain minPwdLength)
$Script:PasswordLengthModifiers = @{
    'very_weak'  = 1.4    # minPwdLength < 8 characters
    'weak'       = 1.2    # minPwdLength 8-11 characters
    'standard'   = 1.0    # minPwdLength 12-15 characters
    'strong'     = 0.8    # minPwdLength >= 16 characters
}

# Password Complexity Modifier
$Script:PasswordComplexityModifiers = @{
    'disabled' = 1.25    # Complexity not required - weak passwords likely
    'enabled'  = 1.0     # Complexity required - standard
}

# Encryption Type Modifiers (for Kerberos-based attacks)
$Script:EncryptionTypeModifiers = @{
    'rc4_only'  = 1.3    # RC4-HMAC only (etype 23) - fast to crack
    'aes128'    = 1.0    # AES128-CTS (etype 17) - standard
    'aes256'    = 0.9    # AES256-CTS (etype 18) - slower to crack
}

# =============================================================================
# SECURITY MODIFIERS (MITIGATING CONTROLS)
# =============================================================================
# These REDUCE the score when protective measures are in place

$Script:SecurityModifiers = @{
    # UAC Flags
    'ACCOUNTDISABLE'      = 0.1     # Account is disabled - can't be used
    'LOCKOUT'             = 0.3     # Account is locked out
    'SMARTCARD_REQUIRED'  = 0.15    # Password is random/unknown (cracking attacks)
    'PASSWORD_EXPIRED'    = 0.7     # Password may be changed soon
    'USE_DES_KEY_ONLY'    = 1.3     # Weak encryption - INCREASES risk
    'NOT_DELEGATED'       = 0.3     # Delegation protection (delegation attacks)

    # Group Membership
    'PROTECTED_USERS'     = 0.2     # Protected Users group membership
}

# =============================================================================
# CORRELATION BONUS
# =============================================================================
# Bonus points when same account appears in multiple risky findings
# Non-admin accounts appearing repeatedly are MORE interesting (potential attack paths)

$Script:CorrelationBonus = @{
    # Standard correlation (for privileged accounts)
    'per_finding'           = 5     # Points per additional finding
    'max_bonus'             = 15    # Maximum correlation bonus

    # Enhanced correlation for non-admin accounts (potential privilege escalation paths)
    # Rationale: A non-admin appearing in 3+ findings suggests an attack path exists
    'non_admin_per_finding' = 8     # Higher points per finding for non-admins
    'non_admin_max_bonus'   = 30    # Higher cap - these are more interesting
    'non_admin_threshold'   = 3     # Minimum findings to trigger enhanced bonus
}

# =============================================================================
# SCORE DISPLAY THRESHOLDS
# =============================================================================
# Color coding for score badges in HTML report

$Script:ScoreThresholds = @{
    'critical' = 80    # Score >= 80: Red (Critical)
    'high'     = 60    # Score >= 60: Orange (High)
    'medium'   = 40    # Score >= 40: Yellow (Medium)
    'low'      = 20    # Score >= 20: Blue (Low)
    # Score < 20: Gray (Info)
}

# =============================================================================
# HELPER FUNCTION: Convert to JavaScript
# =============================================================================

function ConvertTo-ScoringJavaScript {
    <#
    .SYNOPSIS
        Converts PowerShell scoring definitions to JavaScript for HTML embedding.

    .DESCRIPTION
        Generates JavaScript code that can be embedded in the HTML report.
        Called by Export-HTMLReport.ps1 during report generation.
        BaseScores are extracted from $Script:FindingDefinitions.

    .OUTPUTS
        String containing JavaScript variable declarations.
    #>

    # Get base scores from FindingDefinitions (single source of truth)
    $baseScores = Get-FindingBaseScores

    $js = @"
        // ==========================================================================
        // SCORING DEFINITIONS (Auto-generated from adPEAS-FindingDefinitions.ps1)
        // ==========================================================================

        const findingBaseScores = {
"@

    # Add base scores from FindingDefinitions
    $sortedScores = $baseScores.GetEnumerator() | Sort-Object Value -Descending
    $scoreLines = @()
    foreach ($entry in $sortedScores) {
        $scoreLines += "            '$($entry.Key)': $($entry.Value)"
    }
    $js += $scoreLines -join ",`n"
    $js += @"

        };

        const severityBaseScores = {
            'finding': $($Script:SeverityFallbackScores[$Script:SeverityClasses.Finding]),
            'hint': $($Script:SeverityFallbackScores[$Script:SeverityClasses.Hint]),
            'note': $($Script:SeverityFallbackScores[$Script:SeverityClasses.Note]),
            'secure': $($Script:SeverityFallbackScores[$Script:SeverityClasses.Secure])
        };

        const impactMultipliers = {
            tier0: $($Script:ImpactMultipliers['tier0']),
            tier1: $($Script:ImpactMultipliers['tier1']),
            tier2: $($Script:ImpactMultipliers['tier2']),
            none: $($Script:ImpactMultipliers['none'])
        };

        const passwordAgeModifiers = {
            multiplier_10x: $($Script:PasswordAgeModifiers['multiplier_10x']),
            multiplier_5x: $($Script:PasswordAgeModifiers['multiplier_5x']),
            multiplier_3x: $($Script:PasswordAgeModifiers['multiplier_3x']),
            multiplier_2x: $($Script:PasswordAgeModifiers['multiplier_2x']),
            multiplier_1x: $($Script:PasswordAgeModifiers['multiplier_1x']),
            within_policy: $($Script:PasswordAgeModifiers['within_policy'])
        };

        const passwordLengthModifiers = {
            very_weak: $($Script:PasswordLengthModifiers['very_weak']),
            weak: $($Script:PasswordLengthModifiers['weak']),
            standard: $($Script:PasswordLengthModifiers['standard']),
            strong: $($Script:PasswordLengthModifiers['strong'])
        };

        const passwordComplexityModifiers = {
            disabled: $($Script:PasswordComplexityModifiers['disabled']),
            enabled: $($Script:PasswordComplexityModifiers['enabled'])
        };

        const encryptionTypeModifiers = {
            rc4_only: $($Script:EncryptionTypeModifiers['rc4_only']),
            aes128: $($Script:EncryptionTypeModifiers['aes128']),
            aes256: $($Script:EncryptionTypeModifiers['aes256'])
        };

        const securityModifiers = {
            ACCOUNTDISABLE: $($Script:SecurityModifiers['ACCOUNTDISABLE']),
            LOCKOUT: $($Script:SecurityModifiers['LOCKOUT']),
            SMARTCARD_REQUIRED: $($Script:SecurityModifiers['SMARTCARD_REQUIRED']),
            PASSWORD_EXPIRED: $($Script:SecurityModifiers['PASSWORD_EXPIRED']),
            USE_DES_KEY_ONLY: $($Script:SecurityModifiers['USE_DES_KEY_ONLY']),
            NOT_DELEGATED: $($Script:SecurityModifiers['NOT_DELEGATED']),
            PROTECTED_USERS: $($Script:SecurityModifiers['PROTECTED_USERS'])
        };

        const correlationBonus = {
            // Standard correlation (privileged accounts)
            perFinding: $($Script:CorrelationBonus['per_finding']),
            maxBonus: $($Script:CorrelationBonus['max_bonus']),
            // Enhanced correlation for non-admins (potential privilege escalation paths)
            nonAdminPerFinding: $($Script:CorrelationBonus['non_admin_per_finding']),
            nonAdminMaxBonus: $($Script:CorrelationBonus['non_admin_max_bonus']),
            nonAdminThreshold: $($Script:CorrelationBonus['non_admin_threshold'])
        };

        const scoreThresholds = {
            critical: $($Script:ScoreThresholds['critical']),
            high: $($Script:ScoreThresholds['high']),
            medium: $($Script:ScoreThresholds['medium']),
            low: $($Script:ScoreThresholds['low'])
        };
"@

    return $js
}

# =============================================================================
# EXPORT SCORING STATS (for debugging/documentation)
# =============================================================================

function Get-ScoringStats {
    <#
    .SYNOPSIS
        Returns statistics about the scoring definitions.

    .DESCRIPTION
        Extracts statistics from FindingDefinitions BaseScores.

    .EXAMPLE
        Get-ScoringStats
    #>

    $baseScores = Get-FindingBaseScores
    $scoreValues = $baseScores.Values

    [PSCustomObject]@{
        TotalFindings       = $baseScores.Count
        MaxBaseScore        = ($scoreValues | Measure-Object -Maximum).Maximum
        MinBaseScore        = ($scoreValues | Measure-Object -Minimum).Minimum
        AvgBaseScore        = [math]::Round(($scoreValues | Measure-Object -Average).Average, 1)
        ScoreCategories     = @{
            'Critical (80-100)' = ($scoreValues | Where-Object { $_ -ge 80 }).Count
            'High (60-79)'      = ($scoreValues | Where-Object { $_ -ge 60 -and $_ -lt 80 }).Count
            'Medium (40-59)'    = ($scoreValues | Where-Object { $_ -ge 40 -and $_ -lt 60 }).Count
            'Low (20-39)'       = ($scoreValues | Where-Object { $_ -ge 20 -and $_ -lt 40 }).Count
            'Info (0-19)'       = ($scoreValues | Where-Object { $_ -lt 20 }).Count
        }
    }
}
