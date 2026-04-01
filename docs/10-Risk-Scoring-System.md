# Risk Scoring System

Documentation of the context-aware risk scoring system used in adPEAS v2 HTML reports.

> **Maintenance:** All scoring values are centrally defined in:
> - **PowerShell:** `src/modules/Core/adPEAS-ScoringDefinitions.ps1`
> - **JavaScript:** Auto-generated from PowerShell during build via `ConvertTo-ScoringJavaScript`

---

## Overview

The adPEAS v2 scoring system calculates realistic risk scores based on multiple contextual factors rather than simple title-based categorization. This enables security teams to prioritize remediation efforts based on actual exploitability and potential impact.

### Scoring Formula

```
FINAL_SCORE = (BASE × IMPACT × EXPLOITABILITY × SECURITY) + CORRELATION
```

| Component | Range | Description |
|-----------|-------|-------------|
| **BASE** | 0-100 | Intrinsic severity of the finding type |
| **IMPACT** | 1.0-2.0 | Multiplier based on account privilege tier |
| **EXPLOITABILITY** | 0.6-1.6 | Modifier based on password age, policy, encryption |
| **SECURITY** | 0.1-1.0 | Reduction factor for mitigating controls |
| **CORRELATION** | 0-15 | Bonus for accounts appearing in multiple findings |

**Final score is clamped to 0-100.**

---

## Base Scores by Finding Type

Base scores represent the intrinsic risk of each vulnerability type. The actual score is then modified by context.

### Direct Compromise (Base 80-100)

These findings can lead to immediate domain compromise.

| Keyword | Base Score | Check Module | Description |
|---------|------------|--------------|-------------|
| `dcsync` | 100 | Get-DangerousACLs | DCSync rights - immediate domain compromise |
| `replication rights` | 100 | Get-DangerousACLs | Same as DCSync |
| `esc1` | 90 | Get-ADCSVulnerabilities | ADCS ESC1 - enrollee supplies subject + client auth |
| `esc2` | 80 | Get-ADCSVulnerabilities | ADCS ESC2 - any purpose or SubCA template |
| `esc3` | 75 | Get-ADCSVulnerabilities | ADCS ESC3 - certificate request agent |
| `esc4` | 70 | Get-ADCSVulnerabilities | ADCS ESC4 - dangerous template ACL |
| `esc13` | 70 | Get-ADCSVulnerabilities | ADCS ESC13 - issuance policy linked to AD group |
| `esc6` | 65 | Get-ADCSVulnerabilities | ADCS ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 on CA |
| `esc7` | 65 | Get-ADCSVulnerabilities | ADCS ESC7 - dangerous CA permissions |
| `esc8` | 70 | Get-ADCSVulnerabilities | ADCS ESC8 - NTLM relay to web enrollment |
| `esc9` | 60 | Get-ADCSVulnerabilities | ADCS ESC9 - template without security extension |
| `esc10` | 60 | Get-ADCSVulnerabilities | ADCS ESC10 - weak certificate mapping |
| `esc15` | 30 | Get-ADCSVulnerabilities | ADCS ESC15 - schema v1 template with enrollee subject |
| `unconstrained delegation` | 85 | Get-UnconstrainedDelegation | Can capture TGTs |
| `sid history` | 80 | Get-SIDHistoryInjection | SID History injection |

### Credential Exposure (Base 40-60)

Findings that expose or allow access to credentials.

| Keyword | Base Score | Check Module | Description |
|---------|------------|--------------|-------------|
| `laps credential` | 55 | Get-LAPSCredentialAccess | LAPS password readable |
| `laps access` | 45 | Get-LAPSPermissions | LAPS password read permissions |
| `laps password` | 55 | Get-LAPSCredentialAccess | LAPS password readable |
| `gpp password` | 50 | Get-CredentialExposure | Group Policy Preferences password |
| `cpassword` | 50 | Get-CredentialExposure | GPP cpassword attribute |
| `cleartext credential` | 50 | Get-CredentialExposure | Cleartext credentials found |
| `plaintext credential` | 50 | Get-CredentialExposure | Plaintext credentials found |
| `credential exposure` | 45 | Get-CredentialExposure | Generic credential exposure |
| `autoadminlogon` | 45 | Get-CredentialExposure | AutoAdminLogon credentials |
| `password in script` | 45 | Get-GPOScheduledTasks | Password in scheduled task script |
| `sensitive information` | 40 | Get-CredentialExposure | Sensitive data exposure |
| `net use` | 40 | Get-CredentialExposure | Net use with credentials |

### Requires Cracking (Base 30-50)

Findings that require offline password cracking.

| Keyword | Base Score | Check Module | Description |
|---------|------------|--------------|-------------|
| `kerberoastable` | 35 | Get-KerberoastableAccounts | Kerberoastable service account |
| `kerberoast` | 35 | Get-KerberoastableAccounts | Kerberoastable service account |
| `asrep roast` | 30 | Get-ASREPRoastableAccounts | AS-REP roastable account |
| `as-rep roast` | 30 | Get-ASREPRoastableAccounts | AS-REP roastable account |
| `preauth not required` | 30 | Get-ASREPRoastableAccounts | Pre-authentication disabled |

### Delegation Abuse (Base 50-55)

Findings related to Kerberos delegation misconfigurations.

| Keyword | Base Score | Check Module | Description |
|---------|------------|--------------|-------------|
| `rbcd` | 55 | Get-ResourceBasedConstrainedDelegation | Resource-Based Constrained Delegation |
| `resource-based constrained` | 55 | Get-ResourceBasedConstrainedDelegation | RBCD abuse |
| `constrained delegation` | 50 | Get-ConstrainedDelegation | Constrained delegation configured |

### ACL Abuse (Base 40-60)

Findings related to dangerous Access Control List entries.

| Keyword | Base Score | Check Module | Description |
|---------|------------|--------------|-------------|
| `genericall` | 60 | Get-DangerousACLs | Full control over object |
| `writedacl` | 55 | Get-DangerousACLs | Can modify permissions |
| `writeowner` | 55 | Get-DangerousACLs | Can change ownership |
| `genericwrite` | 50 | Get-DangerousACLs | Can write to object |
| `password reset` | 50 | Get-PasswordResetRights | Can reset passwords |
| `reset password` | 50 | Get-PasswordResetRights | Can reset passwords |
| `gpo permission` | 50 | Get-GPOPermissions | Can modify GPOs |
| `dangerous permission` | 45 | Get-DangerousACLs | Other dangerous ACL |
| `laps permission` | 45 | Get-LAPSPermissions | Can read LAPS passwords |
| `gpo link` | 45 | Get-GPOPermissions | Can link GPOs |
| `ou permission` | 40 | Get-DangerousOUPermissions | Dangerous OU permissions |

### Configuration Weakness (Base 25-45)

Findings related to insecure configurations.

| Keyword | Base Score | Check Module | Description |
|---------|------------|--------------|-------------|
| `local admin` | 45 | Get-GPOLocalGroupMembership | Added to local admins via GPO |
| `computer owner` | 40 | Get-NonDefaultComputerOwners | Non-default computer owner |
| `local group` | 40 | Get-GPOLocalGroupMembership | GPO local group membership |
| `password not required` | 35 | Get-PasswordNotRequired | PASSWD_NOTREQD flag |
| `add computer` | 35 | Get-AddComputerRights | Can add computers to domain |
| `laps not configured` | 35 | Get-LAPSConfiguration | LAPS not deployed |
| `reversible encryption` | 30 | Get-AdminReversibleEncryption | Reversible encryption enabled |
| `inactive admin` | 30 | Get-InactiveAdminAccounts | Inactive admin account |
| `orphaned admin` | 30 | Get-InactiveAdminAccounts | Orphaned admin account |
| `smb signing` | 30 | Get-SMBSigningStatus | SMB signing not required |
| `machineaccountquota` | 15 | Get-AddComputerRights | MachineAccountQuota > 0 |
| `kds root key` | 30 | Get-ManagedServiceAccountSecurity | KDS root key issues |
| `password never expires` | 25 | Get-AdminPasswordNeverExpires | Password never expires |
| `ldap signing` | 25 | Get-LDAPConfiguration | LDAP signing not required |
| `channel binding` | 25 | Get-LDAPConfiguration | Channel binding not required |

### Managed Service Accounts (Base 20-25)

Findings related to service account security.

| Keyword | Base Score | Check Module | Description |
|---------|------------|--------------|-------------|
| `gmsa password readable` | 55 | Get-ManagedServiceAccountSecurity | gMSA password retrievable |
| `managed service account` | 25 | Get-ManagedServiceAccountSecurity | MSA configuration issue |
| `smsa` | 20 | Get-ManagedServiceAccountSecurity | sMSA configuration issue |

### Infrastructure (Base 30-45)

Findings related to infrastructure components.

| Keyword | Base Score | Check Module | Description |
|---------|------------|--------------|-------------|
| `exchange` | 45 | Get-ExchangeInfrastructure | Exchange infrastructure finding |
| `unsupported os` | 40 | Get-OutdatedComputers | Unsupported operating system |
| `scom` | 35 | Get-SCOMInfrastructure | SCOM infrastructure |
| `sccm site hierarchy` | 30 | Get-SCCMInfrastructure | SCCM multi-site hierarchy |
| `sccm pxe` | 25 | Get-SCCMInfrastructure | PXE boot server exposure |
| `sccm client` | 20 | Get-SCCMInfrastructure | SCCM client deployment scope |
| `aging os` | 15 | Get-OutdatedComputers | Aging operating system (nearing EOL) |
| `unix password` | 30 | Get-UnixPasswordAccounts | Unix password attributes |
| `unixuserpwd` | 30 | Get-UnixPasswordAccounts | unixUserPassword attribute |

### LAPS Configuration (Base 20-35)

Findings related to LAPS deployment.

| Keyword | Base Score | Check Module | Description |
|---------|------------|--------------|-------------|
| `laps not configured` | 35 | Get-LAPSConfiguration | LAPS missing |
| `laps` | 20 | Get-LAPSConfiguration | LAPS informational |

### Informational (Base 10-15)

Low-severity informational findings.

| Keyword | Base Score | Check Module | Description |
|---------|------------|--------------|-------------|
| `privileged group` | 15 | Get-PrivilegedGroupMembers | Privileged group membership |
| `trust` | 15 | Get-DomainTrusts | Domain trust |
| `group member` | 10 | Get-PrivilegedGroupMembers | Group membership info |
| `protected users` | 10 | Get-ProtectedUsersStatus | Protected Users status |
| `password policy` | 10 | Get-DomainPasswordPolicy | Password policy info |
| `domain controller` | 10 | Get-InfrastructureServers | Domain controller info |
| `infrastructure server` | 10 | Get-InfrastructureServers | Infrastructure server info |

### Fallback Scores

When no keyword matches, the system uses severity-based fallbacks:

| Severity Class | Fallback Score |
|----------------|----------------|
| `finding` | 35 |
| `hint` | 15 |
| `note` | 0 |
| `secure` | 0 |

---

## Impact Multipliers (Account Tier)

The impact multiplier adjusts the base score based on the privilege level of the affected account.

### Microsoft Tiering Model

adPEAS uses the [Microsoft Privileged Access Model](https://docs.microsoft.com/en-us/security/privileged-access-workstations/) for tier classification:

| Tier | Multiplier | SID Pattern | Groups | Scope |
|------|------------|-------------|--------|-------|
| **Tier 0** | ×2.0 | `-512`, `-519`, `-518` | Domain Admins, Enterprise Admins, Schema Admins | Domain Controllers |
| **Tier 1** | ×1.5 | `-548`, `-549`, `-551`, `-550` | Account Operators, Server Operators, Backup Operators, Print Operators | Servers |
| **Tier 2** | ×1.2 | Other privileged | Other administrative groups | Workstations |
| **None** | ×1.0 | Standard | Regular user accounts | - |

### Example Calculation

```
Kerberoastable Domain Admin:
  Base: 35 (kerberoastable)
  × Impact: 2.0 (Tier 0 - Domain Admin)
  = 70 (before other modifiers)

Kerberoastable Standard User:
  Base: 35 (kerberoastable)
  × Impact: 1.0 (None)
  = 35 (before other modifiers)
```

---

## Exploitability Modifiers

The exploitability modifier adjusts the score based on factors that affect how easily the vulnerability can be exploited.

### Password Age (Relative to Policy)

Password age is evaluated **relative to the domain's maxPwdAge policy**, not as an absolute value.

| Policy Multiples | Modifier | Description |
|------------------|----------|-------------|
| ≥10× maxPwdAge | ×1.6 | Extremely old password |
| ≥5× maxPwdAge | ×1.4 | Very old password |
| ≥3× maxPwdAge | ×1.3 | Old password |
| ≥2× maxPwdAge | ×1.2 | Moderately old |
| ≥1× maxPwdAge | ×1.1 | Over policy limit |
| <1× maxPwdAge | ×1.0 | Within policy |

**Example:** If maxPwdAge = 90 days:
- Password 900 days old → 10× policy → ×1.6 modifier
- Password 180 days old → 2× policy → ×1.2 modifier
- Password 45 days old → 0.5× policy → ×1.0 modifier

### Password Policy Strength

The domain's password policy affects cracking-based attack scores.

#### Minimum Password Length

| Min Length | Modifier | Description |
|------------|----------|-------------|
| <8 chars | ×1.4 | Very weak - easy to crack |
| 8-11 chars | ×1.2 | Weak |
| 12-15 chars | ×1.0 | Standard |
| ≥16 chars | ×0.8 | Strong - harder to crack |

#### Password Complexity

| Complexity | Modifier | Description |
|------------|----------|-------------|
| Disabled | ×1.25 | Weak passwords likely |
| Enabled | ×1.0 | Standard complexity |

**Note:** Complexity is determined from the `pwdProperties` attribute (bit 0 = DOMAIN_PASSWORD_COMPLEX).

### Encryption Types (for Kerberos-based attacks)

| Encryption | Modifier | Description |
|------------|----------|-------------|
| RC4 only (etype 23) | ×1.3 | Fast to crack |
| AES128 (etype 17) | ×1.0 | Standard |
| AES256 (etype 18) | ×0.9 | Slower to crack |

---

## Security Modifiers (Mitigating Controls)

Security modifiers **reduce** the score when mitigating controls are in place.

### UAC Flags

| Flag | Modifier | Applies To | Description |
|------|----------|------------|-------------|
| `ACCOUNTDISABLE` | ×0.1 | All findings | Account is disabled |
| `LOCKOUT` | ×0.3 | All findings | Account is locked out |
| `SMARTCARD_REQUIRED` | ×0.15 | Cracking attacks | Password is random/unknown |
| `PASSWORD_EXPIRED` | ×0.7 | Credential attacks | Password may be changed soon |
| `USE_DES_KEY_ONLY` | ×1.3 | Kerberos attacks | Weak encryption (increases risk) |
| `NOT_DELEGATED` | ×0.3 | Delegation attacks | Delegation protection enabled |

### Protected Users Group

| Status | Modifier | Description |
|--------|----------|-------------|
| Member of Protected Users | ×0.2 | Strong Kerberos protections |
| Not a member | ×1.0 | No additional protection |

Protected Users membership is detected via:
1. SID ending in `-525` in `memberOf`
2. `isProtectedUser` flag in scoring context

### Modifier Application Logic

```javascript
// Cracking attacks: Kerberoast, AS-REP Roast
if (isCrackingAttack && hasSmartcardRequired) {
    modifier *= 0.15;  // Password is random, can't crack
}

// Delegation attacks: Unconstrained, Constrained, RBCD
if (isDelegationAttack && hasNotDelegated) {
    modifier *= 0.3;   // Delegation protection enabled
}

// All attacks: Account disabled
if (hasAccountDisable) {
    modifier *= 0.1;   // Account can't be used
}
```

---

## Correlation Bonus

The correlation bonus increases the score when the same account appears in multiple risky findings. **Non-admin accounts receive enhanced bonuses** because multiple findings suggest potential privilege escalation paths.

### Standard Correlation (Privileged Accounts)

```javascript
correlationBonus = (numberOfFindings - 1) * 5
// Capped at 15 points
```

| Findings | Bonus |
|----------|-------|
| 1 finding | +0 |
| 2 findings | +5 |
| 3 findings | +10 |
| 4+ findings | +15 (max) |

### Enhanced Correlation (Non-Admin Accounts)

**Rationale:** When a non-admin user appears in 3+ findings, it often indicates an attack path exists (e.g., User → LAPS Read → Computer → gMSA → DCSync). These accounts deserve heightened attention.

```javascript
// Non-admin accounts with 3+ findings get enhanced scoring
if (isNonAdmin && findingCount >= 3) {
    correlationBonus = (numberOfFindings - 1) * 8
    // Capped at 30 points
}
```

| Findings | Non-Admin Bonus | Standard Bonus |
|----------|-----------------|----------------|
| 1 finding | +0 | +0 |
| 2 findings | +8 | +5 |
| 3 findings | +16 | +10 |
| 4 findings | +24 | +15 (max) |
| 5+ findings | +30 (max) | +15 (max) |

### Configuration Values

| Parameter | Standard | Non-Admin |
|-----------|----------|-----------|
| Points per finding | 5 | 8 |
| Maximum bonus | 15 | 30 |
| Threshold | 2 | 3 |

### Example: Attack Path Detection

Non-admin user `john.doe` appears in:
1. **LAPS Read Rights** on OU=Servers
2. **Computer Owner** of SRV-SQL01
3. **gMSA Password Reader** for svc_backup$
4. *(svc_backup$ has DCSync rights)*

Analysis:
- Account is non-admin (adminTier = 'none')
- Appears in 3 findings → triggers enhanced correlation
- Correlation bonus: (3-1) × 8 = **+16 points**

This elevated score reflects the potential attack path: `john.doe` → LAPS/Owner → Computer → gMSA → DCSync.

### Dangerous Combinations

Certain finding combinations always receive maximum bonus:

| Combination | Bonus (Admin) | Bonus (Non-Admin) |
|-------------|---------------|-------------------|
| DCSync + Kerberoast/ASREP | +15 | +30 |
| Delegation + Kerberoast | +10 | +16 |

---

## Complete Scoring Examples

### Example 1: High-Risk Kerberoastable Domain Admin

**Finding:** Domain Admin with Kerberoastable SPN, old password, RC4 only

| Component | Value | Calculation |
|-----------|-------|-------------|
| Base Score | 35 | Kerberoastable |
| Impact | ×2.0 | Tier 0 (Domain Admin) |
| Password Age | ×1.4 | 5× maxPwdAge |
| Encryption | ×1.3 | RC4 only |
| Policy Length | ×1.2 | 8-char minimum |
| Security | ×1.0 | No mitigations |
| Correlation | +10 | 3 findings |

**Final:** min(max((35 × 2.0 × 1.4 × 1.3 × 1.2 × 1.0) + 10, 0), 100) = **100** (capped)

### Example 2: Low-Risk Kerberoastable with Mitigations

**Finding:** Standard user, Kerberoastable, Smartcard Required, Protected Users

| Component | Value | Calculation |
|-----------|-------|-------------|
| Base Score | 35 | Kerberoastable |
| Impact | ×1.0 | None (standard user) |
| Exploitability | ×1.0 | Recent password |
| Security (Smartcard) | ×0.15 | Password is random |
| Security (Protected) | ×0.2 | Protected Users member |
| Correlation | +0 | 1 finding |

**Final:** (35 × 1.0 × 1.0 × 0.15 × 0.2) + 0 = **1** (very low risk)

### Example 3: DCSync Rights

**Finding:** Non-admin user with DCSync rights

| Component | Value | Calculation |
|-----------|-------|-------------|
| Base Score | 100 | DCSync |
| Impact | ×1.0 | Standard user (but irrelevant - DCSync IS compromise) |
| Exploitability | ×1.0 | N/A |
| Security | ×1.0 | No mitigations |
| Correlation | +0 | 1 finding |

**Final:** 100 × 1.0 × 1.0 × 1.0 + 0 = **100**

---

## Implementation Details

### Data Collection (PowerShell)

The scoring context is built in `Export-HTMLReport.ps1` via the `Build-ScoringContext` function:

```powershell
$scoringContext = @{
    accounts = @{}           # Account info by sAMAccountName
    findingContext = @{}     # Finding metadata
    correlations = @{}       # Account appearance counts
    domainInfo = @{
        passwordPolicy = $null
        maxPwdAgeDays = 0
        minPwdLength = 0
        complexityEnabled = $true
        krbtgtLastReset = $null
    }
}
```

### Score Calculation (JavaScript)

The scoring is performed client-side in the HTML report:

```javascript
function calculateFindingScore(card) {
    const baseScore = getBaseScore(title);
    const impactMod = impactMultipliers[accountInfo.adminTier] || 1.0;
    const exploitMod = getExploitabilityModifier(accountInfo, title);
    const securityMod = getSecurityModifier(accountInfo, title);
    const correlationBonus = getCorrelationBonus(accountInfo);

    let finalScore = Math.round(baseScore * impactMod * exploitMod * securityMod) + correlationBonus;
    return Math.min(Math.max(finalScore, 0), 100);
}
```

### Score Display

Scores are displayed as badges with color coding:

| Score Range | Color | CSS Class |
|-------------|-------|-----------|
| 80-100 | Red | `score-critical` |
| 60-79 | Orange | `score-high` |
| 40-59 | Yellow | `score-medium` |
| 20-39 | Blue | `score-low` |
| 0-19 | Gray | `score-info` |

---

## Customization

All scoring values are centrally maintained in `src/modules/Core/adPEAS-ScoringDefinitions.ps1`.

### Adding New Base Scores

Edit the `$Script:FindingBaseScores` hashtable:

```powershell
$Script:FindingBaseScores = @{
    # ... existing scores ...
    'new finding keyword'  = 45    # Add your keyword (lowercase)
}
```

### Adjusting Multipliers

Edit the respective hashtables:

```powershell
# Impact multipliers (Microsoft Tiering Model)
$Script:ImpactMultipliers = @{
    'tier0' = 2.0    # Domain/Enterprise/Schema Admins (Domain Controllers)
    'tier1' = 1.5    # Operators (Servers)
    'tier2' = 1.2    # Other privileged (Workstations)
    'none'  = 1.0    # Standard accounts
}

# Security modifiers
$Script:SecurityModifiers = @{
    'ACCOUNTDISABLE'      = 0.1
    'SMARTCARD_REQUIRED'  = 0.15
    # ...
}
```


---

## Limitations

1. **Password Age Estimation:** Password age is calculated from `pwdLastSet`, which may not reflect actual password strength.

2. **Encryption Types:** The `msDS-SupportedEncryptionTypes` attribute may not always reflect actual negotiated encryption.

3. **Protected Users Detection:** Requires proper SID resolution; nested group membership may not be fully evaluated.

4. **Policy Inheritance:** Fine-grained password policies (PSOs) are not currently evaluated - only the default domain policy.

---

## References

- [Microsoft: Protected Users Security Group](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [Microsoft: Kerberos Encryption Types](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos)
- [SpecterOps: Kerberoasting](https://posts.specterops.io/kerberoasting-revisited-d434351bd4d1)
- [HarmJ0y: Kerberos Delegation](https://blog.harmj0y.net/activedirectory/s4u2pwnage/)

---

## Navigation

- [Previous: Architecture](09-Architecture.md)
- [Next: Troubleshooting](11-Troubleshooting.md)
- [Back to Home](00-Home.md)