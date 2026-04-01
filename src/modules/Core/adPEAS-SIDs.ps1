<#
.SYNOPSIS
    Central SID definitions for Active Directory Security Checks.

.DESCRIPTION
    This module provides centralized Security Identifier (SID) definitions used across all adPEAS modules for privileged account detection, ACL analysis, and security checks.

    Categories:
    - Privileged SIDs: Well-known privileged identities (SYSTEM, Administrators, etc.)
    - Operator SIDs: Operator groups (Account/Server/Backup/Print Operators)
    - Privileged RID Suffixes: Domain-relative RIDs for privileged groups (-512, -519, etc.)
    - DCSync-Specific: Stricter subset for DCSync-specific checks
    - Exchange Groups: Exchange privileged group names (SIDs vary per installation)
    - Self-Modification SIDs: SELF, Creator Owner (normal on objects)
    - Legacy Compatibility SIDs: Pre-Windows 2000 Compatible Access
    - Container Operator SIDs: Groups expected on containers like CN=Computers
    - Broad Group SIDs: Everyone, Authenticated Users, Domain Users, etc.

    All modules should use these central definitions instead of maintaining their own copies.
    This ensures consistency and simplifies maintenance.

    Reference: https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers

.NOTES
    Author: Alexander Sturz (@_61106960_)
    This module must be loaded BEFORE any module that uses SID-based checks.
#>

# ============================================================================
# PRIVILEGED SIDs (Well-Known, Static)
# ============================================================================
# These are well-known SIDs that are ALWAYS privileged, regardless of domain.
# Used for direct SID matching in Test-IsPrivileged.

<#
.SYNOPSIS
    Well-known privileged SIDs (static, not domain-specific).
.DESCRIPTION
    These identities have elevated privileges on any Windows/AD system.
    Used by Test-IsPrivileged for direct SID matching.
#>
$Script:PrivilegedSIDs = @(
    'S-1-5-18',       # SYSTEM (Local System)
    'S-1-5-19',       # LOCAL SERVICE
    'S-1-5-20',       # NETWORK SERVICE
    'S-1-5-32-544',   # BUILTIN\Administrators
    'S-1-5-9'         # Enterprise Domain Controllers
)

# ============================================================================
# OPERATOR SIDs (Optional Privileged)
# ============================================================================
# Operator groups can manage specific resources. Whether they are considered "privileged" depends on context (controlled by -IncludeOperators parameter).

<#
.SYNOPSIS
    Operator group SIDs (optional, controlled by -IncludeOperators).
.DESCRIPTION
    These BUILTIN groups have specific administrative capabilities:
    - Account Operators: Can manage users and groups (but not Domain Admins)
    - Server Operators: Can manage domain servers
    - Print Operators: Can manage printers and have CreateChild on CN=Computers
    - Backup Operators: Can backup/restore files, bypassing ACLs
#>
$Script:OperatorSIDs = @(
    'S-1-5-32-548',   # Account Operators
    'S-1-5-32-549',   # Server Operators
    'S-1-5-32-550',   # Print Operators
    'S-1-5-32-551'    # Backup Operators
)

# ============================================================================
# PRIVILEGED RID SUFFIXES (Domain-Relative)
# ============================================================================
# These RIDs, when appended to a domain SID (S-1-5-21-xxx-xxx-xxx-RID), identify privileged groups that exist in every AD domain.

<#
.SYNOPSIS
    Domain-relative RID suffixes for privileged groups.
.DESCRIPTION
    These RIDs identify domain-specific privileged groups.
    Full SID format: <DomainSID>-<RID> (e.g., S-1-5-21-xxx-xxx-xxx-512)
#>
$Script:PrivilegedRIDSuffixes = @(
    '-498',   # Enterprise Read-only Domain Controllers
    '-500',   # Domain Administrator (built-in)
    '-502',   # KRBTGT
    '-512',   # Domain Admins
    '-516',   # Domain Controllers
    '-518',   # Schema Admins (forest root)
    '-519',   # Enterprise Admins (forest root)
    '-520',   # Group Policy Creator Owners (can create/edit GPOs)
    '-521',   # Read-only Domain Controllers
    '-526',   # Key Admins
    '-527'    # Enterprise Key Admins
)

# ============================================================================
# OPERATOR RID SUFFIXES (Domain-Relative)
# ============================================================================
# Domain-relative groups that have specific administrative capabilities but are not Tier-0.
# These are "Operator" level (Tier-1) - they can facilitate attacks but don't provide direct domain takeover.

<#
.SYNOPSIS
    Domain-relative RID suffixes for Operator-level groups.
.DESCRIPTION
    These RIDs identify domain-specific groups with elevated but limited privileges.
    Full SID format: <DomainSID>-<RID> (e.g., S-1-5-21-xxx-xxx-xxx-517)

    Cert Publishers (-517):
    - Can write to userCertificate attribute on all objects
    - NOT direct domain takeover, but can facilitate ESC attacks
    - Tier-1 (Operator), not Tier-0 (Privileged)
#>
$Script:OperatorRIDSuffixes = @(
    '-517'    # Cert Publishers (can write certificates, Tier-1)
)

# ============================================================================
# TIER-0 RID SUFFIXES (Domain Admins, Enterprise Admins, Schema Admins)
# ============================================================================
# True Tier-0 groups that represent the highest privilege level in Active Directory.
# These are the accounts that SHOULD be protected by "Protected Users" group.
# Note: krbtgt (-502), DC computer accounts (-516), and gMSAs are excluded from
# "should be protected" checks as Protected Users is not applicable to them.

<#
.SYNOPSIS
    Domain-relative RID suffixes for true Tier-0 privileged groups.
.DESCRIPTION
    These are the accounts with the highest privilege level in AD:
    - Domain Admins (-512): Full control over the domain
    - Enterprise Admins (-519): Full control over the forest (forest root only)
    - Schema Admins (-518): Can modify AD schema (forest root only)
    - Built-in Administrator (-500): Default admin account

    Explicitly EXCLUDED from Protected Users applicability:
    - krbtgt (-502): Service account, cannot use Protected Users
    - Domain Controllers (-516): Computer accounts, not applicable
    - RODCs (-521): Computer accounts, not applicable
#>
$Script:Tier0RIDSuffixes = @(
    '-500',   # Built-in Administrator account
    '-512',   # Domain Admins
    '-518',   # Schema Admins (forest root only)
    '-519'    # Enterprise Admins (forest root only)
)

<#
.SYNOPSIS
    Well-known SID for BUILTIN\Administrators group.
.DESCRIPTION
    Members of BUILTIN\Administrators on Domain Controllers are effectively Tier-0.
    This is a static SID that exists on all Windows systems.
#>
$Script:Tier0StaticSIDs = @(
    'S-1-5-32-544'   # BUILTIN\Administrators
)

<#
.SYNOPSIS
    RID suffixes for accounts that are Tier-0 but CANNOT use Protected Users.
.DESCRIPTION
    These accounts are privileged but Protected Users membership is not applicable:
    - krbtgt: Kerberos service account (cannot authenticate interactively)
    - DC$ accounts: Computer accounts (Protected Users only for users)
    - gMSAs: Group Managed Service Accounts (cannot use Protected Users)
#>
$Script:Tier0ExcludedFromProtectionRIDs = @(
    '-502',   # krbtgt (service account)
    '-516',   # Domain Controllers (computer accounts)
    '-521'    # Read-only Domain Controllers (computer accounts)
)

# ============================================================================
# DCSYNC-SPECIFIC SIDs AND RIDs (Stricter Subset)
# ============================================================================
# For DCSync vulnerability checks, we use a STRICTER definition of "privileged".
# Only accounts that LEGITIMATELY should have DCSync rights are included.
# This excludes groups like Domain Admins because DCSync rights granted to non-standard accounts should be flagged as findings.

<#
.SYNOPSIS
    DCSync-specific privileged SIDs (stricter subset).
.DESCRIPTION
    Only accounts that LEGITIMATELY should have DCSync rights:
    - SYSTEM: Has full access by design
    - Administrators: Built-in local admin group
    - Enterprise Domain Controllers: Replication between DCs
#>
$Script:DCSyncPrivilegedSIDs = @(
    'S-1-5-18',       # SYSTEM
    'S-1-5-32-544',   # BUILTIN\Administrators
    'S-1-5-9'         # Enterprise Domain Controllers
)

<#
.SYNOPSIS
    DCSync-specific RID suffixes (stricter subset).
.DESCRIPTION
    Domain-relative RIDs that legitimately should have DCSync rights.
    Excludes Cert Publishers, Key Admins, etc. which don't need DCSync.
#>
$Script:DCSyncPrivilegedRIDSuffixes = @(
    '-500',   # Domain Administrator
    '-512',   # Domain Admins
    '-516',   # Domain Controllers
    '-518',   # Schema Admins
    '-519',   # Enterprise Admins
    '-521'    # Read-only Domain Controllers
)

# ============================================================================
# EXCHANGE PRIVILEGED GROUPS (By Name)
# ============================================================================
# Exchange groups have variable SIDs per installation, so we match by name.
# ============================================================================
# CONTEXT-SPECIFIC IDENTITY FILTERING
# ============================================================================
# Different security checks require different filtering logic:
# - Domain Root ACLs: Broad groups are FINDINGS (should never have GenericAll/DCSync)
# - OU ACLs: SELF/Creator Owner are normal (self-modification)
# - CN=Computers: SELF/Creator Owner/Pre-Win2000 are normal (object management)

<#
.SYNOPSIS
    Special identity SIDs that are NORMAL on child objects (OUs, Containers).
.DESCRIPTION
    These represent "the object itself" or "the creator" - expected ACL entries.
    Should be filtered out (skipped) when analyzing OUs, containers, and objects.
    Should NOT be filtered on Domain Root (where they would be findings).
#>
$Script:SelfModificationSIDs = @(
    'S-1-5-10',       # SELF (Principal Self) - object can modify itself
    'S-1-3-0',        # Creator Owner - creator has rights on created objects
    'S-1-3-1'         # Creator Group - creator's primary group
)

<#
.SYNOPSIS
    Legacy compatibility SIDs - normal on containers like CN=Computers.
.DESCRIPTION
    Pre-Windows 2000 Compatible Access is expected on legacy containers.
#>
$Script:LegacyCompatibilitySIDs = @(
    'S-1-5-32-554'    # BUILTIN\Pre-Windows 2000 Compatible Access
)

<#
.SYNOPSIS
    Operator groups that are EXPECTED to have CreateChild on CN=Computers.
.DESCRIPTION
    These are not privileged for other purposes but CAN manage computer
    accounts by design in the CN=Computers container.
#>
$Script:ContainerOperatorSIDs = @(
    'S-1-5-32-548',   # Account Operators - can create/manage users and computers
    'S-1-5-32-550'    # Print Operators - legacy, has CreateChild on CN=Computers by default
)

# ============================================================================
# BROAD GROUP SIDs (Static, Well-Known)
# ============================================================================
# These groups include large numbers of users by default.
# If found with dangerous rights (GenericAll, DCSync), they are ALWAYS findings (except where explicitly handled, like Authenticated Users + MachineAccountQuota).

<#
.SYNOPSIS
    Broad groups that IF found with dangerous rights are ALWAYS a finding.
.DESCRIPTION
    These well-known SIDs represent large populations of users:
    - Everyone: All users including anonymous
    - Authenticated Users: All domain-authenticated users
    - Anonymous Logon: Unauthenticated access
    - BUILTIN\Users: Local users group
    - BUILTIN\Guests: Guest account group
#>
$Script:BroadGroupSIDs = @(
    'S-1-1-0',        # Everyone
    'S-1-5-11',       # Authenticated Users
    'S-1-5-7',        # Anonymous Logon
    'S-1-5-4',        # Interactive
    'S-1-5-2',        # Network
    'S-1-5-32-545',   # BUILTIN\Users
    'S-1-5-32-546'    # BUILTIN\Guests
)

<#
.SYNOPSIS
    Broad group RID suffixes (domain-relative).
.DESCRIPTION
    Domain Users, Domain Guests, and Domain Computers are "broad" groups
    because they contain many/all domain members by default.
#>
$Script:BroadGroupRIDSuffixes = @(
    '-513',   # Domain Users
    '-514',   # Domain Guests
    '-515'    # Domain Computers
)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

<#
.SYNOPSIS
    Tests if a SID is in the privileged SIDs list.
.PARAMETER SID
    The Security Identifier to check.
.OUTPUTS
    Boolean - $true if the SID is in $Script:PrivilegedSIDs.
#>
function Test-IsPrivilegedSID {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SID
    )

    return $Script:PrivilegedSIDs -contains $SID
}

<#
.SYNOPSIS
    Tests if a SID is an operator group SID.
.PARAMETER SID
    The Security Identifier to check.
.OUTPUTS
    Boolean - $true if the SID is in $Script:OperatorSIDs.
#>
function Test-IsOperatorSID {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SID
    )

    return $Script:OperatorSIDs -contains $SID
}

<#
.SYNOPSIS
    Tests if a SID matches a privileged RID suffix.
.PARAMETER SID
    The Security Identifier to check.
.OUTPUTS
    String - The matching RID suffix, or $null if no match.
#>
function Test-IsPrivilegedRID {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SID
    )

    foreach ($suffix in $Script:PrivilegedRIDSuffixes) {
        if ($SID -like "*$suffix") {
            return $suffix
        }
    }

    return $null
}

<#
.SYNOPSIS
    Tests if a SID matches an Operator RID suffix.
.PARAMETER SID
    The Security Identifier to check.
.OUTPUTS
    String - The matching RID suffix, or $null if no match.
#>
function Test-IsOperatorRID {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SID
    )

    foreach ($suffix in $Script:OperatorRIDSuffixes) {
        if ($SID -like "*$suffix") {
            return $suffix
        }
    }

    return $null
}

<#
.SYNOPSIS
    Tests if a SID is in the DCSync-specific privileged SIDs list.
.PARAMETER SID
    The Security Identifier to check.
.OUTPUTS
    Boolean - $true if the SID is in $Script:DCSyncPrivilegedSIDs.
#>
function Test-IsDCSyncPrivilegedSID {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SID
    )

    return $Script:DCSyncPrivilegedSIDs -contains $SID
}

<#
.SYNOPSIS
    Tests if a SID matches a DCSync-specific privileged RID suffix.
.PARAMETER SID
    The Security Identifier to check.
.OUTPUTS
    String - The matching RID suffix, or $null if no match.
#>
function Test-IsDCSyncPrivilegedRID {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SID
    )

    foreach ($suffix in $Script:DCSyncPrivilegedRIDSuffixes) {
        if ($SID -like "*$suffix") {
            return $suffix
        }
    }

    return $null
}

<#
.SYNOPSIS
    Tests if a SID is a self-modification identity (SELF, Creator Owner, Creator Group).
.PARAMETER SID
    The Security Identifier to check.
.OUTPUTS
    Boolean - $true if the SID is in $Script:SelfModificationSIDs.
#>
function Test-IsSelfModificationSID {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SID
    )

    return $Script:SelfModificationSIDs -contains $SID
}

<#
.SYNOPSIS
    Tests if a SID is a legacy compatibility identity.
.PARAMETER SID
    The Security Identifier to check.
.OUTPUTS
    Boolean - $true if the SID is in $Script:LegacyCompatibilitySIDs.
#>
function Test-IsLegacyCompatibilitySID {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SID
    )

    return $Script:LegacyCompatibilitySIDs -contains $SID
}

<#
.SYNOPSIS
    Tests if a SID is a container operator (expected on CN=Computers).
.PARAMETER SID
    The Security Identifier to check.
.OUTPUTS
    Boolean - $true if the SID is in $Script:ContainerOperatorSIDs.
#>
function Test-IsContainerOperatorSID {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SID
    )

    return $Script:ContainerOperatorSIDs -contains $SID
}

<#
.SYNOPSIS
    Tests if a SID is a broad group SID.
.PARAMETER SID
    The Security Identifier to check.
.OUTPUTS
    Boolean - $true if the SID is in $Script:BroadGroupSIDs.
#>
function Test-IsBroadGroupSID {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SID
    )

    return $Script:BroadGroupSIDs -contains $SID
}

<#
.SYNOPSIS
    Tests if a SID matches a broad group RID suffix.
.PARAMETER SID
    The Security Identifier to check.
.OUTPUTS
    String - The matching RID suffix, or $null if no match.
#>
function Test-IsBroadGroupRID {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SID
    )

    foreach ($suffix in $Script:BroadGroupRIDSuffixes) {
        if ($SID -like "*$suffix") {
            return $suffix
        }
    }

    return $null
}

# ============================================================================
# SECURITY SCOPES (Context-Dependent Expected Identities)
# ============================================================================
# Scopes define which identities are EXPECTED in specific security contexts.
# Used by Test-IsExpectedInScope to determine if a finding should be reported.
#
# Scope Structure:
# - ExpectedSIDs: Static SIDs that are expected (SYSTEM, Administrators, etc.)
# - ExpectedRIDSuffixes: Domain-relative RIDs that are expected (-512, -519, etc.)
# - AttentionBroadGroups: Broad groups that are "expected but noteworthy" (returns Attention, not Finding)
# - Description: Human-readable scope description

<#
.SYNOPSIS
    Security scope definitions for context-dependent identity checks.
.DESCRIPTION
    Each scope defines which identities are EXPECTED to have certain rights.
    Used by Test-IsExpectedInScope to classify findings.

    Severity returns:
    - "Expected": Identity is expected in this scope (no finding)
    - "Attention": Identity is technically expected but security-relevant (soft finding)
    - "Finding": Identity should NOT have these rights (hard finding)
#>
$Script:SecurityScopes = @{
    # ===== DCSync Scope =====
    # Who SHOULD have DCSync rights (DS-Replication-Get-Changes-All)?
    # Note: Domain Admins CAN have DCSync but should still be flagged
    # because custom accounts with DCSync are the real risk.
    'DCSync' = @{
        Description = "Identities that legitimately need DCSync (replication) rights"
        ExpectedSIDs = @(
            'S-1-5-18',       # SYSTEM
            'S-1-5-32-544',   # BUILTIN\Administrators
            'S-1-5-9'         # Enterprise Domain Controllers
        )
        ExpectedRIDSuffixes = @(
            '-516',   # Domain Controllers
            '-521'    # Read-only Domain Controllers
        )
        AttentionBroadGroups = @()    # No broad groups allowed
    }

    # ===== Domain Root ACL Scope =====
    # Who SHOULD have GenericAll/WriteDACL on the domain root object?
    'DomainRootACL' = @{
        Description = "Identities expected to have full control on domain root"
        ExpectedSIDs = @(
            'S-1-5-18',       # SYSTEM
            'S-1-5-32-544'    # BUILTIN\Administrators
        )
        ExpectedRIDSuffixes = @(
            '-500',   # Built-in Administrator
            '-512',   # Domain Admins
            '-519'    # Enterprise Admins
        )
        AttentionBroadGroups = @()  # No broad groups allowed on domain root
    }

    # ===== OU ACL Scope =====
    # Who SHOULD have GenericAll/WriteDACL on Organizational Units?
    'OUACL' = @{
        Description = "Identities expected to manage OUs"
        ExpectedSIDs = @(
            'S-1-5-18',       # SYSTEM
            'S-1-5-32-544'    # BUILTIN\Administrators
        )
        ExpectedRIDSuffixes = @(
            '-500',   # Built-in Administrator
            '-512',   # Domain Admins
            '-519'    # Enterprise Admins
        )
        AttentionBroadGroups = @()
    }

    # ===== Computer Container ACL Scope =====
    # Who SHOULD have CreateChild on CN=Computers?
    'ComputerContainerACL' = @{
        Description = "Identities expected to create computer accounts in CN=Computers"
        ExpectedSIDs = @(
            'S-1-5-18',       # SYSTEM
            'S-1-5-32-544',   # BUILTIN\Administrators
            'S-1-5-32-548',   # Account Operators (by design)
            'S-1-5-32-550'    # Print Operators (legacy, by design)
        )
        ExpectedRIDSuffixes = @(
            '-500',   # Built-in Administrator
            '-512',   # Domain Admins
            '-519'    # Enterprise Admins
        )
        AttentionBroadGroups = @()
    }

    # ===== MachineAccountQuota Scope =====
    # Who SHOULD be able to create computer accounts via ms-DS-MachineAccountQuota?
    'MachineAccountQuota' = @{
        Description = "Identities that can create computer accounts via MAQ"
        ExpectedSIDs = @(
            'S-1-5-18',       # SYSTEM
            'S-1-5-32-544'    # BUILTIN\Administrators
        )
        ExpectedRIDSuffixes = @(
            '-500',   # Built-in Administrator
            '-512',   # Domain Admins
            '-519'    # Enterprise Admins
        )
        # Authenticated Users having MAQ > 0 is a default setting
        # It's "expected" but should be flagged as "Attention"
        AttentionBroadGroups = @(
            'S-1-5-11'    # Authenticated Users
        )
    }

    # ===== User Object ACL Scope =====
    # Who SHOULD have write access to user objects?
    'UserObjectACL' = @{
        Description = "Identities expected to manage user objects"
        ExpectedSIDs = @(
            'S-1-5-18',       # SYSTEM
            'S-1-5-32-544',   # BUILTIN\Administrators
            'S-1-5-32-548'    # Account Operators (by design)
        )
        ExpectedRIDSuffixes = @(
            '-500',   # Built-in Administrator
            '-512',   # Domain Admins
            '-519'    # Enterprise Admins
        )
        AttentionBroadGroups = @()
    }

    # ===== GPO Scope =====
    # Who SHOULD be able to create/edit GPOs?
    'GPO' = @{
        Description = "Identities expected to manage Group Policy Objects"
        ExpectedSIDs = @(
            'S-1-5-18',       # SYSTEM
            'S-1-5-32-544'    # BUILTIN\Administrators
        )
        ExpectedRIDSuffixes = @(
            '-500',   # Built-in Administrator
            '-512',   # Domain Admins
            '-519',   # Enterprise Admins
            '-520'    # Group Policy Creator Owners
        )
        AttentionBroadGroups = @()
    }

    # ===== ADCS (Certificate Services) Scope =====
    # Who SHOULD have Enroll rights on certificate templates?
    'ADCSEnroll' = @{
        Description = "Identities expected to enroll certificates"
        ExpectedSIDs = @(
            'S-1-5-18',       # SYSTEM
            'S-1-5-32-544'    # BUILTIN\Administrators
        )
        ExpectedRIDSuffixes = @(
            '-500',   # Built-in Administrator
            '-512',   # Domain Admins
            '-519',   # Enterprise Admins
            '-516'    # Domain Controllers (for DC certificates)
        )
        # Domain Users/Computers having Enroll is often by design
        # but can be a vulnerability (ESC1, ESC2, etc.)
        AttentionBroadGroups = @(
            'S-1-5-11'    # Authenticated Users
        )
    }

    # ===== Kerberos Delegation Scope =====
    # Who SHOULD have unconstrained/constrained delegation configured?
    'KerberosDelegation' = @{
        Description = "Identities expected to have Kerberos delegation"
        ExpectedSIDs = @()
        ExpectedRIDSuffixes = @(
            '-516'    # Domain Controllers (often have delegation)
        )
        AttentionBroadGroups = @()
    }

    # ===== LAPS Read Scope =====
    # Who SHOULD be able to read LAPS passwords?
    'LAPSRead' = @{
        Description = "Identities expected to read LAPS passwords"
        ExpectedSIDs = @(
            'S-1-5-18',       # SYSTEM
            'S-1-5-32-544'    # BUILTIN\Administrators
        )
        ExpectedRIDSuffixes = @(
            '-500',   # Built-in Administrator
            '-512',   # Domain Admins
            '-519'    # Enterprise Admins
        )
        AttentionBroadGroups = @()
    }

    # ===== PKI Container Scope (ESC5) =====
    # Who SHOULD have write access to PKI containers in Configuration partition?
    'PKIContainer' = @{
        Description = "Identities expected to manage PKI containers"
        ExpectedSIDs = @(
            'S-1-5-18',       # SYSTEM
            'S-1-5-32-544'    # BUILTIN\Administrators
        )
        ExpectedRIDSuffixes = @(
            '-500',   # Built-in Administrator
            '-512',   # Domain Admins
            '-519',   # Enterprise Admins
            '-517'    # Cert Publishers (by design)
        )
        AttentionBroadGroups = @()
    }
}

<#
.SYNOPSIS
    Gets all privileged group SIDs for a specific domain.
.DESCRIPTION
    Combines static privileged SIDs with domain-relative SIDs constructed
    from the provided domain SID. Used for group membership checks.
.PARAMETER DomainSID
    The domain SID (e.g., "S-1-5-21-xxx-xxx-xxx").
.PARAMETER IncludeOperators
    Include operator groups in the result.
.PARAMETER StrictDCSync
    Use stricter DCSync-specific subset.
.OUTPUTS
    String[] - Array of complete SID strings.
#>
function Get-PrivilegedGroupSIDs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainSID,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeOperators,

        [Parameter(Mandatory=$false)]
        [switch]$StrictDCSync
    )

    $result = @()

    if ($StrictDCSync) {
        # DCSync-specific: only BUILTIN\Administrators from static
        $result += 'S-1-5-32-544'

        # Add domain-relative DCSync privileged groups
        foreach ($suffix in $Script:DCSyncPrivilegedRIDSuffixes) {
            $result += "$DomainSID$suffix"
        }
    }
    else {
        # Standard: BUILTIN\Administrators
        $result += 'S-1-5-32-544'

        # Add domain-relative privileged groups
        foreach ($suffix in $Script:PrivilegedRIDSuffixes) {
            $result += "$DomainSID$suffix"
        }

        # Add operator groups if requested
        if ($IncludeOperators) {
            $result += $Script:OperatorSIDs
        }
    }

    return $result
}

<#
.SYNOPSIS
    Gets all Tier-0 group SIDs for a specific domain.
.DESCRIPTION
    Returns the SIDs of true Tier-0 groups (Domain Admins, Enterprise Admins, Schema Admins, Administrators).
    Used by Get-ProtectedUsersStatus to identify accounts that SHOULD be protected.
.PARAMETER DomainSID
    The domain SID (e.g., "S-1-5-21-xxx-xxx-xxx").
.OUTPUTS
    String[] - Array of complete SID strings for Tier-0 groups.
#>
function Get-Tier0GroupSIDs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainSID
    )

    $result = @()

    # Add static Tier-0 SID (BUILTIN\Administrators)
    $result += $Script:Tier0StaticSIDs

    # Add domain-relative Tier-0 groups
    foreach ($suffix in $Script:Tier0RIDSuffixes) {
        $result += "$DomainSID$suffix"
    }

    return $result
}

<#
.SYNOPSIS
    Tests if an account is excluded from Protected Users applicability.
.DESCRIPTION
    Checks if the account is one that CANNOT use Protected Users:
    - krbtgt: Service account
    - DC$ computer accounts: Computer accounts
    - gMSA accounts: Group Managed Service Accounts
.PARAMETER Account
    AD object with objectSid and objectClass properties.
.OUTPUTS
    [PSCustomObject] with:
    - IsExcluded: $true if account cannot use Protected Users
    - Reason: Why account is excluded (or $null)
#>
function Test-IsExcludedFromProtectedUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Account
    )

    $result = [PSCustomObject]@{
        IsExcluded = $false
        Reason = $null
    }

    # Check objectClass for computer accounts and gMSAs
    $objectClass = $Account.objectClass
    if ($objectClass) {
        if ($objectClass -contains 'computer') {
            $result.IsExcluded = $true
            $result.Reason = "Computer account (Protected Users only for users)"
            return $result
        }
        if ($objectClass -contains 'msDS-GroupManagedServiceAccount') {
            $result.IsExcluded = $true
            $result.Reason = "gMSA account (cannot use Protected Users)"
        }
    }

    # Check for krbtgt by sAMAccountName
    if ($Account.sAMAccountName -eq 'krbtgt') {
        $result.IsExcluded = $true
        $result.Reason = "krbtgt service account (cannot authenticate interactively)"
        return $result
    }

    # Check by SID suffix for DC accounts
    $sid = $Account.objectSid
    if ($sid) {
        foreach ($suffix in $Script:Tier0ExcludedFromProtectionRIDs) {
            if ($sid -like "*$suffix") {
                $result.IsExcluded = $true
                $result.Reason = "System account (RID $suffix - cannot use Protected Users)"
                return $result
            }
        }
    }

    return $result
}

