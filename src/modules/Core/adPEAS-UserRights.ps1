<#
.SYNOPSIS
    The user rights adPEAS evaluates, and who holds each of them by default.

.DESCRIPTION
    Get-GPOUserRightsAssignment used to decide by the identity of the holder: a right
    granted to a privileged SID, an operator group or a well-known service identity was
    hidden, everything else reported. That is the wrong question asked of the wrong half
    of the data, and it fails in both directions.

    It hides real findings. Backup Operators holding SeDebugPrivilege is not a Windows
    default and is a clean path to SYSTEM on every machine in scope - and it was silently
    suppressed, because the group is on the privileged list.

    It reports expected ones. Which principals hold a right by default depends on the
    right, not on how privileged the principal looks, and no identity list can express
    that.

    The question that actually matters is whether an assignment departs from what Windows
    ships, and this table is what makes that question answerable.

    WHY THE COMPARISON IS EXACT

    The [Privilege Rights] section of GptTmpl.inf is absolute, not additive: the principals
    listed for a right become the complete set of holders on every machine the GPO reaches.
    So the GPO's list and the default list are two sets describing the same thing, and the
    difference between them is meaningful in both directions:

      added   - holders beyond the default. The escalation risk, and the finding.
      removed - default holders the GPO drops. Usually deliberate hardening, occasionally
                an operational foot-gun; reported as a note, never as a finding.

    MEMBER AND DOMAIN CONTROLLER DEFAULTS DIFFER

    Server Operators hold rights on a domain controller that nobody holds on a member
    server, so each right carries both sets. The caller passes the scopes the GPO actually
    reaches and the union of those baselines is what counts as expected - a holder that is
    default somewhere the policy applies is not a deviation worth anyone's attention.

    WHERE THE DEFAULTS COME FROM, AND WHAT TO DO WHEN THEY ARE WRONG

    Every entry below is the documented Windows default. A wrong entry produces a false
    positive (a default reported) or a false negative (a deviation hidden), so a right
    whose default set is not established here carries $null rather than a guess. A $null
    baseline is not treated as "nobody holds this by default" - the check falls back to the
    identity filter for that right and says so in the finding, which keeps the uncertainty
    visible instead of silently deciding.

.NOTES
    Author: Alexander Sturz (@_61106960_)
    Reference: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment
#>

# Well-known SIDs used below. Written out rather than referenced by name, because this
# table has to be readable next to the Windows documentation it mirrors.
#   S-1-1-0        Everyone                     S-1-5-32-544  Administrators
#   S-1-5-6        SERVICE                      S-1-5-32-545  Users
#   S-1-5-11       Authenticated Users          S-1-5-32-546  Guests
#   S-1-5-18       SYSTEM                       S-1-5-32-548  Account Operators
#   S-1-5-19       LOCAL SERVICE                S-1-5-32-549  Server Operators
#   S-1-5-20       NETWORK SERVICE              S-1-5-32-550  Print Operators
#   S-1-5-32-551   Backup Operators             S-1-5-32-555  Remote Desktop Users
#   S-1-5-32-559   Performance Log Users        S-1-5-32-568  IIS_IUSRS
#   S-1-5-90-0     Window Manager\Window Manager Group
#   S-1-5-80-0     NT SERVICE\ALL SERVICES

$Script:UserRightsBaseline = [ordered]@{

    # =========================================================================
    # Tier 1 - a direct route to SYSTEM, to credentials, or to the domain
    # =========================================================================

    'SeDebugPrivilege' = @{
        Name = 'Debug programs'
        Tier = 'Finding'
        Why  = 'Opens any process, including LSASS. A holder reads credentials out of memory on every machine in scope.'
        # Administrators only, on a member and on a domain controller alike.
        Member = @('S-1-5-32-544')
        DC     = @('S-1-5-32-544')
    }

    'SeTcbPrivilege' = @{
        Name = 'Act as part of the operating system'
        Tier = 'Finding'
        Why  = 'The holder can create a token for any identity. It is the operating system trust boundary itself.'
        # Nobody by default. Windows grants this to no principal out of the box.
        Member = @()
        DC     = @()
    }

    'SeCreateTokenPrivilege' = @{
        Name = 'Create a token object'
        Tier = 'Finding'
        Why  = 'Forges an access token directly, with any group membership the holder chooses.'
        Member = @()
        DC     = @()
    }

    'SeImpersonatePrivilege' = @{
        Name = 'Impersonate a client after authentication'
        Tier = 'Finding'
        Why  = 'The precondition of the Potato family of local privilege escalations.'
        # Administrators and the three service identities.
        Member = @('S-1-5-32-544', 'S-1-5-6', 'S-1-5-19', 'S-1-5-20')
        DC     = @('S-1-5-32-544', 'S-1-5-6', 'S-1-5-19', 'S-1-5-20')
    }

    'SeAssignPrimaryTokenPrivilege' = @{
        Name = 'Replace a process level token'
        Tier = 'Finding'
        Why  = 'Starts a process under another identity, which is the second half of a token abuse chain.'
        Member = @('S-1-5-19', 'S-1-5-20')
        DC     = @('S-1-5-19', 'S-1-5-20')
    }

    'SeLoadDriverPrivilege' = @{
        Name = 'Load and unload device drivers'
        Tier = 'Finding'
        Why  = 'Code in the kernel. A signed vulnerable driver turns this into complete control of the machine.'
        Member = @('S-1-5-32-544')
        # Print Operators hold it on a domain controller, for printer drivers.
        DC     = @('S-1-5-32-544', 'S-1-5-32-550')
    }

    'SeBackupPrivilege' = @{
        Name = 'Back up files and directories'
        Tier = 'Finding'
        Why  = 'Reads every file regardless of its ACL - on a domain controller, that includes the NTDS database.'
        Member = @('S-1-5-32-544', 'S-1-5-32-551')
        DC     = @('S-1-5-32-544', 'S-1-5-32-551', 'S-1-5-32-549')
    }

    'SeRestorePrivilege' = @{
        Name = 'Restore files and directories'
        Tier = 'Finding'
        Why  = 'Writes every file regardless of its ACL, and can set owner. The write half of SeBackupPrivilege.'
        Member = @('S-1-5-32-544', 'S-1-5-32-551')
        DC     = @('S-1-5-32-544', 'S-1-5-32-551', 'S-1-5-32-549')
    }

    'SeTakeOwnershipPrivilege' = @{
        Name = 'Take ownership of files or other objects'
        Tier = 'Finding'
        Why  = 'Ownership carries WriteDacl, so the holder grants itself whatever access it wants afterwards.'
        Member = @('S-1-5-32-544')
        DC     = @('S-1-5-32-544')
    }

    'SeEnableDelegationPrivilege' = @{
        Name = 'Enable computer and user accounts to be trusted for delegation'
        Tier = 'Finding'
        Why  = 'Configures Kerberos delegation, which is impersonation of any user against the delegated service.'
        # Nobody on a member; Administrators on a domain controller, where it means anything.
        Member = @()
        DC     = @('S-1-5-32-544')
    }

    'SeSyncAgentPrivilege' = @{
        Name = 'Synchronize directory service data'
        Tier = 'Finding'
        Why  = 'Reads every object and attribute in the directory, password hashes included.'
        Member = @()
        DC     = @()
    }

    'SeManageVolumePrivilege' = @{
        Name = 'Perform volume maintenance tasks'
        Tier = 'Finding'
        Why  = 'Raw volume access bypasses the file system and its ACLs entirely.'
        Member = @('S-1-5-32-544')
        DC     = @('S-1-5-32-544')
    }

    'SeSecurityPrivilege' = @{
        Name = 'Manage auditing and security log'
        Tier = 'Finding'
        Why  = 'Clears the security log, which is how an intrusion stops being reconstructable.'
        Member = @('S-1-5-32-544')
        DC     = @('S-1-5-32-544')
    }

    'SeRelabelPrivilege' = @{
        Name = 'Modify an object label'
        Tier = 'Finding'
        Why  = 'Changes the integrity level of an object, defeating the protection a low-integrity sandbox provides.'
        Member = @()
        DC     = @()
    }

    'SeTrustedCredManAccessPrivilege' = @{
        Name = 'Access Credential Manager as a trusted caller'
        Tier = 'Finding'
        Why  = 'Reads the saved credentials of every user of the machine in cleartext.'
        Member = @()
        DC     = @()
    }

    # =========================================================================
    # Tier 2 - a foothold or a way across, rather than straight up
    # =========================================================================

    'SeRemoteInteractiveLogonRight' = @{
        Name = 'Allow log on through Remote Desktop Services'
        Tier = 'Hint'
        Why  = 'An interactive session on the machine, and with it whatever the account can reach from there.'
        Member = @('S-1-5-32-544', 'S-1-5-32-555')
        # A domain controller does not carry Remote Desktop Users in its default policy.
        DC     = @('S-1-5-32-544')
    }

    'SeInteractiveLogonRight' = @{
        Name = 'Allow log on locally'
        Tier = 'Hint'
        Why  = 'A console session. On a domain controller it is the difference between a member and an admin of the domain.'
        Member = @('S-1-5-32-544', 'S-1-5-32-545', 'S-1-5-32-551', 'S-1-5-32-546')
        DC     = @('S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-551', 'S-1-5-32-550', 'S-1-5-32-549')
    }

    'SeBatchLogonRight' = @{
        Name = 'Log on as a batch job'
        Tier = 'Hint'
        Why  = 'Runs a scheduled task as the account, which is code execution without an interactive session.'
        Member = @('S-1-5-32-544', 'S-1-5-32-551', 'S-1-5-32-559')
        DC     = @('S-1-5-32-544', 'S-1-5-32-551', 'S-1-5-32-559')
    }

    'SeServiceLogonRight' = @{
        Name = 'Log on as a service'
        Tier = 'Hint'
        Why  = 'Runs a service as the account. A service starts without anyone logging on.'
        # Deliberately no baseline. What holds this varies with every product installed on
        # the machine - SQL, Exchange and IIS each add their own service accounts - so any
        # list here would be wrong on most domains in one direction or the other. The
        # check falls back to the identity filter for this right and says so.
        Member = $null
        DC     = $null
    }

    'SeSystemtimePrivilege' = @{
        Name = 'Change the system time'
        Tier = 'Hint'
        Why  = 'Kerberos rejects a ticket outside its clock skew, so the clock is an authentication dependency.'
        Member = @('S-1-5-32-544', 'S-1-5-19')
        DC     = @('S-1-5-32-544', 'S-1-5-19', 'S-1-5-32-549')
    }

    'SeRemoteShutdownPrivilege' = @{
        Name = 'Force shutdown from a remote system'
        Tier = 'Hint'
        Why  = 'Denial of service against the machine, remotely and without touching it.'
        Member = @('S-1-5-32-544')
        DC     = @('S-1-5-32-544', 'S-1-5-32-549')
    }

    'SeShutdownPrivilege' = @{
        Name = 'Shut down the system'
        Tier = 'Hint'
        Why  = 'Denial of service, and on a domain controller a way to force authentication elsewhere.'
        Member = @('S-1-5-32-544', 'S-1-5-32-545', 'S-1-5-32-551')
        DC     = @('S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-551', 'S-1-5-32-550', 'S-1-5-32-549')
    }
}

# SeMachineAccountPrivilege is deliberately absent: Get-AddComputerRights covers it
# together with ms-DS-MachineAccountQuota, which is the other half of that story.
# The Se*Deny* rights are absent as well - they take access away.

<#
.SYNOPSIS
    Compares the holders a GPO assigns to a right against the Windows default.

.DESCRIPTION
    Returns what the GPO adds beyond the default and what it removes from it, or nothing
    when the right is not one adPEAS evaluates. The [Privilege Rights] section is absolute,
    so both directions are real statements about the machines in scope.

.PARAMETER Right
    The constant, for instance SeDebugPrivilege.

.PARAMETER HolderSID
    The SIDs the GPO assigns the right to.

.PARAMETER Scope
    Which default sets apply: Member, DC, or both when the GPO reaches both kinds of
    machine. A holder that is default in any scope the policy reaches is not a deviation.

.OUTPUTS
    Hashtable with Added, Removed, HasBaseline, Tier, Name and Why - or $null for a right
    outside the table.
#>
function Compare-UserRightAssignment {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Right,

        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [string[]]$HolderSID,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Member', 'DC')]
        [string[]]$Scope = @('Member')
    )

    $entry = $Script:UserRightsBaseline[$Right]
    if (-not $entry) { return $null }

    # The union of the baselines for every scope the GPO reaches. A holder that is default
    # on a domain controller is not a deviation in a policy that also reaches one.
    $baseline = @()
    $hasBaseline = $false
    foreach ($s in @($Scope)) {
        if ($null -ne $entry[$s]) {
            $hasBaseline = $true
            $baseline += @($entry[$s])
        }
    }

    $holders = @($HolderSID | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    if (-not $hasBaseline) {
        # No documented default for this right. Everything is reported as added and the
        # caller is told the comparison did not happen, so it can fall back rather than
        # present a guess as a deviation.
        return @{
            Added       = $holders
            Removed     = @()
            HasBaseline = $false
            Tier        = $entry.Tier
            Name        = $entry.Name
            Why         = $entry.Why
        }
    }

    # Compare-Object is avoided on purpose: it unrolls a single-element side and returns
    # nothing for two empty ones, both of which have bitten this codebase before.
    $added = @($holders | Where-Object { $baseline -notcontains $_ })
    $removed = @($baseline | Where-Object { $holders -notcontains $_ })

    return @{
        Added       = $added
        Removed     = $removed
        HasBaseline = $true
        Tier        = $entry.Tier
        Name        = $entry.Name
        Why         = $entry.Why
    }
}
