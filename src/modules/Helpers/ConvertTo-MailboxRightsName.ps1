<#
.SYNOPSIS
    Names the access mask of an ACE in msExchMailboxSecurityDescriptor the way Exchange
    names mailbox permissions.

.DESCRIPTION
    A mailbox security descriptor reuses the bits of an Active Directory access mask with
    Exchange's own meaning. Read as directory rights, the default entry for the mailbox
    owner - NT AUTHORITY\SELF, mask 0x20001 - says "CreateChild,ReadControl", which nobody
    recognises; Get-MailboxPermission shows the same entry as "FullAccess, ReadPermission".

    The names are the members of Exchange's MailboxRights enumeration. Their values:

    | Bit     | Name             | Basis |
    |---------|------------------|-------|
    | 0x1     | FullAccess       | measured: 0x1 on a mailbox, Get-MailboxPermission "FullAccess" |
    | 0x20000 | ReadPermission   | measured: SELF 0x20001, Get-MailboxPermission "FullAccess, ReadPermission" |
    | 0x4     | ExternalAccount  | measured: SELF 0x20005 on arbitration mailboxes, "FullAccess, ExternalAccount, ReadPermission" |
    | 0x10000 | DeleteItem       | the standard right DELETE |
    | 0x40000 | ChangePermission | the standard right WRITE_DAC |
    | 0x80000 | ChangeOwner      | the standard right WRITE_OWNER |
    | 0x2     | SendAs           | declaration order of the enumeration; seen only on SYSTEM (0x20003) of an object Get-MailboxPermission does not accept |

    Measured against Exchange Server 2019. A bit outside the table is shown as hex rather
    than given a guessed name.

.PARAMETER Mask
    The access mask of the ACE.

.OUTPUTS
    [string] - the names joined with ", ", or "None" for an empty mask.

.EXAMPLE
    ConvertTo-MailboxRightsName -Mask 0x20001

    FullAccess, ReadPermission

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
function ConvertTo-MailboxRightsName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [long]$Mask
    )

    # The L suffix keeps every literal an Int64 on Windows PowerShell 5.1 as well
    $rights = [ordered]@{
        0x1L     = 'FullAccess'
        0x2L     = 'SendAs'
        0x4L     = 'ExternalAccount'
        0x10000L = 'DeleteItem'
        0x20000L = 'ReadPermission'
        0x40000L = 'ChangePermission'
        0x80000L = 'ChangeOwner'
    }

    $remaining = $Mask -band 0xFFFFFFFFL
    if ($remaining -eq 0) { return 'None' }

    $names = New-Object System.Collections.Generic.List[string]
    foreach ($bit in $rights.Keys) {
        if (($remaining -band $bit) -eq $bit) {
            $names.Add($rights[$bit])
            $remaining = $remaining -band (-bnot $bit)
        }
    }
    if ($remaining -ne 0) {
        $names.Add(('0x{0:X}' -f $remaining))
    }
    return ($names -join ', ')
}
