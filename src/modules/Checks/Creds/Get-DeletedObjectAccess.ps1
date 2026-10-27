function Get-DeletedObjectAccess {
    <#
    .SYNOPSIS
    Tests which deleted objects the current user can read, and who else may list them.

    .DESCRIPTION
    A deleted object is moved to the Deleted Objects container of its naming context. With
    the AD Recycle Bin enabled it keeps every attribute there for the deleted object
    lifetime - description and info included; without it, the tombstone keeps only the few
    attributes the schema marks to be preserved. The container is invisible to a search
    that does not send the show-deleted control, and its default ACL grants List Contents
    and Read Property to SYSTEM and Administrators only, so a domain user sees nothing of it
    (measured: the container's DN, no attribute, no child).

    Two answers:

    1. Which deleted objects the account running the scan can read, and whether one of them
       holds a credential in a free-text attribute (Get-CredentialTextMatch, the patterns of
       Get-PasswordInDescription) or a value in a Unix password attribute. Such a value
       outlives the account it was written for, and no check that reads live objects sees
       it. An account outside Administrators that can read them at all holds a delegation on
       the container.
    2. Who may list the container: the principals the ACL of CN=Deleted Objects grants List
       Contents, and its owner, outside Tier 0. Only an administrator can read that ACL by
       default, so a scan run as an ordinary user says so instead.

    Restoring a deleted object is a different right - Reanimate-Tombstones on the naming
    context head, with write access to the object - and is reported by Get-DangerousACLs for
    the domain and by Get-CriticalObjectACLs for the configuration partition. Whether the
    Recycle Bin is enabled, and for how long deleted objects are kept, is reported by
    Get-DomainInformation.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .PARAMETER IncludePrivileged
    Also list the Tier-0 principals and the Exchange service groups that may list deleted
    objects. Administrators do by default, and Exchange setup grants it to Exchange Servers
    and Exchange Trusted Subsystem, so they are hidden unless asked for.

    .EXAMPLE
    Get-DeletedObjectAccess

    .EXAMPLE
    Get-DeletedObjectAccess -IncludePrivileged

    .EXAMPLE
    Get-DeletedObjectAccess -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Creds
    Author: Alexander Sturz (@_61106960_)
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
        [switch]$IncludePrivileged
    )

    begin {
        Write-Log "[Get-DeletedObjectAccess] Starting check"
    }

    process {
        try {
            # Connection parameters only, never @PSBoundParameters: -IncludePrivileged would
            # be splatted into Ensure-LDAPConnection and Get-DomainObject, which have no
            # parameter of that name.
            $connectionParams = @{}
            if ($Domain)     { $connectionParams['Domain']     = $Domain }
            if ($Server)     { $connectionParams['Server']     = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            Show-SubHeader "Testing which deleted objects the current user can read..." -ObjectType "DeletedObject"

            $domainDN = [string]$Script:LDAPContext.DomainDN

            # ===== Step 1: the container =====
            # By its well-known GUID (GUID_DELETED_OBJECTS_CONTAINER_W, MS-ADTS 6.1.1.4) rather
            # than by name, and with the show-deleted control: the container is itself a
            # deleted object, and without the control a base search on it answers
            # noSuchObject. Its security descriptor comes back only to an account that may
            # read it - by default an administrator.
            $containerDN = "CN=Deleted Objects,$domainDN"
            $containerSD = $null
            try {
                $container = @(Get-DomainObject -SearchBase "<WKGUID=18e2ea80684f11d2b9aa00c04f79f805,$domainDN>" -Scope Base -LDAPFilter '(objectClass=*)' -Properties 'distinguishedName', 'nTSecurityDescriptor' -Raw -IncludeDeleted @connectionParams)[0]
                if ($container) {
                    if ($container.distinguishedName) { $containerDN = [string]$container.distinguishedName }
                    $containerSD = $container.nTSecurityDescriptor
                }
            } catch {
                Write-Log "[Get-DeletedObjectAccess] The deleted objects container could not be read: $_"
            }

            # ===== Step 2: what this account can read =====
            # All properties: the objects with a credential are shown in full. The search is
            # one level deep because deletion moves every object directly into the
            # container. Measured: with the Recycle Bin enabled, a recycled object - past its
            # deleted object lifetime, or a tombstone left from before the Recycle Bin was
            # enabled - is not returned with this control; without the Recycle Bin, the
            # tombstones are, with the few attributes they keep. Neither carries the
            # attributes looked at here.
            $deletedObjects = @(Get-DomainObject -SearchBase $containerDN -Scope OneLevel -LDAPFilter '(objectClass=*)' -IncludeDeleted @connectionParams)
            Write-Log "[Get-DeletedObjectAccess] $($deletedObjects.Count) deleted object(s) visible"

            # Administrators holds List Contents and Read Property on the container by
            # default (measured); any other account that sees deleted objects holds a
            # delegation. The session token says which, without an ACL this account may not
            # be allowed to read. Get-CurrentUserTokenGroups hands its list back as one
            # object, so @() around it makes a one-element array that contains no SID.
            $readsAsAdministrator = Test-SIDInTokenGroups -SID 'S-1-5-32-544'

            if ($deletedObjects.Count -eq 0) {
                if ($readsAsAdministrator) {
                    Show-Line "No deleted object exists in the domain" -Class Note
                } else {
                    Show-Line "No deleted object is visible to this account - it may not list them, or there is none" -Class Note
                }
            } else {
                if ($readsAsAdministrator) {
                    Show-Line "This account can read $($deletedObjects.Count) deleted object(s) - as a member of Administrators" -Class Note
                } else {
                    Show-Line "This account can read $($deletedObjects.Count) deleted object(s) through a delegation on the deleted objects container" -Class Hint -FindingId 'DELETED_OBJECTS_READ_DELEGATED'
                }

                $freeTextAttributes = @($Script:CredentialTextBaseAttributes) + @($Script:CredentialTextExchangeAttributes) + @($Script:CredentialTextCloudAttributes)
                # The attributes Get-UnixPasswordAccounts reads on live objects.
                $passwordAttributes = @('unixUserPassword', 'userPassword', 'msSFU30Password', 'sambaNTPassword', 'sambaLMPassword')

                $reported = 0
                foreach ($deletedObject in $deletedObjects) {
                    $objectDN = [string]$deletedObject.distinguishedName

                    $attributesToCheck = @()
                    foreach ($name in $freeTextAttributes) {
                        # Joined rather than cast: description is multi-valued in the schema.
                        $value = (@($deletedObject.$name) | Where-Object { $_ }) -join ' '
                        if (-not [string]::IsNullOrWhiteSpace($value)) {
                            $attributesToCheck += @{ Name = $name; Value = $value }
                        }
                    }
                    $credentialMatch = Get-CredentialTextMatch -Attributes $attributesToCheck -Label $objectDN
                    $passwordAttribute = @($passwordAttributes | Where-Object { $null -ne $deletedObject.$_ -and [string]$deletedObject.$_ -ne '' })[0]

                    if ($credentialMatch.Tier -eq 0 -and -not $passwordAttribute) { continue }

                    $display = ConvertTo-DeletedObjectDisplay -DeletedObject $deletedObject
                    if ($passwordAttribute) {
                        Show-Line "Password attribute $passwordAttribute set on deleted $($display.Kind) '$($display.Name)'" -Class Finding
                        $class = 'Finding'
                    } elseif ($credentialMatch.Tier -eq 1) {
                        Show-Line "Probable credential found in $($credentialMatch.Attribute) of deleted $($display.Kind) '$($display.Name)'" -Class Finding
                        $class = 'Finding'
                    } else {
                        Show-Line "Possible credential mention in $($credentialMatch.Attribute) of deleted $($display.Kind) '$($display.Name)'" -Class Hint
                        $class = 'Hint'
                    }
                    $display.Object | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'DeletedObject' -Force
                    Show-Object $display.Object -Class $class
                    $reported++
                }

                if ($reported -eq 0) {
                    Show-Line "None of the $($deletedObjects.Count) deleted object(s) holds a credential in a free-text or password attribute" -Class Secure
                }
            }

            # ===== Step 3: who else may list them =====
            # Its own try: a failure here must not read as a clean ACL, and must not take
            # the answer above with it.
            try {
                Show-DeletedObjectsReaders -ContainerDN $containerDN -SecurityDescriptor $containerSD -IncludePrivileged:$IncludePrivileged -ConnectionParams $connectionParams
            } catch {
                Write-Log "[Get-DeletedObjectAccess] ACL analysis failed: $_" -Level Error
                Show-Line "Error during the ACL analysis - who may list deleted objects could not be evaluated: $_" -Class Finding
            }

        } catch {
            Write-Log "[Get-DeletedObjectAccess] Error: $_" -Level Error
            Show-Line "Error during check - deleted object access could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-DeletedObjectAccess] Check completed"
    }
}

<#
.SYNOPSIS
    Prepares a deleted object for display and names it for the line above it.

.DESCRIPTION
    A deleted object's name and cn carry a line feed, "DEL:" and the object GUID after the
    name it had (MS-ADTS 3.1.1.5.5.1.2) - printed as they are, they break the row in two.
    Both are cut back to the name before the line feed. The object is named by
    sAMAccountName, else by msDS-LastKnownRDN, else by that name, and its kind by the most
    specific objectClass.

.PARAMETER DeletedObject
    The object as Get-DomainObject returned it.

.OUTPUTS
    PSCustomObject with Object (the same object, name and cn cleaned), Name and Kind.
#>
function ConvertTo-DeletedObjectDisplay {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $DeletedObject
    )

    foreach ($attribute in @('name', 'cn')) {
        $value = [string]$DeletedObject.$attribute
        if ($value -match "`n") {
            $DeletedObject | Add-Member -NotePropertyName $attribute -NotePropertyValue (($value -split "`n")[0]) -Force
        }
    }

    $shownName = if ($DeletedObject.sAMAccountName) { [string]$DeletedObject.sAMAccountName }
                 elseif ($DeletedObject.'msDS-LastKnownRDN') { [string]$DeletedObject.'msDS-LastKnownRDN' }
                 elseif ($DeletedObject.name) { [string]$DeletedObject.name }
                 else { [string]$DeletedObject.distinguishedName }

    # objectClass lists the inheritance chain, most specific class last.
    $mostSpecific = [string](@($DeletedObject.objectClass) | Select-Object -Last 1)
    $kindLabels = @{
        'user'                                = 'user'
        'computer'                            = 'computer'
        'group'                               = 'group'
        'contact'                             = 'contact'
        'organizationalUnit'                  = 'OU'
        'groupPolicyContainer'                = 'GPO'
        'msDS-GroupManagedServiceAccount'     = 'gMSA'
        'msDS-ManagedServiceAccount'          = 'MSA'
        'msDS-DelegatedManagedServiceAccount' = 'dMSA'
    }
    $kind = if ($kindLabels.ContainsKey($mostSpecific)) { $kindLabels[$mostSpecific] } elseif ($mostSpecific) { $mostSpecific } else { 'object' }

    return [PSCustomObject]@{
        Object = $DeletedObject
        Name   = $shownName
        Kind   = $kind
    }
}

<#
.SYNOPSIS
    Reports the principals outside Tier 0 that may list the Deleted Objects container.

.DESCRIPTION
    Step 3 of Get-DeletedObjectAccess. Listing the container is the gate: a deleted object
    keeps the security descriptor it had (Microsoft, Restoring Deleted Objects), so whoever
    may list the container reads of each object what its own ACL allows - for most objects,
    what any authenticated user could read while it was alive. Read Property on the
    container itself is not needed for that, and is not asked for.

    Counted: an ACE that applies to the container and grants List Contents, generic read or
    full control, and the owner, who holds WRITE_DAC implicitly and may grant itself the
    rest. Tier 0 holds it by default, and Exchange setup grants it to Exchange Servers and
    Exchange Trusted Subsystem; both are listed only with -IncludePrivileged.

.PARAMETER ContainerDN
    The DN of the container, for the log and Get-ObjectACL.

.PARAMETER SecurityDescriptor
    The raw security descriptor of the container, $null when it could not be read.

.PARAMETER IncludePrivileged
    Also list Tier-0 principals and the Exchange service groups.

.PARAMETER ConnectionParams
    Domain/Server/Credential hashtable, passed through unchanged.
#>
function Show-DeletedObjectsReaders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ContainerDN,

        [Parameter(Mandatory = $false)]
        $SecurityDescriptor,

        [Parameter(Mandatory = $false)]
        [switch]$IncludePrivileged,

        [Parameter(Mandatory = $false)]
        [hashtable]$ConnectionParams = @{}
    )

    Show-SubHeader "Analyzing who may list deleted objects..." -ObjectType "DeletedObjectsReader"

    if (-not $SecurityDescriptor) {
        Show-Line "The ACL of the deleted objects container is readable by administrators only - other readers not checked" -Class Note
        return
    }

    $aclResult = Get-ObjectACL -DistinguishedName $ContainerDN -SecurityDescriptor $SecurityDescriptor -AllowOnly @ConnectionParams
    if (-not $aclResult) {
        Show-Line "The ACL of the deleted objects container could not be parsed - who may list deleted objects was not checked" -Class Note
        return
    }

    # Rights per trustee, so a trustee with several ACEs is one row.
    $rightsBySID = [ordered]@{}
    $nameBySID = @{}
    if ($aclResult.OwnerSID) {
        $rightsBySID[[string]$aclResult.OwnerSID] = @('Owner')
        $nameBySID[[string]$aclResult.OwnerSID] = $(if ($aclResult.Owner) { [string]$aclResult.Owner } else { [string]$aclResult.OwnerSID })
    }
    foreach ($ace in @($aclResult.ACEs)) {
        # Only what applies to the container itself: not inherit-only.
        if (-not (Test-ACEAppliesToSelf -ACE $ace)) { continue }

        $rights = @($ace.RightsRaw)
        $granted = @()
        if ($rights -contains 'GenericAll') {
            $granted += 'Full control'
        } elseif ($rights -contains 'GenericRead' -or $rights -contains 'ListChildren') {
            $granted += 'List contents'
            if ($rights -contains 'GenericRead' -or $rights -contains 'ReadProperty') { $granted += 'Read properties' }
        }
        if ($granted.Count -eq 0) { continue }

        $sid = [string]$ace.TrusteeSID
        if (-not $rightsBySID.Contains($sid)) {
            $rightsBySID[$sid] = @()
            $nameBySID[$sid] = $(if ($ace.Trustee) { [string]$ace.Trustee } else { $sid })
        }
        $rightsBySID[$sid] = @($rightsBySID[$sid]) + $granted
    }

    $readers = @()
    $exchangeReads = $false
    foreach ($sid in @($rightsBySID.Keys)) {
        $rightsText = @($rightsBySID[$sid] | Select-Object -Unique) -join ', '

        $expectedAs = $null
        if ((Test-IsPrivileged -Identity $sid).Category -eq 'Privileged') {
            $expectedAs = 'Tier 0'
        } elseif ((Test-IsExchangeServiceGroup -Identity $sid).IsExchangeService) {
            $expectedAs = 'set by Exchange setup'
            $exchangeReads = $true
        }

        if ($expectedAs) {
            if (-not $IncludePrivileged) {
                Write-Log "[Get-DeletedObjectAccess] Expected reader hidden: $($nameBySID[$sid]) ($sid) - $rightsText - $expectedAs"
                continue
            }
            $rightsText = "$rightsText - $expectedAs"
        } elseif (Test-IsBroadTrustee -SID $sid) {
            $rightsText = "$rightsText - granted to a broad group so every member holds it"
        }

        $readers += [PSCustomObject]@{
            Trustee               = $nameBySID[$sid]
            TrusteeSID            = $sid
            deletedObjectsRights  = $rightsText
            _Expected             = [bool]$expectedAs
        }
    }

    $unexpected = @($readers | Where-Object { -not $_._Expected })
    if ($unexpected.Count -gt 0) {
        $headlineClass = if (@($unexpected | Where-Object { $_.deletedObjectsRights -match 'broad group' }).Count -gt 0) { 'Finding' } else { 'Hint' }
        Show-Line "Found $($unexpected.Count) principal(s) outside Tier 0 that may list deleted objects" -Class $headlineClass
    } else {
        Show-Line "Only Tier 0$(if ($exchangeReads) { ' and the Exchange service groups' }) may list deleted objects" -Class Secure
    }

    foreach ($reader in $readers) {
        $rowClass = if ($reader._Expected) { 'Note' } elseif ($reader.deletedObjectsRights -match 'broad group') { 'Finding' } else { 'Hint' }
        $reader.PSObject.Properties.Remove('_Expected')
        $reader | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'DeletedObjectsReader' -Force
        Show-Object $reader -Class $rowClass
    }
}
