function Move-DomainObject {
<#
.SYNOPSIS
    Moves and/or renames ANY Active Directory object via LDAP ModifyDN.

.DESCRIPTION
    Move-DomainObject relocates an object to a different container and/or changes its RDN.
    Both are the same LDAP operation (ModifyDN, RFC 4511 section 4.9), so they are exposed
    by one function rather than two: newSuperior carries the parent, newRDN the name, and a
    single request can change either or both.

    This is NOT an attribute write. An object's OU membership is its position in the
    directory tree, expressed by its distinguishedName - there is no attribute that holds
    it, which is why Set-DomainObject cannot perform a move.

    The objectGUID and objectSID survive a move unchanged, so group memberships, the
    Kerberos principal and any ACE referencing the object keep working. What does change is
    which GPOs apply and which delegated ACLs reach it.

    Validates before writing, because the DC's own errors for a bad move point away from the
    cause: a cross-domain target returns affectsMultipleDSAs, a missing target returns
    noSuchObject that could equally mean the source, and a systemFlags block returns a bare
    unwillingToPerform.

.PARAMETER Identity
    sAMAccountName, DistinguishedName, SID, ObjectGUID, or DOMAIN\name format.
    Identifies the object to move. A value that matches more than one object is rejected
    rather than resolved to the first match.

.PARAMETER DestinationOU
    DistinguishedName of the container the object should end up in.
    Omit to keep the current parent and only rename.

.PARAMETER NewName
    New RDN value, UNESCAPED and WITHOUT the attribute prefix - pass 'Jane Smith', not
    'CN=Jane Smith'. The attribute type is carried over from the current RDN because AD does
    not permit changing it (a CN cannot become an OU). Escaping is applied by this function.
    Omit to keep the current name and only move.

.PARAMETER Domain
    Target domain (FQDN).

.PARAMETER Server
    Specific Domain Controller to target.

.PARAMETER Credential
    PSCredential object for authentication.

.PARAMETER PassThru
    Returns a result object instead of only console output.
    Useful for scripting and automation.

.EXAMPLE
    Move-DomainObject -Identity "jdoe" -DestinationOU "OU=Sales,DC=contoso,DC=com"
    Moves the user to the Sales OU, keeping the name.

.EXAMPLE
    Move-DomainObject -Identity "jdoe" -NewName "Doe, Jane"
    Renames the object in place to CN=Doe\, Jane - the comma is escaped automatically.

.EXAMPLE
    Move-DomainObject -Identity "CN=WS01,CN=Computers,DC=contoso,DC=com" -DestinationOU "OU=Tier0,DC=contoso,DC=com" -NewName "WS01-T0"
    Moves and renames in a single ModifyDN operation.

.EXAMPLE
    Move-DomainObject -Identity "OU=Old,DC=contoso,DC=com" -DestinationOU "OU=Archive,DC=contoso,DC=com"
    Moves an entire OU with its subtree.

.EXAMPLE
    $result = Move-DomainObject -Identity "jdoe" -DestinationOU "OU=Sales,DC=contoso,DC=com" -PassThru
    $result.NewDistinguishedName
    Moves the object and returns the result for programmatic use.

.OUTPUTS
    Boolean - $true if successful or already in place, $false if failed.
    With -PassThru, a PSCustomObject carrying Operation, Object, NewDistinguishedName,
    ObjectClass, Success and Message.

.NOTES
    Author: Alexander Sturz (@_61106960_)

    Requires Delete Child on the source container AND Create Child for the object's class on
    the target container - a move consumes the delete right. Cross-DOMAIN moves are a
    different operation entirely (SID history, not ModifyDN) and are out of scope.
#>
    [CmdletBinding()]
    param(
        # === Object Identity ===
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('distinguishedName', 'Name', 'sAMAccountName')]
        [string]$Identity,

        # === Move / Rename Target ===
        [Parameter(Mandatory=$false, Position=1)]
        [Alias('TargetOU', 'NewParent')]
        [string]$DestinationOU,

        [Parameter(Mandatory=$false)]
        [string]$NewName,

        # === Connection Parameters ===
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$PassThru
    )

    begin {
        Write-Log "[Move-DomainObject] Starting move/rename operation"

        # Empty values are rejected before the "at least one of" test below, because an empty
        # string is falsy in PowerShell: a passed-but-empty parameter would otherwise be
        # reported as not having been passed at all, which points at the wrong mistake.
        # An empty -NewName would also build an RDN with no value, which AD answers with a
        # generic invalidDNSyntax.
        if ($PSBoundParameters.ContainsKey('NewName') -and [string]::IsNullOrWhiteSpace($NewName)) {
            throw "[Move-DomainObject] -NewName cannot be empty or whitespace"
        }

        if ($PSBoundParameters.ContainsKey('DestinationOU') -and [string]::IsNullOrWhiteSpace($DestinationOU)) {
            throw "[Move-DomainObject] -DestinationOU cannot be empty or whitespace"
        }

        # ModifyDN needs at least one of the two halves to change. PowerShell cannot express
        # "at least one of these parameters" declaratively, so it is checked here.
        if (-not $DestinationOU -and -not $NewName) {
            throw "[Move-DomainObject] Specify -DestinationOU, -NewName, or both"
        }

        # MS-ADTS systemFlags bits that forbid the operation outright. Mostly set on naming
        # context heads and configuration objects, but this function is class-agnostic.
        $FLAG_DOMAIN_DISALLOW_MOVE = 0x04000000
        $FLAG_DOMAIN_DISALLOW_RENAME = 0x08000000
    }

    process {
        # Ensure LDAP connection at start of process block
        $ConnectionParams = @{}
        if ($Domain) { $ConnectionParams['Domain'] = $Domain }
        if ($Server) { $ConnectionParams['Server'] = $Server }
        if ($Credential) { $ConnectionParams['Credential'] = $Credential }

        # Ensure-LDAPConnection returns $false when there is no session, but THROWS when
        # explicit connection parameters cannot be resolved to a domain. Both are the same
        # outcome here.
        $Connected = $false
        try {
            $Connected = Ensure-LDAPConnection @ConnectionParams
        } catch {
            Write-Error "[Move-DomainObject] $($_.Exception.Message)"
        }

        if (-not $Connected) {
            if ($PassThru) {
                return [PSCustomObject]@{
                    Operation = "MoveObject"
                    Object = $Identity
                    Success = $false
                    Message = "No LDAP connection available"
                }
            }
            return $false
        }

        try {
            # === Resolve the source object ===
            # Get-DomainObject already covers sAMAccountName, DN, SID, GUID and DOMAIN\name
            # (including the Global Catalog path for the latter), so the identity ladder that
            # Set-DomainObject carries inline is not copied a third time.
            $Candidates = @(Get-DomainObject -Identity $Identity `
                -Properties @('distinguishedName', 'objectClass', 'systemFlags') @ConnectionParams)

            if ($Candidates.Count -eq 0) {
                $Message = "Object not found: $Identity"
                Write-Error "[Move-DomainObject] $Message"
                if ($PassThru) {
                    return [PSCustomObject]@{
                        Operation = "MoveObject"
                        Object = $Identity
                        Success = $false
                        Message = $Message
                    }
                }
                return $false
            }

            # A bare name resolves through (|(sAMAccountName=)(cn=)(name=)) with no object
            # class restriction, so it can match several objects. Moving "the first one" would
            # relocate an object the caller never named, so ambiguity is an error here rather
            # than a silent pick.
            if ($Candidates.Count -gt 1) {
                $DNList = (@($Candidates | ForEach-Object { $_.distinguishedName }) -join '; ')
                $Message = "Identity '$Identity' matches $($Candidates.Count) objects - pass a distinguishedName instead. Matches: $DNList"
                Write-Error "[Move-DomainObject] $Message"
                if ($PassThru) {
                    return [PSCustomObject]@{
                        Operation = "MoveObject"
                        Object = $Identity
                        Success = $false
                        Message = $Message
                    }
                }
                return $false
            }

            $SourceObject = $Candidates[0]
            $SourceDN = [string]$SourceObject.distinguishedName

            # objectClass is multi-valued and ordered least to most specific.
            $ObjectClass = @($SourceObject.objectClass)[-1]

            $SourceParts = Split-LDAPDN -DistinguishedName $SourceDN
            if (-not $SourceParts) {
                $Message = "Cannot parse the object's distinguishedName: $SourceDN"
                Write-Error "[Move-DomainObject] $Message"
                if ($PassThru) {
                    return [PSCustomObject]@{
                        Operation = "MoveObject"
                        Object = $SourceDN
                        Success = $false
                        Message = $Message
                    }
                }
                return $false
            }

            Write-Log "[Move-DomainObject] Found $ObjectClass object: $SourceDN"

            # === Determine the target parent and the target RDN ===
            $TargetParentDN = $SourceParts.Parent
            if ($DestinationOU) {
                $TargetParentDN = $DestinationOU.Trim()
            }

            if ($PSBoundParameters.ContainsKey('NewName')) {
                # -NewName is a bare, UNESCAPED value, so it is escaped here. The attribute
                # type comes from the existing RDN: AD does not allow changing it.
                $TargetRDN = $SourceParts.RDNType + '=' + (Escape-LDAPDNComponent -Value $NewName)
            } else {
                # No rename: reuse the source RDN verbatim. It came from AD and is already
                # RFC 4514 escaped - sending it through the escaper again would turn
                # CN=Doe\, Jane into CN=Doe\\\, Jane and file the object under that name.
                $TargetRDN = $SourceParts.RDN
            }

            $Comparison = [System.StringComparison]::OrdinalIgnoreCase
            $ParentChanged = -not $TargetParentDN.Equals($SourceParts.Parent, $Comparison)
            $RDNChanged = -not $TargetRDN.Equals($SourceParts.RDN, $Comparison)

            # === Nothing to do ===
            if (-not $ParentChanged -and -not $RDNChanged) {
                Write-Log "[Move-DomainObject] Object is already at the requested location and name"
                if ($PassThru) {
                    return [PSCustomObject]@{
                        Operation = "MoveObject"
                        Object = $SourceDN
                        NewDistinguishedName = $SourceDN
                        ObjectClass = $ObjectClass
                        Success = $true
                        NoOp = $true
                        Message = "Object is already at the requested location and name"
                    }
                }
                Show-Line "Object is already at the requested location and name: $SourceDN" -Class Note
                return $true
            }

            # === Pre-flight validation ===
            # Suffix comparisons use EndsWith with an explicit leading comma so the match sits
            # on an RDN boundary, and Ordinal rather than -like because -like reads [ and ] as
            # a character class and an OU named "[Tier 0] Servers" is an ordinary way to name
            # one (same reasoning as Get-LDAPConfiguration.ps1).
            $DomainDN = [string]$Script:LDAPContext.DomainDN
            $Rejection = $null

            $SystemFlags = 0
            if ($null -ne $SourceObject.systemFlags) {
                $SystemFlags = [int]$SourceObject.systemFlags
            }

            if ($TargetParentDN.Equals($SourceDN, $Comparison) -or
                $TargetParentDN.EndsWith(',' + $SourceDN, $Comparison)) {
                # Matters for OU moves: an OU cannot become its own descendant.
                $Rejection = "Destination is the object itself or below it, which would detach the subtree: $TargetParentDN"
            }
            elseif (-not ($TargetParentDN.Equals($DomainDN, $Comparison) -or
                          $TargetParentDN.EndsWith(',' + $DomainDN, $Comparison))) {
                # ModifyDN cannot cross a domain boundary - the DC would answer
                # affectsMultipleDSAs (result 71), which names neither side of the problem.
                $Rejection = "Destination is outside the connected domain ($DomainDN). ModifyDN cannot move an object between domains - that needs a cross-domain migration with SID history. Destination: $TargetParentDN"
            }
            elseif ($ParentChanged -and ($SystemFlags -band $FLAG_DOMAIN_DISALLOW_MOVE) -ne 0) {
                $Rejection = "The object has systemFlags FLAG_DOMAIN_DISALLOW_MOVE set and cannot be moved: $SourceDN"
            }
            elseif ($RDNChanged -and ($SystemFlags -band $FLAG_DOMAIN_DISALLOW_RENAME) -ne 0) {
                $Rejection = "The object has systemFlags FLAG_DOMAIN_DISALLOW_RENAME set and cannot be renamed: $SourceDN"
            }

            # Target existence costs a round trip, so it runs only once the string checks pass.
            if (-not $Rejection -and $ParentChanged) {
                # A base-scope read of the container itself. A non-existent base makes the DC
                # answer noSuchObject, which Get-DomainObject surfaces as a terminating error,
                # so absence arrives here as an exception rather than an empty result.
                $TargetFound = $false
                try {
                    $TargetFound = @(Get-DomainObject -SearchBase $TargetParentDN -Scope Base `
                        -Properties @('distinguishedName') @ConnectionParams).Count -gt 0
                } catch {
                    Write-Log "[Move-DomainObject] Destination lookup failed: $($_.Exception.Message)"
                }

                if (-not $TargetFound) {
                    $Rejection = "Destination container not found or not readable: $TargetParentDN"
                }
            }

            if ($Rejection) {
                Write-Error "[Move-DomainObject] $Rejection"
                if ($PassThru) {
                    return [PSCustomObject]@{
                        Operation = "MoveObject"
                        Object = $SourceDN
                        ObjectClass = $ObjectClass
                        Success = $false
                        Message = $Rejection
                    }
                }
                return $false
            }

            # === Build and send the ModifyDNRequest ===
            # The three-argument constructor requires all three values, so the unchanged half
            # is passed through explicitly rather than omitted.
            $TargetDN = $TargetRDN + ',' + $TargetParentDN
            Write-Log "[Move-DomainObject] Moving '$SourceDN' to '$TargetDN'"

            $MoveRequest = New-Object System.DirectoryServices.Protocols.ModifyDNRequest
            $MoveRequest.DistinguishedName = $SourceDN
            $MoveRequest.NewParentDistinguishedName = $TargetParentDN
            $MoveRequest.NewName = $TargetRDN
            # Already the default. Set explicitly because AD rejects deleteoldrdn=FALSE with
            # unwillingToPerform - keeping the old RDN as a second value is not configurable.
            $MoveRequest.DeleteOldRdn = $true

            try {
                $Response = $Script:LdapConnection.SendRequest($MoveRequest)

                if ($Response.ResultCode -eq [System.DirectoryServices.Protocols.ResultCode]::Success) {
                    Write-Log "[Move-DomainObject] ModifyDNRequest succeeded"
                    if ($PassThru) {
                        return [PSCustomObject]@{
                            Operation = "MoveObject"
                            Object = $SourceDN
                            NewDistinguishedName = $TargetDN
                            ObjectClass = $ObjectClass
                            Success = $true
                            Message = "Object successfully moved"
                        }
                    }
                    Show-Line "Successfully moved $ObjectClass object" -Class Hint
                    Show-KeyValue "From:" $SourceDN
                    Show-KeyValue "To:" $TargetDN
                    # The object is the same principal, but its policy and delegation context
                    # is not - worth stating, because that is usually the point of the move.
                    Show-Line "objectGUID and objectSID are unchanged, but applied GPOs and inherited ACLs now come from the new location" -Class Note
                    return $true
                } else {
                    $Message = "ModifyDNRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                    Write-Error "[Move-DomainObject] $Message"
                    if ($PassThru) {
                        return [PSCustomObject]@{
                            Operation = "MoveObject"
                            Object = $SourceDN
                            ObjectClass = $ObjectClass
                            Success = $false
                            Message = $Message
                        }
                    }
                    return $false
                }
            } catch {
                # Decode the LDAP write failure into an actionable message (LDAP ResultCode +
                # AD server sub-error) instead of the generic text. The operation string must
                # start with "move " so Resolve-LDAPWriteError picks the ModifyDN rights hint.
                $writeError = Resolve-LDAPWriteError -Exception $_.Exception -Operation "move object '$SourceDN'"
                Write-Error ("[Move-DomainObject] Failed to move object." + [Environment]::NewLine + '  ' + $writeError.Formatted)
                if ($PassThru) {
                    return [PSCustomObject]@{
                        Operation  = "MoveObject"
                        Object     = $SourceDN
                        ObjectClass = $ObjectClass
                        Success    = $false
                        ResultCode = $writeError.ResultCode
                        ResultName = $writeError.ResultName
                        Message    = $writeError.Formatted
                    }
                }
                return $false
            }

        } catch {
            $writeError = Resolve-LDAPWriteError -Exception $_.Exception -Operation "move object '$Identity'"
            Write-Error ("[Move-DomainObject] Error." + [Environment]::NewLine + '  ' + $writeError.Formatted)
            if ($PassThru) {
                return [PSCustomObject]@{
                    Operation  = "MoveObject"
                    Object     = $Identity
                    Success    = $false
                    ResultCode = $writeError.ResultCode
                    ResultName = $writeError.ResultName
                    Message    = $writeError.Formatted
                }
            }
            return $false
        }
    }

    end {
        Write-Log "[Move-DomainObject] Move/rename operation completed"
    }
}
