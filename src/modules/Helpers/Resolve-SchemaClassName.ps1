function Resolve-SchemaClassName {
    <#
    .SYNOPSIS
    Resolves a schema class GUID to its LDAP display name, falling back to the directory's
    own schema when the static table does not know it.

    .DESCRIPTION
    An ACE's InheritedObjectType names the object class the ACE descends to. adPEAS carries
    a static table of the common ones ($Script:SchemaClassGUIDs), but that table can only
    ever hold the classes the base schema ships. Any forest that has been extended - by
    Exchange, by Configuration Manager, by a third-party product - has hundreds more, and a
    GUID the table does not know is printed raw, which tells a reader nothing and makes two
    different ACEs look like duplicates.

    So the static table is tried first, and on a miss the schema partition is asked. Every
    classSchema object is read once per session and cached, because resolving a handful of
    GUIDs one query at a time costs more than reading the list, and because the same GUIDs
    recur across every ACL adPEAS parses.

    A directory that cannot be read returns $null rather than a guess. The caller decides
    what to print for an unresolved GUID - printing the GUID is honest, inventing a name is
    not.

    .PARAMETER GUID
    The schema class GUID, as a string or a [GUID].

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Resolve-SchemaClassName -GUID 'bf967aba-0de6-11d0-a285-00aa003049e2'
    # Returns: user     (from the static table, no query)

    .EXAMPLE
    Resolve-SchemaClassName -GUID 'f0f8ffac-1191-11d0-a060-00aa006c33ed'
    # Returns: publicFolder     (from the schema partition, Exchange-extended forest)

    .OUTPUTS
    String - the class's lDAPDisplayName, or $null when it cannot be resolved.

    .NOTES
    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [AllowNull()]
        $GUID,

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    process {
        if (-not $GUID) { return $null }

        $guidString = if ($GUID -is [GUID]) { $GUID.ToString() } else { ([string]$GUID).Trim('{}').ToLower() }
        if (-not $guidString) { return $null }

        # Static table first. It answers for the base-schema classes without a round trip,
        # and it is also what the offline tests exercise.
        $staticName = Get-SchemaClassName -GUID $guidString
        if ($staticName -and $staticName -ne 'All Objects') { return $staticName }

        # Build credential parameters for the inner query. An inner scope has no access to
        # the caller's $PSBoundParameters (CF-006).
        $CredParams = @{}
        if ($PSBoundParameters.ContainsKey('Domain')) { $CredParams['Domain'] = $Domain }
        if ($PSBoundParameters.ContainsKey('Server')) { $CredParams['Server'] = $Server }
        if ($PSBoundParameters.ContainsKey('Credential')) { $CredParams['Credential'] = $Credential }

        # Cache is built once per session. $null is a distinct state from an empty map: it
        # means "not attempted yet", so a forest whose schema really is unreadable is not
        # re-queried on every ACE.
        if ($null -eq $Script:SchemaClassNameCache) {
            $Script:SchemaClassNameCache = @{}

            $schemaDN = $null
            if ($Script:LDAPContext) {
                $schemaDN = [string]$Script:LDAPContext.SchemaNamingContext
                if (-not $schemaDN -and $Script:LDAPContext.ConfigurationNamingContext) {
                    # RootDSE did not hand one over. The schema container is always a direct
                    # child of the configuration container, so this is derivation, not a guess.
                    $schemaDN = "CN=Schema,$($Script:LDAPContext.ConfigurationNamingContext)"
                }
            }

            if (-not $schemaDN) {
                Write-Log "[Resolve-SchemaClassName] No schema naming context available - GUIDs outside the static table stay unresolved"
                return $null
            }

            try {
                # -Raw because schemaIDGUID has no converter and would arrive as a byte[]
                # under a name the consumer would then have to special-case anyway.
                $classes = @(Get-DomainObject -LDAPFilter '(objectCategory=classSchema)' -SearchBase $schemaDN -Properties 'lDAPDisplayName','schemaIDGUID' -Raw @CredParams)

                foreach ($class in $classes) {
                    if (-not $class.lDAPDisplayName -or -not $class.schemaIDGUID) { continue }
                    try {
                        $classGuid = [GUID]::new([byte[]]$class.schemaIDGUID)
                        $Script:SchemaClassNameCache[$classGuid.ToString()] = [string]$class.lDAPDisplayName
                    }
                    catch {
                        # A schemaIDGUID that is not 16 bytes is not a GUID. Skipping one
                        # entry is better than losing the whole map.
                        Write-Log "[Resolve-SchemaClassName] Unreadable schemaIDGUID on $($class.lDAPDisplayName): $_"
                    }
                }

                Write-Log "[Resolve-SchemaClassName] Cached $($Script:SchemaClassNameCache.Count) schema class name(s) from $schemaDN"
            }
            catch {
                Write-Log "[Resolve-SchemaClassName] Schema partition not readable: $_" -Level Error
            }
        }

        if ($Script:SchemaClassNameCache.ContainsKey($guidString)) {
            return $Script:SchemaClassNameCache[$guidString]
        }

        return $null
    }
}
