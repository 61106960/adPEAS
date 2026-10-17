function Get-DomainControllerGPOContext {
    <#
    .SYNOPSIS
    Collects what decides whether a Group Policy link reaches a domain controller: where
    the domain controllers sit, which site each one is in, and which containers block
    inheritance.

    .DESCRIPTION
    A GPO reaches a domain controller through a link on a container above its computer
    object - the Domain Controllers OU, an OU above it, the domain root - or through a link
    on the site the domain controller is in. A container that blocks inheritance (gPOptions
    bit 0) stops every link above it that is not enforced, site links included; that is how
    a domain-root policy can reach every member computer and no domain controller.

    Read from the directory once per session and cached in
    $Script:DomainControllerGPOContext; Disconnect-adPEAS clears it.

    The domain controllers are taken from where their computer objects actually are, not
    from the name of the OU they are expected in: a domain controller moved out of the
    Domain Controllers OU is reached by the policies above its real location. The site comes
    from serverReferenceBL, the back link from the server object under CN=Sites.

    .OUTPUTS
    PSCustomObject with
      DomainControllers  - one entry per domain controller: DistinguishedName, SiteDN
                           ($null where the site could not be read), and objectSid and
                           primaryGroupID, which security filtering is judged by
                           (Test-GPOFilterCoversComputer)
      BlockedContainers  - hashtable of lower-case DNs whose gPOptions blocks inheritance
      DomainDN           - the domain root, where the walk up from a domain controller ends

    $null when the domain controllers or the blocking containers could not be read - the
    question then has no answer, and a caller must say Unknown rather than No.

    .NOTES
    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    process {
        if ($Script:DomainControllerGPOContext) {
            return $Script:DomainControllerGPOContext
        }

        $domainDN = $Script:LDAPContext.DomainDN
        if (-not $domainDN) {
            Write-Log "[Get-DomainControllerGPOContext] No domain DN in the session context"
            return $null
        }

        # Every domain has a domain controller; none read means none could be read.
        $dcObjects = @()
        try {
            $dcObjects = @(Get-DomainComputer -DomainController -Properties 'distinguishedName', 'serverReferenceBL', 'objectSid', 'primaryGroupID')
        } catch {
            Write-Log "[Get-DomainControllerGPOContext] Could not read the domain controllers: $_"
            return $null
        }
        if ($dcObjects.Count -eq 0) {
            Write-Log "[Get-DomainControllerGPOContext] No domain controller object was returned"
            return $null
        }

        $dcEntries = @()
        foreach ($dcObject in $dcObjects) {
            $dcDN = [string]$dcObject.distinguishedName
            if (-not $dcDN) { continue }

            # CN=<server>,CN=Servers,CN=<site>,CN=Sites,CN=Configuration,... - the site is
            # what follows CN=Servers. Escape-aware, like every other DN split here.
            $siteDN = $null
            foreach ($backLink in @($dcObject.serverReferenceBL)) {
                if ("$backLink" -match '^CN=(?:[^,\\]|\\.)+,CN=Servers,(CN=(?:[^,\\]|\\.)+,CN=Sites,.+)$') {
                    $siteDN = $Matches[1]
                    break
                }
            }

            $dcEntries += [PSCustomObject]@{
                DistinguishedName = $dcDN
                SiteDN            = $siteDN
                objectSid         = $(if ($dcObject.objectSid) { [string]@($dcObject.objectSid)[0] } else { $null })
                primaryGroupID    = $(if ($dcObject.primaryGroupID) { [string]@($dcObject.primaryGroupID)[0] } else { $null })
            }
        }

        # One query for every container that blocks inheritance, the domain object
        # included - which blocks site-linked policies.
        $blockedContainers = @{}
        try {
            foreach ($container in @(Get-DomainObject -LDAPFilter '(gPOptions:1.2.840.113556.1.4.803:=1)' -Properties 'distinguishedName')) {
                $containerDN = [string]$container.distinguishedName
                if ($containerDN) { $blockedContainers[$containerDN.ToLowerInvariant()] = $true }
            }
        } catch {
            # Without it a policy blocked on its way down would be reported as reaching the
            # domain controllers. No answer is better than that one.
            Write-Log "[Get-DomainControllerGPOContext] Could not read the containers that block inheritance: $_"
            return $null
        }

        $Script:DomainControllerGPOContext = [PSCustomObject]@{
            DomainControllers = $dcEntries
            BlockedContainers = $blockedContainers
            DomainDN          = $domainDN
        }
        return $Script:DomainControllerGPOContext
    }
}
