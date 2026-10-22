function ConvertTo-UntrustedXml {
    <#
    .SYNOPSIS
    Parses XML read from a share, with DTD processing prohibited and no resolver.

    .DESCRIPTION
    A file on a share is written by whoever may write that share, which is the opposite of
    a file this scan can trust. "[xml]$text" parses with the defaults of the framework, and
    whether those resolve an external entity has changed across .NET versions. Here the
    reader refuses a DTD outright and has no resolver at all, so nothing in the file can
    make the parser fetch anything.

    .PARAMETER Text
    The content of the file.

    .OUTPUTS
    [xml], or nothing when the text is not XML - including XML that carries a DTD.

    .NOTES
    Internal helper function
    #>
    [CmdletBinding()]
    [OutputType([xml])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Text
    )

    if (-not $Text) { return }

    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null

    $stringReader = $null
    $reader = $null
    try {
        $stringReader = New-Object System.IO.StringReader $Text
        $reader = [System.Xml.XmlReader]::Create($stringReader, $settings)
        $document = New-Object System.Xml.XmlDocument
        $document.XmlResolver = $null
        $document.Load($reader)
        return $document
    } catch {
        Write-Log "[ConvertTo-UntrustedXml] Not parsed as XML: $($_.Exception.GetBaseException().Message)"
        return
    } finally {
        if ($reader) { $reader.Dispose() }
        if ($stringReader) { $stringReader.Dispose() }
    }
}

function Invoke-ShareHunt {
    <#
    .SYNOPSIS
    Finds the shares of the domain's computers this account can read, and searches them for
    credentials.

    .DESCRIPTION
    Get-CredentialExposure reads SYSVOL and NETLOGON. The file servers, the deployment
    shares and the administrators' own shares are where scripts and configuration files
    with credentials end up just as often, and nothing in adPEAS read them. This check
    does, in four steps, each bounded so that a large domain finishes:

    1. The computers: enabled Windows computers with a logon in the last ActiveDays days,
       by their DNS name - only a name below the domain's own, since the computer account
       may write dNSHostName itself. Or the computers named with -ComputerName.
    2. Who answers on port 445: one sweep with a deadline per block of hosts rather than
       per host (Test-TcpPortReachable).
    3. Their shares, enumerated in a runspace pool with one deadline for the pass
       (Get-SMBShareListMany), and of those the ones worth reading: disk shares, without
       the administrative ones and without SYSVOL and NETLOGON, which
       Get-CredentialExposure reads (Test-ShareWorthScanning). Each is probed for whether
       this account can list it (Test-SharePathReadable).
    4. The readable shares, walked breadth-first under limits of depth, files, time and
       file size (Get-ShareFileCandidate), and every candidate file analysed by the same
       functions the SYSVOL scan uses (Find-XmlFileCredential, Find-ScriptFileCredential).
       An XML file whose structure holds no credential is read as text as well: an
       application's settings.xml is not a policy file, and its password is a line.

    Every limit that is reached and everything that is left out is counted and said: a
    share that was walked to its end looks no different from one whose walk was stopped,
    unless the report says which it was.

    Under -OPSEC the check does nothing: it connects to every Windows computer of the
    domain over SMB, which is the loudest thing adPEAS can do.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .PARAMETER ComputerName
    The computers to search, instead of the domain's active Windows computers. One name, a
    list of them, or whatever comes down the pipeline - a string, or an object with a
    dNSHostName, Name, CN or IPAddress, which is what every Get-Domain* function returns.
    The same aliases Test-RemoteAdminAccess accepts, so the two read the same piped object.

    A name given here is not checked against the domain's DNS name the way a name read from
    the directory is: the caller named it on purpose.

    An empty pipeline searches nothing. It deliberately does not fall back to the domain -
    "Get-DomainComputer -OperatingSystem '*Server 2012*' | Invoke-ShareHunt" in a domain
    with no such computer would otherwise sweep every computer there is.

    .PARAMETER ActiveDays
    How recent the last logon of a computer must be, in days. Default: 30.

    .PARAMETER IncludeAdmin
    Searches the administrative shares as well (C$, ADMIN$ and the like). Readable only with
    administrator rights on the target, and walking one means walking a whole volume.

    .PARAMETER IncludeSysvol
    Searches SYSVOL and NETLOGON as well.

    .PARAMETER MaxDepth
    How far below the root of a share the walk goes. Default: 5.

    .PARAMETER MaxEntries
    How many files of one share the walk looks at. Default: 50000.

    .PARAMETER MaxFileSizeKB
    Files above this size are counted, not read. Default: 1024.

    .PARAMETER ShareTimeoutSeconds
    How long the walk of one share may take. Default: 120.

    .PARAMETER MaxMinutes
    How long the walks of all shares together may take. Default: 60.

    .PARAMETER ThrottleLimit
    How many share enumerations run at once. Default: 32.

    .PARAMETER ConnectTimeoutMs
    The deadline of one block of the port sweep. Default: 1000.

    .PARAMETER ListSharesOnly
    Lists the shares and stops there: no file is read and no credential is searched for.
    What it is for is the first pass over an unknown domain - the list of shares this
    account can reach is the answer to "where would I even look", and it comes back in the
    time the sweep and the enumeration take, without the walks.

    .PARAMETER OPSEC
    Skips the check.

    .EXAMPLE
    Invoke-ShareHunt

    .EXAMPLE
    Invoke-ShareHunt -ComputerName fs01.contoso.com, fs02.contoso.com -MaxDepth 8

    .EXAMPLE
    'fs01.contoso.com' | Invoke-ShareHunt -ListSharesOnly

    .EXAMPLE
    Get-DomainComputer -OperatingSystem '*Server*' | Invoke-ShareHunt
    The servers of the domain, by their dNSHostName.

    .EXAMPLE
    Invoke-ShareHunt -ActiveDays 14 -MaxMinutes 20

    .EXAMPLE
    Invoke-ShareHunt -ListSharesOnly
    The readable shares of the domain, without reading a file in them.

    .NOTES
    Category: Shares
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

        [Parameter(Mandatory=$false, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('DNSHostName', 'Name', 'CN', 'IPAddress')]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [AllowNull()]
        [string[]]$ComputerName,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1, 3650)]
        [int]$ActiveDays = 30,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeAdmin,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeSysvol,

        [Parameter(Mandatory=$false)]
        [ValidateRange(0, 64)]
        [int]$MaxDepth = 5,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1, 10000000)]
        [int]$MaxEntries = 50000,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1, 1048576)]
        [int]$MaxFileSizeKB = 1024,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1, 86400)]
        [int]$ShareTimeoutSeconds = 120,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1, 1440)]
        [int]$MaxMinutes = 60,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1, 256)]
        [int]$ThrottleLimit = 32,

        [Parameter(Mandatory=$false)]
        [ValidateRange(50, 60000)]
        [int]$ConnectTimeoutMs = 1000,

        [Parameter(Mandatory=$false)]
        [switch]$ListSharesOnly,

        [Parameter(Mandatory=$false)]
        [switch]$OPSEC
    )

    begin {
        Write-Log "[Invoke-ShareHunt] Starting check"

        # Filled by process{}, used once by end{}.
        $givenTargets = New-Object System.Collections.Generic.List[string]
        $givenNameless = 0
        $targetsWereGiven = $false
    }

    process {
        # Collects and nothing else. The check belongs in end{}: run from process{} it
        # would sweep the network, enumerate shares and print both its sections once per
        # piped computer.
        if (-not $PSBoundParameters.ContainsKey('ComputerName')) { return }
        $targetsWereGiven = $true
        foreach ($one in @($ComputerName)) {
            $trimmed = ([string]$one).Trim()
            # An object whose dNSHostName is empty binds the empty string rather than
            # falling back to its Name, and guessing a short name for it is not better
            # than counting it as nameless.
            if ($trimmed) { $givenTargets.Add($trimmed) } else { $givenNameless++ }
        }
    }

    end {
        try {
            # Connection parameters only: Ensure-LDAPConnection and the Get-Domain* functions
            # have none of the others, and splatting $PSBoundParameters would fail to bind.
            $connectionParams = @{}
            if ($PSBoundParameters.ContainsKey('Domain'))     { $connectionParams['Domain'] = $Domain }
            if ($PSBoundParameters.ContainsKey('Server'))     { $connectionParams['Server'] = $Server }
            if ($PSBoundParameters.ContainsKey('Credential')) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed). Needed even with
            # -ComputerName: the analysis asks the directory about the accounts it finds.
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            Show-SubHeader "Searching for readable shares..." -ObjectType "ReadableShare"

            if ($OPSEC) {
                Show-Line "OPSEC mode: Skipping the share hunt (would connect to every computer over SMB)" -Class Hint
                return
            }

            # Invoke-adPEAS sets the context for each check and passes none of the switches
            # named in the lines below; without one they are reachable, and worth naming.
            $standalone = ($null -eq $Script:adPEAS_CurrentCheckContext)

            # ===== The computers =====
            $outsideDomain = 0
            $withoutName = 0
            # ExpectingInput as well as the flag: an empty pipeline binds nothing, so the
            # flag alone cannot tell "@() | Invoke-ShareHunt" from a call with no targets at
            # all - and the difference is between searching nothing and searching a whole
            # domain. Measured on Windows PowerShell 5.1: for an empty pipeline process{}
            # never runs and ExpectingInput is still true.
            if ($targetsWereGiven -or $PSCmdlet.MyInvocation.ExpectingInput) {
                $targets = @($givenTargets | Sort-Object -Unique)
                $withoutName = $givenNameless
            } else {
                $domainFQDN = ([string]$Script:LDAPContext.Domain).Trim().TrimEnd('.').ToLowerInvariant()
                $since = (Get-Date).AddDays(-$ActiveDays).ToFileTime()
                # Only the attribute the sweep needs: nothing of the computer objects is
                # shown, so the -Properties rule for displayed objects does not apply.
                # Announced before the query rather than after it: on a large domain this
                # is the first thing that takes time, and a check that has printed nothing
                # yet is indistinguishable from one that is stuck.
                Show-Progress -Activity 'Share hunt' -Current 1 -Total 1 -Status 'Looking for the active computers of the domain'
                $computers = @(Get-DomainComputer -Enabled -LDAPFilter "(&(lastLogonTimestamp>=$since)(operatingSystem=Windows*))" `
                    -Properties 'dNSHostName' @connectionParams)
                $names = New-Object System.Collections.Generic.List[string]
                foreach ($computer in $computers) {
                    $fqdn = ([string]$computer.dNSHostName).Trim().TrimEnd('.').ToLowerInvariant()
                    if (-not $fqdn) { $withoutName++; continue }
                    # The computer account may write its own dNSHostName; a name outside the
                    # domain is one this scan was not asked to contact.
                    if (-not $fqdn.EndsWith(".$domainFQDN")) { $outsideDomain++; continue }
                    $names.Add($fqdn)
                }
                $targets = @($names | Sort-Object -Unique)
            }
            Write-Log "[Invoke-ShareHunt] $($targets.Count) computer(s) to contact"

            # ===== Who answers on 445 =====
            # Swept a block at a time rather than in one call, only so that the count can
            # be shown as it goes: the sweep works in blocks of this size either way, so
            # the result and the cost are the same.
            $sweepBatch = 256
            $reachableList = New-Object System.Collections.Generic.List[string]
            for ($offset = 0; $offset -lt $targets.Count; $offset += $sweepBatch) {
                Show-Progress -Activity 'Share hunt' -Current $offset -Total $targets.Count `
                    -Status "Checking port 445: $offset of $($targets.Count) computer(s), $($reachableList.Count) answering"
                $last = [Math]::Min($offset + $sweepBatch, $targets.Count) - 1
                foreach ($answer in @(Test-TcpPortReachable -Target $targets[$offset..$last] -Port 445 -TimeoutMs $ConnectTimeoutMs -BatchSize $sweepBatch)) {
                    if ($answer.Reachable) { $reachableList.Add($answer.Target) }
                }
            }
            $reachable = @($reachableList)
            $unreachable = $targets.Count - $reachable.Count
            Write-Log "[Invoke-ShareHunt] $($reachable.Count) of $($targets.Count) computer(s) answer on port 445"

            # ===== Their shares, and the ones worth reading =====
            # In chunks of a few pool loads, again so the count advances - and a stalled
            # host then costs its chunk's deadline rather than the whole pass's. The pool
            # is opened once per chunk, which is why the chunk is several loads and not one.
            $listingChunk = [Math]::Max(1, $ThrottleLimit) * 4
            $listings = New-Object System.Collections.Generic.List[object]
            for ($offset = 0; $offset -lt $reachable.Count; $offset += $listingChunk) {
                Show-Progress -Activity 'Share hunt' -Current $offset -Total $reachable.Count `
                    -Status "Enumerating shares: $offset of $($reachable.Count) computer(s)"
                $last = [Math]::Min($offset + $listingChunk, $reachable.Count) - 1
                foreach ($listing in @(Get-SMBShareListMany -Target $reachable[$offset..$last] -ThrottleLimit $ThrottleLimit)) {
                    $listings.Add($listing)
                }
            }
            $listFailed = @{}
            $leftOutAdmin = 0
            $leftOutSysvol = 0
            $candidates = New-Object System.Collections.Generic.List[object]
            foreach ($listing in $listings) {
                if ($listing.Error) {
                    if (-not $listFailed.ContainsKey($listing.Error)) { $listFailed[$listing.Error] = 0 }
                    $listFailed[$listing.Error]++
                    continue
                }
                foreach ($share in @($listing.Shares)) {
                    $verdict = Test-ShareWorthScanning -Name $share.Name -Type $share.Type -IncludeAdmin:$IncludeAdmin -IncludeSysvol:$IncludeSysvol
                    if (-not $verdict.Scan) {
                        # Printers and pipes are not counted: no one expects a file there.
                        if ($verdict.Reason -eq 'Administrative share') { $leftOutAdmin++ }
                        elseif ($verdict.Reason -eq 'Read by Get-CredentialExposure') { $leftOutSysvol++ }
                        continue
                    }
                    $candidates.Add([PSCustomObject]@{
                        Computer = $listing.ComputerName
                        Name     = $share.Name
                        Remark   = $share.Remark
                        Path     = "\\$($listing.ComputerName)\$($share.Name)"
                        Walk     = $null
                    })
                }
            }

            # ===== Readable by this account =====
            $readable = New-Object System.Collections.Generic.List[object]
            $notReadable = 0
            $index = 0
            # No threshold on the count here: one share on an unresponsive host can take
            # as long as thirty on a healthy one, and the point of the display is to say
            # which host is being waited for.
            foreach ($share in $candidates) {
                $index++
                Show-Progress -Activity 'Share hunt' -Current $index -Total $candidates.Count `
                    -Status "Probing share $index of $($candidates.Count)" -ObjectName $share.Path
                if ((Test-SharePathReadable -Path $share.Path).Readable) { $readable.Add($share) } else { $notReadable++ }
            }
            Write-Log "[Invoke-ShareHunt] $($readable.Count) of $($candidates.Count) share(s) can be read"

            # ===== The walks =====
            # One budget for every walk together, as well as one per share: the per-share
            # limit keeps a single large share from taking the pass, the pass limit keeps
            # two hundred shares at their limit each from taking an afternoon.
            $passDeadline = [DateTime]::UtcNow.AddMinutes($MaxMinutes)
            $extensions = @('*.xml') + @($Script:CredentialScanExtensions)
            $index = 0
            if (-not $ListSharesOnly) {
                foreach ($share in $readable) {
                    $index++
                    # Every share, whatever the count: one of them may take the full
                    # per-share budget on its own.
                    Show-Progress -Activity 'Share hunt' -Current $index -Total $readable.Count `
                        -Status "Searching share $index of $($readable.Count)" -ObjectName $share.Path
                    $shareDeadline = [DateTime]::UtcNow.AddSeconds($ShareTimeoutSeconds)
                    if ($shareDeadline -gt $passDeadline) { $shareDeadline = $passDeadline }
                    $share.Walk = Get-ShareFileCandidate -Path $share.Path -Extension $extensions -MaxDepth $MaxDepth `
                        -MaxEntries $MaxEntries -MaxFileSizeKB $MaxFileSizeKB -Deadline $shareDeadline
                }
            }
            Show-Progress -Activity 'Share hunt' -Completed

            # ===== Output: what was left out, then the readable shares =====
            if ($outsideDomain -gt 0) {
                Show-Line "$outsideDomain active computer(s) with a DNS name outside $domainFQDN - not contacted" -Class Note
            }
            if ($withoutName -gt 0) {
                Show-Line "$withoutName active computer(s) without a DNS name (dNSHostName) - not contacted" -Class Note
            }
            if ($unreachable -gt 0) {
                Show-Line "$unreachable of $($targets.Count) computer(s) do not answer on port 445" -Class Note
            }
            if ($listFailed.Count -gt 0) {
                $failedTotal = 0
                foreach ($value in $listFailed.Values) { $failedTotal += $value }
                $reasons = @($listFailed.GetEnumerator() | Sort-Object -Property @{ Expression = { $_.Value }; Descending = $true }, @{ Expression = { [string]$_.Key }; Descending = $false } |
                    ForEach-Object { "$($_.Value) $($_.Key)" })
                Show-Line "$failedTotal computer(s) did not list their shares: $($reasons -join ', ')" -Class Note
            }
            if ($leftOutAdmin -gt 0) {
                $text = "$leftOutAdmin administrative share(s) left out"
                if ($standalone -and -not $IncludeAdmin) { $text += ' (-IncludeAdmin to search them)' }
                Show-Line $text -Class Note
            }
            if ($leftOutSysvol -gt 0) {
                $text = "$leftOutSysvol SYSVOL and NETLOGON share(s) left out - Get-CredentialExposure reads them"
                if ($standalone -and -not $IncludeSysvol) { $text += ' (-IncludeSysvol to search them here)' }
                Show-Line $text -Class Note
            }
            if ($notReadable -gt 0) {
                Show-Line "$notReadable share(s) are listed but cannot be read by this account" -Class Note
            }

            if ($readable.Count -eq 0) {
                Show-Line "No readable share found" -Class Note
                return
            }

            $byComputer = @($readable | Group-Object -Property Computer | Sort-Object -Property Name)
            Show-Line "Found $($readable.Count) readable share(s) on $($byComputer.Count) computer(s):" -Class Note

            foreach ($group in $byComputer) {
                $shares = @($group.Group | Sort-Object -Property Name)
                $hostObject = [PSCustomObject][ordered]@{
                    Name           = $group.Name
                    computerName   = $group.Name
                    readableShares = @($shares | ForEach-Object { if ($_.Remark) { "$($_.Path) ($($_.Remark))" } else { $_.Path } })
                }
                # What the walk could not cover, share by share: a limit it reached, or
                # folders it could not open. Short; the section help says what each means.
                # With -ListSharesOnly there is no walk to report on, and nothing here has
                # to say so: reading a property of $null answers $null and "$null -gt 0" is
                # false, so a share without a walk contributes no part and gets no row.
                $incomplete = @(foreach ($share in $shares) {
                    $parts = @()
                    if ($share.Walk.Truncated) { $parts += "stopped at $($share.Walk.Truncated)" }
                    if ($share.Walk.Denied -gt 0) { $parts += "$($share.Walk.Denied) folder(s) not readable" }
                    if ($parts.Count -gt 0) { "$($share.Path): $($parts -join ', ')" }
                })
                if ($incomplete.Count -gt 0) {
                    $hostObject | Add-Member -NotePropertyName 'notFullySearched' -NotePropertyValue $incomplete -Force
                }
                $hostObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'ReadableShare' -Force
                Show-Object $hostObject -Class Note
            }

            if ($ListSharesOnly) {
                # Said as a note rather than left to be inferred from a missing section: a
                # reader who does not know the switch was used would otherwise read the
                # absence of credentials as a result.
                Show-Line "No file was read - the shares were only listed (-ListSharesOnly)" -Class Note
                return
            }

            # ===== The credentials in them =====
            Show-SubHeader "Searching readable shares for credentials..." -ObjectType "ShareCredential"

            $unreadable = 0
            $tooLarge = 0
            $results = New-Object System.Collections.Generic.List[object]
            foreach ($share in $readable) {
                $tooLarge += [int]$share.Walk.SkippedLarge
                foreach ($file in @($share.Walk.Files)) {
                    try {
                        $found = @()
                        if ($file.Extension -ieq '.xml') {
                            $text = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
                            $document = ConvertTo-UntrustedXml -Text $text
                            if ($document) {
                                $found = @(Find-XmlFileCredential -XmlContent $document -FilePath $file.FullName -FileName $file.Name -FileTime $file.LastWriteTime)
                            }
                            # An XML file whose structure holds no credential is still text:
                            # an application's settings.xml keeps its password in an element
                            # no policy parser looks at. A policy file that did yield one is
                            # not read again, or its cpassword line would be reported twice.
                            if ($found.Count -eq 0) {
                                $found = @(Find-ScriptFileCredential -Content $text -FilePath $file.FullName -FileName $file.Name -FileTime $file.LastWriteTime)
                            }
                        } else {
                            $text = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
                            if ($file.Extension -ieq '.vbe') { $text = ConvertFrom-VBE -EncodedScript $text }
                            $found = @(Find-ScriptFileCredential -Content $text -FilePath $file.FullName -FileName $file.Name -FileTime $file.LastWriteTime)
                        }
                        foreach ($one in $found) { $results.Add($one) }
                    } catch {
                        $unreadable++
                        Write-Log "[Invoke-ShareHunt] $($file.FullName) could not be read: $($_.Exception.Message)"
                    }
                }
            }

            if ($unreadable -gt 0) {
                Show-Line "$unreadable file(s) could not be read" -Class Note
            }
            if ($tooLarge -gt 0) {
                Show-Line "$tooLarge file(s) over $MaxFileSizeKB KB not read" -Class Note
            }

            if ($results.Count -eq 0) {
                # Not "Secure": a share is read only as far as this account and the limits
                # allowed, which is never the guarantee that word would make.
                Show-Line "No credentials found in $($readable.Count) readable share(s)" -Class Note
                return
            }

            foreach ($result in $results) {
                $credObj = $result.Credential
                Show-Line $result.Headline -Class $result.Class
                $credObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'ShareCredential' -Force
                $credObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue $result.Context -Force
                Show-Object $credObj -Class $result.Class
            }

        } catch {
            Write-Log "[Invoke-ShareHunt] Error: $_" -Level Error
            Show-Line "Error during check - the shares could not be searched: $_" -Class Finding
        }

        Write-Log "[Invoke-ShareHunt] Check completed"
    }
}
