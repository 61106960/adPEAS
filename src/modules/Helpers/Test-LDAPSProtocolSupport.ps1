function Test-LDAPSProtocolSupport {
    <#
    .SYNOPSIS
    Asks a domain controller, one TLS version at a time, which ones it will accept on the LDAPS
    port.

    .DESCRIPTION
    Runs only when the LDAPS handshake has already failed, and turns the one line Windows gives
    for that failure into a diagnosis.

    The message a failed handshake produces is almost always "An existing connection was
    forcibly closed by the remote host" - a TCP reset in the middle of the negotiation, which
    Microsoft attributes to the client and the server not agreeing on a protocol version or a
    cipher suite. Which of the two it was, the message does not say, and the difference decides
    what somebody does next.

    So this asks each version on its own:

      some accepted   the versions are fine and the default negotiation offered something the
                      server killed the connection over - the thing to look at is which
                      protocols and ciphers this client enables, under
                      HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
      all reset       every attempt was torn down at the socket before a TLS byte was exchanged.
                      A server refusing a version or a cipher answers with a TLS alert; it does
                      not reset. So this is not a TLS configuration at all - look for a device
                      in the path that proxies the TCP handshake and then drops the session, or
                      a listener on 636 with nothing speaking TLS behind it.
      none accepted   TLS was spoken and refused, so it is the cipher suites rather than the
                      version

    The three are told apart by the exception chain and never by its text. The message is
    localised, and the same teardown surfaces as "Unable to read data" or "Unable to write data"
    depending on whether the ClientHello had left yet. A SocketException at the bottom means the
    transport died; an AuthenticationException means TLS was negotiated and refused.

    Deliberately NOT done here: using a version that worked for the real connection. The
    handshake adPEAS tests is a .NET SslStream, while the LdapConnection that follows negotiates
    through Schannel and takes no protocol parameter - there is nothing to pass a result to. The
    probe reports, it does not steer.

    Nothing here throws. It is called from an error path, and a diagnostic that fails has to
    leave the original error standing rather than replace it with its own.

    .PARAMETER Server
    The host name to authenticate against - the name that has to match the certificate, which is
    why it stays the name even when the TCP connection goes to an address.

    .PARAMETER ConnectTarget
    Where to open the socket. Differs from Server when a custom DNS server resolved the name
    already. Defaults to Server.

    .PARAMETER Port
    LDAPS port, 636 by default.

    .PARAMETER TimeoutMs
    Per-attempt TCP connect timeout. The handshake itself is left to the OS; a server that
    answers the port but never completes the negotiation is the case being measured, and it
    fails fast by resetting.

    .OUTPUTS
    [PSCustomObject] with
      Accepted  - version names that completed a handshake, strongest first
      Rejected  - version names that did not
      Summary   - one sentence for the error block, or $null when nothing could be measured

    .EXAMPLE
    Test-LDAPSProtocolSupport -Server 'dc01.contoso.com'

    .NOTES
    Author: Alexander Sturz (@_61106960_)
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [string]$ConnectTarget,

        [Parameter(Mandatory=$false)]
        [int]$Port = 636,

        [Parameter(Mandatory=$false)]
        [int]$TimeoutMs = 2000
    )

    if ([string]::IsNullOrWhiteSpace($ConnectTarget)) { $ConnectTarget = $Server }

    $accepted          = New-Object System.Collections.Generic.List[string]
    $rejected          = New-Object System.Collections.Generic.List[string]
    $unreachable       = New-Object System.Collections.Generic.List[string]
    $resetBeforeTls    = New-Object System.Collections.Generic.List[string]
    $negotiationFailed = New-Object System.Collections.Generic.List[string]
    $socketCodes       = New-Object System.Collections.Generic.List[string]

    # Strongest first, so the Accepted list reads as "the best it would do".
    #
    # Each name is cast at runtime rather than written as an enum literal: Tls13 exists only from
    # .NET Framework 4.8, and a literal would make this file fail to load on an older host
    # instead of simply skipping that one probe.
    foreach ($name in @('Tls13', 'Tls12', 'Tls11', 'Tls')) {
        $protocol = $null
        try {
            $protocol = [System.Security.Authentication.SslProtocols]$name
        } catch {
            Write-Log "[Test-LDAPSProtocolSupport] $name is not available on this host - skipped"
            continue
        }

        $tcp = $null
        $ssl = $null
        try {
            # The socket is opened in its own step so that a failure here is not counted as the
            # server rejecting a TLS version. It is the same distinction the summary rests on:
            # a port that stopped answering says nothing about cipher suites, and reporting it
            # as "accepted none of TLS 1.0 to 1.3" would be an assertion about the server built
            # on the absence of a server.
            $connected = $false
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $connect = $tcp.BeginConnect($ConnectTarget, $Port, $null, $null)
                if ($connect.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
                    $tcp.EndConnect($connect)
                    $connected = $true
                }
            } catch {
                Write-Log "[Test-LDAPSProtocolSupport] $name - TCP connect failed: $($_.Exception.Message)"
            }

            if (-not $connected) {
                Write-Log "[Test-LDAPSProtocolSupport] $name - port $Port did not answer"
                $unreachable.Add($name)
                continue
            }

            # Everything accepted on purpose. The question is which versions the server will
            # negotiate, and a certificate this client does not trust is a different finding -
            # one that CertificateError already reports.
            $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, { $true })
            $ssl.AuthenticateAsClient($Server, $null, $protocol, $false)

            Write-Log "[Test-LDAPSProtocolSupport] $name accepted - $($ssl.SslProtocol) / $($ssl.CipherAlgorithm)"
            $accepted.Add($name)
        }
        catch {
            # Classified by the exception chain, not by its text. The message is localised - on a
            # German host the same reset reads "Eine bestehende Verbindung wurde ... abgebrochen"
            # - and it also differs by timing: the same teardown surfaces as "Unable to read
            # data" or "Unable to write data" depending on whether the client had got its
            # ClientHello out yet. Neither is a basis for a conclusion.
            #
            # What distinguishes the two cases is what sits at the bottom:
            #
            #   SocketException          the transport was torn down. No TLS message was
            #                            exchanged, so the server never refused a version - it
            #                            refused the conversation.
            #   AuthenticationException  TLS was spoken and the negotiation failed. That is the
            #                            version or cipher case.
            $socketError = $null
            $sawAuthFailure = $false
            $detail = $_.Exception.Message
            $walk = $_.Exception
            while ($walk) {
                if ($walk -is [System.Net.Sockets.SocketException]) {
                    $socketError = $walk.SocketErrorCode
                    $detail = $walk.Message
                }
                if ($walk -is [System.Security.Authentication.AuthenticationException]) {
                    $sawAuthFailure = $true
                    $detail = $walk.Message
                }
                $walk = $walk.InnerException
            }

            if ($socketError -and -not $sawAuthFailure) {
                Write-Log "[Test-LDAPSProtocolSupport] $name - connection torn down ($socketError) before any TLS message"
                $resetBeforeTls.Add($name)
                if (-not $socketCodes.Contains([string]$socketError)) { $socketCodes.Add([string]$socketError) }
            } else {
                Write-Log "[Test-LDAPSProtocolSupport] $name - negotiation refused: $detail"
                $negotiationFailed.Add($name)
            }
            $rejected.Add($name)
        }
        finally {
            if ($ssl) { try { $ssl.Dispose() } catch { } }
            if ($tcp) { try { $tcp.Close() } catch { } }
        }
    }

    # ToArray(), not @($list): casting a hashtable to PSCustomObject throws "Argument types do
    # not match" when a value is @() around a List[object]. Same reason as in
    # Split-GPOFindingByReach.
    $result = [PSCustomObject]@{
        Accepted          = $accepted.ToArray()
        Rejected          = $rejected.ToArray()
        Unreachable       = $unreachable.ToArray()
        ResetBeforeTls    = $resetBeforeTls.ToArray()
        NegotiationFailed = $negotiationFailed.ToArray()
        SocketErrors      = $socketCodes.ToArray()
        Summary           = $null
    }

    $friendly = @{ 'Tls13' = 'TLS 1.3'; 'Tls12' = 'TLS 1.2'; 'Tls11' = 'TLS 1.1'; 'Tls' = 'TLS 1.0' }
    $nameOf = { param($keys) (@($keys) | ForEach-Object { $friendly[$_] }) -join ', ' }

    if ($accepted.Count -gt 0) {
        $result.Summary = ('Asked one version at a time, the server accepted ' +
            (& $nameOf $accepted.ToArray()) +
            ' - so the versions are not the problem and the default negotiation offered something it refused.' +
            ' Check the protocols and cipher suites this client enables under SCHANNEL.')
    }
    elseif ($resetBeforeTls.Count -gt 0 -and $negotiationFailed.Count -eq 0) {
        # The strongest statement this probe can make, and the one that was missing: every
        # attempt was torn down at the socket before a single TLS byte was exchanged, and
        # identically for every version. A server refusing a version or a cipher answers with a
        # TLS alert; it does not reset the socket. So this is not a TLS configuration at all.
        #
        # The port answered during the reachability test, which is what makes a middlebox the
        # likely explanation: a firewall that proxies the TCP handshake and then drops the
        # session when the payload arrives looks exactly like this.
        $result.Summary = ('The server accepted the TCP connection and then tore it down (' +
            (($socketCodes.ToArray() | Sort-Object) -join ', ') +
            ') before any TLS message was exchanged, identically for ' +
            (& $nameOf $resetBeforeTls.ToArray()) +
            '. A version or cipher mismatch answers with a TLS alert rather than resetting, so this' +
            ' is not a TLS configuration problem - look for a device in the path that proxies the' +
            ' handshake and drops the session, or a listener on 636 with no TLS behind it.')
    }
    elseif ($rejected.Count -gt 0) {
        $result.Summary = ('Asked one version at a time, the server accepted none of ' +
            (& $nameOf $rejected.ToArray()) +
            ' - which points at the cipher suites or a device in the path rather than the TLS version.')
    }
    elseif ($unreachable.Count -gt 0) {
        # Every attempt failed before any TLS was spoken. The port answered a moment ago, during
        # the reachability test, so something closed in between - and that is a different
        # statement from the server refusing a version. Claiming the latter here would blame a
        # cipher configuration for a socket that was never open.
        $result.Summary = ("Port $Port did not answer on any retry, so the handshake could not be " +
            'measured - the earlier reachability test and these attempts disagree, which suggests ' +
            'something between this host and the server is closing the connection.')
    }
    # Nothing at all measured - not one version could even be constructed on this host. No
    # summary, because every sentence available would be a claim about the server.

    return $result
}
