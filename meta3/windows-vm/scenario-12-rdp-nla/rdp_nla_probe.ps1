# rdp_nla_probe.ps1 -- live RDP security-negotiation probe for meta3/windows-vm
# scenario 12. Speaks TPKT / X.224, NOT SMB.
#
# EXIT CODES (consumed by verify-poc.ps1):
#   0  server accepted PROTOCOL_RDP      -> host is VULNERABLE (no NLA)
#   2  server demanded TLS/CredSSP       -> host is REMEDIATED
#   3  INDETERMINATE -> transport/harness failure. NOT a verdict.
#
# WHAT IS MEASURED.
# MS-RDPBCGR: the client opens with an X.224 Connection Request carrying an
# RDP_NEG_REQ whose requestedProtocols says which security layers it can do.
# The server answers inside an X.224 Connection Confirm with either
#   RDP_NEG_RSP     (type 0x02) selectedProtocol PROTOCOL_RDP 0x0 / SSL 0x1 /
#                               HYBRID 0x2 / HYBRID_EX 0x8
#   RDP_NEG_FAILURE (type 0x03) failureCode, e.g. SSL_REQUIRED_BY_SERVER 0x1,
#                               HYBRID_REQUIRED_BY_SERVER 0x5
# The probe asks for PROTOCOL_RDP and nothing else. Being granted it means the
# listener will carry a Standard RDP Security session with no CredSSP in front
# of it; being refused means NLA is enforced.
#
# MEASURED ON META3WIN, same host, UserAuthentication/SecurityLayer flipped,
# byte offsets absolute in the 19-byte reply:
#   UA=1 SL=2  03-00-00-13 0E D0 00-00 12-34 00 | 03 00 08-00 05-00-00-00
#              -> RDP_NEG_FAILURE, HYBRID_REQUIRED_BY_SERVER
#   UA=0 SL=1  03-00-00-13 0E D0 00-00 12-34 00 | 02 1F 08-00 00-00-00-00
#              -> RDP_NEG_RSP, selectedProtocol = PROTOCOL_RDP
# The negotiation structure begins at offset 11, after TPKT(4) + the 7-byte
# X.224 Connection Confirm.
#
# WHY THE PREVIOUS REVISION MEASURED NOTHING -- MEASURED, NOT ASSUMED, AND IT IS
# NOT THE MISSING-NBSS BUG FROM SCENARIOS 10 AND 11. RDP has no NBSS layer. Its
# exact bytes were replayed against META3WIN in both states and drew
# ConnectionReset in both. Two independent defects:
#   * IT NEVER SENT A CONNECTION REQUEST. In an X.224 TPDU byte 4 is the length
#     indicator and byte 5 is the TPDU code -- 0xE0 for CR. The old packet put
#     0x0E at byte 4 (correct only by coincidence, as an LI of 14) and left byte
#     5 at 0x00, which is not a TPDU code, so the listener reset before any
#     negotiation logic ran. The rest was garbage too: an invented "called TSAP"
#     of 03 00 00 'PORT' 00 00 00 00 that is not in MS-RDPBCGR, a TPKT length of
#     26 for a 19-byte PDU, and an RDP_NEG_REQ written at offset 17 over bytes
#     the same script had already written.
#   * ITS RESPONSE OFFSETS WERE WRONG BY FOUR. It read the X.224 TPDU code at
#     offset 4 (that is the LI, 0x0E) and the negotiation type at offset 15
#     (that is inside failureCode). It also called 0xE0 "Disconnect" -- 0xE0 is
#     Connection Request; Disconnect Request is 0x80. So a correct reply would
#     still have been misgraded.
#   * It treated SSL_NOT_ALLOWED_BY_SERVER (0x2) as proof of NLA. That code
#     means the server CANNOT do TLS, which is the opposite claim.
param(
    [string] $TargetHost = '127.0.0.1',
    [int]    $Port       = 3389,
    [int]    $TimeoutMs  = 5000
)

$ErrorActionPreference = 'Stop'

$EXIT_VULNERABLE    = 0
$EXIT_REMEDIATED    = 2
$EXIT_INDETERMINATE = 3

$PROTOCOL_RDP       = 0x00000000
$PROTOCOL_SSL       = 0x00000001
$PROTOCOL_HYBRID    = 0x00000002
$PROTOCOL_HYBRID_EX = 0x00000008

$TYPE_NEG_RSP     = 0x02
$TYPE_NEG_FAILURE = 0x03

$X224_CC = 0xD0   # Connection Confirm
$X224_DR = 0x80   # Disconnect Request

function Get-ProtocolName {
    param([uint32] $P)
    switch ($P) {
        $PROTOCOL_RDP       { return 'PROTOCOL_RDP' }
        $PROTOCOL_SSL       { return 'PROTOCOL_SSL' }
        $PROTOCOL_HYBRID    { return 'PROTOCOL_HYBRID (CredSSP/NLA)' }
        $PROTOCOL_HYBRID_EX { return 'PROTOCOL_HYBRID_EX' }
        default             { return ('0x{0:X8}' -f $P) }
    }
}

function Get-FailureName {
    param([uint32] $C)
    switch ($C) {
        1 { return 'SSL_REQUIRED_BY_SERVER' }
        2 { return 'SSL_NOT_ALLOWED_BY_SERVER' }
        3 { return 'SSL_CERT_NOT_ON_SERVER' }
        4 { return 'INCONSISTENT_FLAGS' }
        5 { return 'HYBRID_REQUIRED_BY_SERVER' }
        6 { return 'SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER' }
        default { return ('0x{0:X8}' -f $C) }
    }
}

function Read-Exactly {
    param($Stream, [int] $Count)
    $buf = New-Object byte[] $Count
    $off = 0
    while ($off -lt $Count) {
        $n = $Stream.Read($buf, $off, $Count - $off)
        if ($n -le 0) { return $null }
        $off += $n
    }
    return ,$buf
}

function Get-SocketOutcome {
    param($ErrorRecord)
    $ex = $ErrorRecord.Exception
    while ($ex -and -not ($ex -is [System.Net.Sockets.SocketException])) { $ex = $ex.InnerException }
    if (-not $ex) { return @{ Outcome = 'error'; Detail = $ErrorRecord.Exception.Message } }
    switch ($ex.SocketErrorCode) {
        'ConnectionReset'   { return @{ Outcome = 'reset';   Detail = 'ConnectionReset' } }
        'ConnectionAborted' { return @{ Outcome = 'reset';   Detail = 'ConnectionAborted' } }
        'TimedOut'          { return @{ Outcome = 'timeout'; Detail = 'TimedOut' } }
        default             { return @{ Outcome = 'error';   Detail = "$($ex.SocketErrorCode)" } }
    }
}

function New-X224ConnectionRequest {
    # TPKT(4) + X.224 Class 0 Connection Request(7) + RDP_NEG_REQ(8) = 19 bytes.
    #
    #   0      0x03 TPKT version 3
    #   1      0x00 reserved
    #   2-3    total PDU length, BIG-endian  = 19
    #   4      LI, length of the X.224 TPDU after this byte = 14
    #   5      0xE0 CR TPDU + credit 0
    #   6-7    destination reference = 0
    #   8-9    source reference = 0
    #   10     class / options = 0
    #   11     RDP_NEG_REQ type = 0x01
    #   12     flags = 0
    #   13-14  length = 8, LITTLE-endian (the TPKT length above is big-endian;
    #          they genuinely differ, and mixing them up is a classic bug here)
    #   15-18  requestedProtocols, LITTLE-endian
    #
    # No routing token and no "Cookie: mstshash=" is sent. Both are optional per
    # MS-RDPBCGR 2.2.1.1 and only matter to a Connection Broker.
    param([uint32] $RequestedProtocols)

    $buf = New-Object byte[] 19
    $buf[0] = 0x03; $buf[1] = 0x00
    $buf[2] = 0x00; $buf[3] = 0x13
    $buf[4] = 0x0E; $buf[5] = 0xE0
    $buf[6] = 0x00; $buf[7] = 0x00
    $buf[8] = 0x00; $buf[9] = 0x00
    $buf[10] = 0x00
    $buf[11] = 0x01
    $buf[12] = 0x00
    $buf[13] = 0x08; $buf[14] = 0x00
    $buf[15] = [byte]( $RequestedProtocols         -band 0xFF)
    $buf[16] = [byte](($RequestedProtocols -shr 8)  -band 0xFF)
    $buf[17] = [byte](($RequestedProtocols -shr 16) -band 0xFF)
    $buf[18] = [byte](($RequestedProtocols -shr 24) -band 0xFF)
    return ,$buf
}

function Invoke-X224Exchange {
    # One connection: send a Connection Request, read one complete TPKT frame.
    # Returns the transport outcome and, on 'response', the whole frame.
    param([uint32] $RequestedProtocols)

    $result = @{ Outcome = 'error'; Detail = ''; Frame = $null }
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $client.ReceiveTimeout = $TimeoutMs
        $client.SendTimeout    = $TimeoutMs

        $iar = $client.BeginConnect($TargetHost, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            $result.Outcome = 'connect-timeout'
            return $result
        }
        try { $client.EndConnect($iar) }
        catch [System.Net.Sockets.SocketException] {
            $result.Outcome = 'connect-failed'
            $result.Detail  = "$($_.Exception.SocketErrorCode)"
            return $result
        }

        $stream = $client.GetStream()
        $req = New-X224ConnectionRequest $RequestedProtocols
        $stream.Write($req, 0, $req.Length)
        $stream.Flush()

        $hdr = Read-Exactly $stream 4
        if ($null -eq $hdr) {
            $result.Outcome = 'closed'
            $result.Detail  = 'server closed before sending a TPKT header'
            return $result
        }
        if ($hdr[0] -ne 0x03) {
            $result.Outcome = 'malformed'
            $result.Detail  = ('TPKT version 0x{0:X2}, expected 0x03' -f $hdr[0])
            return $result
        }
        # TPKT length is BIG-endian and counts the 4-byte header itself.
        $total = ($hdr[2] -shl 8) -bor $hdr[3]
        if ($total -lt 7 -or $total -gt 8192) {
            $result.Outcome = 'malformed'
            $result.Detail  = "TPKT length $total"
            return $result
        }
        $rest = Read-Exactly $stream ($total - 4)
        if ($null -eq $rest) {
            $result.Outcome = 'closed'
            $result.Detail  = 'server closed mid-TPKT'
            return $result
        }
        $frame = New-Object byte[] $total
        [Array]::Copy($hdr, 0, $frame, 0, 4)
        [Array]::Copy($rest, 0, $frame, 4, $total - 4)
        $result.Outcome = 'response'
        $result.Frame   = $frame
        return $result
    }
    catch {
        $o = Get-SocketOutcome $_
        $result.Outcome = $o.Outcome
        $result.Detail  = $o.Detail
        return $result
    }
    finally {
        try { $client.Close() } catch { }
    }
}

function Read-X224Response {
    # Decode a TPKT frame into { Kind; Value; Detail }. Kind is one of
    # 'neg-rsp' | 'neg-failure' | 'bare-cc' | 'disconnect' | 'unknown'.
    param([byte[]] $Frame)

    $hex = [BitConverter]::ToString($Frame)
    if ($Frame.Length -lt 7) {
        return @{ Kind = 'unknown'; Detail = "frame too short ($($Frame.Length) bytes): $hex" }
    }
    $li   = $Frame[4]
    $code = $Frame[5]
    if ($code -eq $X224_DR) {
        return @{ Kind = 'disconnect'; Detail = "X.224 Disconnect Request (0x80): $hex" }
    }
    if ($code -ne $X224_CC) {
        return @{ Kind = 'unknown'; Detail = ('X.224 TPDU code 0x{0:X2}, expected 0xD0 Connection Confirm: {1}' -f $code, $hex) }
    }
    # X.224 CC is 7 bytes (LI + code + 2 + 2 + 1); LI counts everything after
    # itself, so LI = 6 means a bare Connection Confirm with no RDP negotiation
    # structure. Anything longer carries one, starting at offset 11.
    if ($li -le 6 -or $Frame.Length -lt 19) {
        return @{ Kind = 'bare-cc'; Detail = "X.224 Connection Confirm with no RDP negotiation structure (LI=$li, $($Frame.Length) bytes): $hex" }
    }
    $type = $Frame[11]
    $val  = [BitConverter]::ToUInt32($Frame, 15)
    if ($type -eq $TYPE_NEG_RSP) {
        return @{ Kind = 'neg-rsp'; Value = $val; Detail = $hex }
    }
    if ($type -eq $TYPE_NEG_FAILURE) {
        return @{ Kind = 'neg-failure'; Value = $val; Detail = $hex }
    }
    return @{ Kind = 'unknown'; Detail = ('RDP negotiation type 0x{0:X2} is neither RSP (0x02) nor FAILURE (0x03): {1}' -f $type, $hex) }
}

function Test-RdpListenerAlive {
    # Liveness control. Asks for PROTOCOL_SSL|PROTOCOL_HYBRID, which this server
    # grants in BOTH states -- measured on META3WIN: selectedProtocol =
    # PROTOCOL_HYBRID with UA=1/SL=2 and with UA=0/SL=1 alike. So it proves the
    # listener is speaking RDP without telling us anything about the NLA policy.
    # Without it a reset on the plain-RDP request would be unreadable: "the
    # server refuses Standard RDP Security" and "nothing is listening on 3389"
    # are opposite conclusions from the same observation.
    param([string] $Label)

    $r = Invoke-X224Exchange ($PROTOCOL_SSL -bor $PROTOCOL_HYBRID)
    if ($r.Outcome -ne 'response') {
        Write-Host "[rdp-nla-probe] $Label FAILED: $($r.Outcome) $($r.Detail)"
        return $false
    }
    $p = Read-X224Response $r.Frame
    if ($p.Kind -eq 'neg-rsp') {
        Write-Host "[rdp-nla-probe] $Label OK: listener negotiated $(Get-ProtocolName $p.Value)"
        return $true
    }
    if ($p.Kind -eq 'neg-failure' -or $p.Kind -eq 'bare-cc') {
        # Still a well-formed RDP answer, so the listener is provably alive.
        Write-Host "[rdp-nla-probe] $Label OK: listener answered X.224 ($($p.Kind))"
        return $true
    }
    Write-Host "[rdp-nla-probe] $Label FAILED: $($p.Detail)"
    return $false
}

# ----------------------------------------------------------------------------
Write-Host "[rdp-nla-probe] target=${TargetHost}:${Port} timeout=${TimeoutMs}ms"

if (-not (Test-RdpListenerAlive 'liveness control (requestedProtocols=SSL|HYBRID)')) {
    Write-Host "[rdp-nla-probe] INDETERMINATE: nothing is answering RDP on ${TargetHost}:${Port}, so a refusal of plain RDP cannot be told apart from a dead listener."
    exit $EXIT_INDETERMINATE
}

# --- The measurement: ask for Standard RDP Security and nothing else. ---
$m = Invoke-X224Exchange $PROTOCOL_RDP
Write-Host "[rdp-nla-probe] plain-RDP request transport outcome: $($m.Outcome) $($m.Detail)"

if ($m.Outcome -eq 'response') {
    $p = Read-X224Response $m.Frame
    switch ($p.Kind) {
        'neg-rsp' {
            if ($p.Value -eq $PROTOCOL_RDP) {
                Write-Host "[rdp-nla-probe] VULNERABLE: server selected PROTOCOL_RDP -- Standard RDP Security accepted with no CredSSP. $($p.Detail)"
                exit $EXIT_VULNERABLE
            }
            Write-Host "[rdp-nla-probe] REMEDIATED: server refused to stay on plain RDP and upgraded to $(Get-ProtocolName $p.Value). $($p.Detail)"
            exit $EXIT_REMEDIATED
        }
        'neg-failure' {
            $name = Get-FailureName $p.Value
            if ($p.Value -eq 1 -or $p.Value -eq 5 -or $p.Value -eq 6) {
                Write-Host "[rdp-nla-probe] REMEDIATED: server rejected plain RDP with $name. $($p.Detail)"
                exit $EXIT_REMEDIATED
            }
            # 2 = SSL_NOT_ALLOWED_BY_SERVER, 3 = SSL_CERT_NOT_ON_SERVER,
            # 4 = INCONSISTENT_FLAGS. None of these is the server demanding NLA;
            # they describe a server that cannot do TLS or a malformed request,
            # so none of them may be graded as remediation.
            Write-Host "[rdp-nla-probe] INDETERMINATE: RDP_NEG_FAILURE $name is not a statement that NLA is required. $($p.Detail)"
            exit $EXIT_INDETERMINATE
        }
        'bare-cc' {
            # The server confirmed the connection and demanded no upgrade. That
            # is acceptance of Standard RDP Security.
            Write-Host "[rdp-nla-probe] VULNERABLE: server confirmed the connection without demanding TLS/CredSSP. $($p.Detail)"
            exit $EXIT_VULNERABLE
        }
        default {
            Write-Host "[rdp-nla-probe] INDETERMINATE: $($p.Detail)"
            exit $EXIT_INDETERMINATE
        }
    }
}

if ($m.Outcome -eq 'reset' -or $m.Outcome -eq 'closed' -or $m.Outcome -eq 'timeout') {
    # The listener took the connection and gave nothing back. That is a refusal
    # of plain RDP ONLY if it is still serving; re-prove that now, because a
    # listener that died mid-probe produces the identical symptom.
    if (-not (Test-RdpListenerAlive 'liveness re-check after the plain-RDP attempt')) {
        Write-Host "[rdp-nla-probe] INDETERMINATE: the listener stopped serving during the probe, so the dropped plain-RDP connection proves nothing."
        exit $EXIT_INDETERMINATE
    }
    Write-Host "[rdp-nla-probe] REMEDIATED: server dropped the plain-RDP request ($($m.Outcome)) while still negotiating TLS/CredSSP on the same port."
    exit $EXIT_REMEDIATED
}

Write-Host "[rdp-nla-probe] INDETERMINATE: transport failure '$($m.Outcome)' ($($m.Detail)) is a harness fault, not a statement about the NLA policy."
exit $EXIT_INDETERMINATE
