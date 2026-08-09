# smb1_probe.ps1 -- live SMB1 NEGOTIATE probe for meta3/windows-vm scenario 10.
#
# EXIT CODES (consumed by verify-poc.ps1):
#   0  SMB1 NEGOTIATE ACCEPTED    -> host is VULNERABLE
#   2  SMB1 NEGOTIATE REFUSED     -> host is REMEDIATED
#   3  INDETERMINATE              -> transport/harness failure. NOT a verdict.
#
# WHY THE SMB2 BASELINE EXISTS.
# A TCP reset is what this server sends when it REFUSES SMB1 -- and also what
# the stack sends when nothing is listening on 445 at all, when the service
# died, or when a firewall ate the connection. Those are opposite conclusions
# from an identical observation, so a reset on its own cannot be graded. This
# probe therefore negotiates SMB2 FIRST on its own connection. Only once the
# host has provably answered SMB on this port does a subsequent SMB1 reset mean
# "this server refuses SMB1"; if the SMB2 baseline fails the probe reports
# INDETERMINATE instead of guessing. When the SMB1 attempt is dropped, SMB2 is
# re-negotiated afterwards as well, so "the listener went away mid-probe" is
# also caught rather than being scored as a refusal.
#
# WHY THE DIALECT LIST IS SMB1-ONLY.
# The previous revision offered "SMB 2.002" and "SMB 2.???" inside the SMB1
# NEGOTIATE. That is a multi-protocol negotiate: a host with SMB1 ENABLED
# answers it with an SMB2 response (0xFE 'SMB') because SMB2 is the better
# dialect on offer -- which is byte-for-byte what a host with SMB1 DISABLED
# does. Offering only SMB1 dialects removes that escape hatch, so an accepted
# reply can only mean the SMB1 dialect itself was served.
#
# WHY THE FRAMING CHANGED.
# Direct-hosted SMB on 445 still requires the 4-byte NetBIOS Session Service
# header (type 0x00 + 24-bit big-endian length) in front of every message. The
# previous revision wrote the bare SMB header, so byte 0 (0xFF) was read as an
# NBSS message type, which is not a valid one; srvnet reset the connection
# before any dialect logic ran. That is why the old probe errored identically
# in the vulnerable and the remediated state -- it never performed a negotiate
# at all. Its SMB1 request was malformed in three further ways: a 24-byte
# header (the SMB1 header is 32 bytes), no WordCount/ByteCount, and dialect
# strings with no 0x02 BufferFormat prefix.
param(
    [string] $TargetHost = '127.0.0.1',
    [int]    $Port       = 445,
    [int]    $TimeoutMs  = 5000
)

$ErrorActionPreference = 'Stop'

$EXIT_VULNERABLE    = 0
$EXIT_REMEDIATED    = 2
$EXIT_INDETERMINATE = 3

# SMB1 dialects offered, in wire order. The response's DialectIndex indexes
# into exactly this list.
$Smb1Dialects = @(
    'PC NETWORK PROGRAM 1.0',
    'LANMAN1.0',
    'Windows for Workgroups 3.1a',
    'LM1.2X002',
    'LANMAN2.1',
    'NT LM 0.12'
)

function New-NbssFrame {
    # 4-byte NetBIOS Session Service header: type 0x00 (session message) plus a
    # 24-bit big-endian payload length. Mandatory on 445, not just on 139.
    param([byte[]] $Payload)
    $frame = New-Object byte[] (4 + $Payload.Length)
    $frame[0] = 0x00
    $frame[1] = [byte](($Payload.Length -shr 16) -band 0xFF)
    $frame[2] = [byte](($Payload.Length -shr 8)  -band 0xFF)
    $frame[3] = [byte]( $Payload.Length          -band 0xFF)
    [Array]::Copy($Payload, 0, $frame, 4, $Payload.Length)
    return ,$frame
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
    # Map an exception raised on a connected socket to a transport outcome.
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

function Invoke-SmbExchange {
    # One connection: connect, send a single NBSS-framed SMB message, read one
    # NBSS-framed reply. Returns the transport outcome and, on 'response', the
    # SMB payload with the NBSS header stripped.
    param([byte[]] $Payload)

    $result = @{ Outcome = 'error'; Detail = ''; Payload = $null }
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
        $frame  = New-NbssFrame $Payload
        $stream.Write($frame, 0, $frame.Length)
        $stream.Flush()

        $hdr = Read-Exactly $stream 4
        if ($null -eq $hdr) {
            $result.Outcome = 'closed'
            $result.Detail  = 'server closed before sending an NBSS header'
            return $result
        }
        if ($hdr[0] -ne 0x00) {
            $result.Outcome = 'malformed'
            $result.Detail  = ('NBSS type 0x{0:X2}' -f $hdr[0])
            return $result
        }
        $len = ($hdr[1] -shl 16) -bor ($hdr[2] -shl 8) -bor $hdr[3]
        if ($len -lt 4 -or $len -gt 262144) {
            $result.Outcome = 'malformed'
            $result.Detail  = "NBSS length $len"
            return $result
        }
        $body = Read-Exactly $stream $len
        if ($null -eq $body) {
            $result.Outcome = 'closed'
            $result.Detail  = 'server closed mid-message'
            return $result
        }
        $result.Outcome = 'response'
        $result.Payload = $body
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

function New-Smb2NegotiateRequest {
    # SMB2 NEGOTIATE. Dialects 0x0202..0x0302 only: 0x0311 (SMB 3.1.1) would
    # require negotiate contexts, and this message exists purely to prove the
    # port answers SMB -- not to establish a session.
    $dialects = @(0x0202, 0x0210, 0x0300, 0x0302)
    $buf = New-Object byte[] (64 + 36 + (2 * $dialects.Count))

    # SMB2 header (64 bytes); every field not set below is legitimately zero.
    $buf[0] = 0xFE; $buf[1] = 0x53; $buf[2] = 0x4D; $buf[3] = 0x42  # 0xFE 'SMB'
    $buf[4]  = 64          # StructureSize = 64
    $buf[12] = 0x00        # Command = SMB2 NEGOTIATE (0x0000)
    $buf[14] = 1           # CreditRequest = 1

    # NEGOTIATE request body at offset 64.
    $b = 64
    $buf[$b]     = 36                       # StructureSize = 36
    $buf[$b + 2] = [byte]$dialects.Count    # DialectCount
    $buf[$b + 4] = 1                        # SecurityMode = SIGNING_ENABLED
    [Array]::Copy([guid]::NewGuid().ToByteArray(), 0, $buf, $b + 12, 16)  # ClientGuid
    $d = $b + 36
    foreach ($dia in $dialects) {
        $buf[$d]     = [byte]( $dia        -band 0xFF)
        $buf[$d + 1] = [byte](($dia -shr 8) -band 0xFF)
        $d += 2
    }
    return ,$buf
}

function New-Smb1NegotiateRequest {
    # SMB_COM_NEGOTIATE with an SMB1-only dialect list.
    $bytes = New-Object System.Collections.Generic.List[byte]
    foreach ($d in $Smb1Dialects) {
        $bytes.Add(0x02)   # BufferFormat = Dialect
        foreach ($c in [System.Text.Encoding]::ASCII.GetBytes($d)) { $bytes.Add($c) }
        $bytes.Add(0x00)   # null terminator
    }
    $dialectBytes = $bytes.ToArray()

    $buf = New-Object byte[] (32 + 3 + $dialectBytes.Length)
    # SMB1 header is 32 bytes, not 24.
    $buf[0] = 0xFF; $buf[1] = 0x53; $buf[2] = 0x4D; $buf[3] = 0x42  # 0xFF 'SMB'
    $buf[4]  = 0x72        # SMB_COM_NEGOTIATE
    # bytes 5-8 NTStatus = 0
    $buf[9]  = 0x18        # Flags: CASE_INSENSITIVE | CANONICALIZED_PATHS
    $buf[10] = 0x01        # Flags2 low  \ 0xC801 = UNICODE | NT_STATUS
    $buf[11] = 0xC8        # Flags2 high /          | EXTENDED_SECURITY | LONG_NAMES
    $buf[24] = 0xFF; $buf[25] = 0xFF   # TID = 0xFFFF
    $buf[26] = 0xFF; $buf[27] = 0xFE   # PIDLow
    # Request body: WordCount(1) = 0, ByteCount(2), then the dialect buffer.
    $buf[32] = 0x00
    $buf[33] = [byte]( $dialectBytes.Length        -band 0xFF)
    $buf[34] = [byte](($dialectBytes.Length -shr 8) -band 0xFF)
    [Array]::Copy($dialectBytes, 0, $buf, 35, $dialectBytes.Length)
    return ,$buf
}

function Test-SmbMarker {
    param([byte[]] $Payload, [byte] $First)
    if ($Payload.Length -lt 4) { return $false }
    return ($Payload[0] -eq $First -and $Payload[1] -eq 0x53 -and
            $Payload[2] -eq 0x4D  -and $Payload[3] -eq 0x42)
}

function Get-Smb1NegotiateVerdict {
    # 'accepted' | 'refused' | 'indeterminate', from a parsed SMB1 reply.
    param([byte[]] $Payload)

    if (Test-SmbMarker $Payload 0xFE) {
        return @{ Verdict = 'refused'
                  Detail  = 'server answered SMB2 (0xFE SMB) to an SMB1-only NEGOTIATE' }
    }
    if (-not (Test-SmbMarker $Payload 0xFF)) {
        $head = [BitConverter]::ToString($Payload, 0, [Math]::Min(8, $Payload.Length))
        return @{ Verdict = 'indeterminate'; Detail = "unrecognised protocol marker $head" }
    }
    if ($Payload[4] -ne 0x72) {
        return @{ Verdict = 'indeterminate'
                  Detail  = ('SMB1 reply to a different command (0x{0:X2})' -f $Payload[4]) }
    }
    $status = [BitConverter]::ToUInt32($Payload, 5)
    if ($status -ne 0) {
        return @{ Verdict = 'refused'; Detail = ('SMB1 NEGOTIATE returned NTSTATUS 0x{0:X8}' -f $status) }
    }
    if ($Payload.Length -lt 35) {
        return @{ Verdict = 'indeterminate'; Detail = "SMB1 reply truncated ($($Payload.Length) bytes)" }
    }
    if ($Payload[32] -lt 1) {
        return @{ Verdict = 'refused'; Detail = 'SMB1 NEGOTIATE response carried no DialectIndex (WordCount=0)' }
    }
    $idx = [BitConverter]::ToUInt16($Payload, 33)
    if ($idx -eq 0xFFFF) {
        return @{ Verdict = 'refused'; Detail = 'DialectIndex=0xFFFF (no offered SMB1 dialect accepted)' }
    }
    if ($idx -ge $Smb1Dialects.Count) {
        return @{ Verdict = 'indeterminate'; Detail = "DialectIndex=$idx is outside the offered list" }
    }
    return @{ Verdict = 'accepted'; Detail = "server selected SMB1 dialect '$($Smb1Dialects[$idx])' (index $idx)" }
}

# ----------------------------------------------------------------------------
Write-Host "[smb1-probe] target=${TargetHost}:${Port} timeout=${TimeoutMs}ms"

# --- Baseline: is anything answering SMB on this port at all? ---
$pre = Invoke-SmbExchange (New-Smb2NegotiateRequest)
if ($pre.Outcome -ne 'response' -or -not (Test-SmbMarker $pre.Payload 0xFE)) {
    Write-Host "[smb1-probe] SMB2 baseline FAILED: $($pre.Outcome) $($pre.Detail)"
    Write-Host "[smb1-probe] INDETERMINATE: nothing is answering SMB on ${TargetHost}:${Port}, so a refusal of SMB1 cannot be told apart from a dead listener."
    exit $EXIT_INDETERMINATE
}
Write-Host ('[smb1-probe] SMB2 baseline OK: host answered NEGOTIATE with dialect 0x{0:X4}' -f `
    [BitConverter]::ToUInt16($pre.Payload, 68))

# --- The measurement: an SMB1-only NEGOTIATE on a fresh connection. ---
$smb1 = Invoke-SmbExchange (New-Smb1NegotiateRequest)
Write-Host "[smb1-probe] SMB1 NEGOTIATE transport outcome: $($smb1.Outcome) $($smb1.Detail)"

if ($smb1.Outcome -eq 'response') {
    $v = Get-Smb1NegotiateVerdict $smb1.Payload
    switch ($v.Verdict) {
        'accepted' {
            Write-Host "[smb1-probe] VULNERABLE: SMB1 NEGOTIATE accepted -- $($v.Detail)"
            exit $EXIT_VULNERABLE
        }
        'refused' {
            Write-Host "[smb1-probe] REMEDIATED: SMB1 NEGOTIATE refused -- $($v.Detail)"
            exit $EXIT_REMEDIATED
        }
        default {
            Write-Host "[smb1-probe] INDETERMINATE: $($v.Detail)"
            exit $EXIT_INDETERMINATE
        }
    }
}

if ($smb1.Outcome -eq 'reset' -or $smb1.Outcome -eq 'closed' -or $smb1.Outcome -eq 'timeout') {
    # The server took the connection and then gave nothing back. That is a
    # refusal ONLY if the same port still serves SMB; re-prove it now, because
    # a listener that died during the probe produces the identical symptom.
    $post = Invoke-SmbExchange (New-Smb2NegotiateRequest)
    if ($post.Outcome -ne 'response' -or -not (Test-SmbMarker $post.Payload 0xFE)) {
        Write-Host "[smb1-probe] SMB2 re-check after the SMB1 attempt FAILED: $($post.Outcome) $($post.Detail)"
        Write-Host "[smb1-probe] INDETERMINATE: the listener stopped serving during the probe, so the dropped SMB1 connection proves nothing."
        exit $EXIT_INDETERMINATE
    }
    Write-Host "[smb1-probe] REMEDIATED: server dropped the SMB1 NEGOTIATE ($($smb1.Outcome)) while still answering SMB2 on the same port."
    exit $EXIT_REMEDIATED
}

Write-Host "[smb1-probe] INDETERMINATE: transport failure '$($smb1.Outcome)' ($($smb1.Detail)) is a harness fault, not a statement about SMB1."
exit $EXIT_INDETERMINATE
