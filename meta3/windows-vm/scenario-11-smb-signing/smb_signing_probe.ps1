# smb_signing_probe.ps1 -- live SMB2 NEGOTIATE probe for meta3/windows-vm
# scenario 11. Reads the server's message-signing policy off the wire.
#
# EXIT CODES (consumed by verify-poc.ps1):
#   0  SecurityMode WITHOUT SIGNING_REQUIRED -> host is VULNERABLE (relay surface)
#   2  SecurityMode WITH    SIGNING_REQUIRED -> host is REMEDIATED
#   3  INDETERMINATE  -> transport/harness failure. NOT a verdict.
#
# WHAT IS MEASURED, AND WHY IT CANNOT BE INFERRED FROM A CONNECTION OUTCOME.
# A server that only OFFERS signing and a server that REQUIRES it both complete
# the TCP handshake and both answer an SMB2 NEGOTIATE. The difference lives in
# one bit of one field of the NEGOTIATE RESPONSE -- SecurityMode, at offset 2 of
# the response body, i.e. offset 66 of the SMB2 message:
#     0x01 SMB2_NEGOTIATE_SIGNING_ENABLED
#     0x02 SMB2_NEGOTIATE_SIGNING_REQUIRED
# so the probe parses that field. Nothing about connect/reset/timeout is graded
# as a verdict here, because none of those distinguish the two states.
#
# MEASURED ON META3WIN, same host, one setting changed, byte offsets absolute in
# the NBSS-framed reply:
#   RequireSecuritySignature=$true   ... 41-00-03-00-02-03 ...  SecurityMode=0x0003
#   RequireSecuritySignature=$false  ... 41-00-01-00-02-03 ...  SecurityMode=0x0001
# (0x41 = response StructureSize 65, then SecurityMode LE, then DialectRevision
# 0x0302.) That is the discriminator, and it is present in both states -- which
# is exactly what makes this measurable at all.
#
# WHY THE PREVIOUS REVISION MEASURED NOTHING -- MEASURED, NOT ASSUMED.
# It failed identically in the vulnerable and the remediated state. Reproduced
# on META3WIN by replaying its exact bytes in both states:
#   * with the 4-byte NetBIOS Session Service header ..... 174-byte reply
#   * with its bytes exactly (no NBSS header) ............ ConnectionReset
# Direct-hosted SMB on 445 still requires the NBSS header (type 0x00 + 24-bit
# big-endian length) in front of every message. Without it byte 0 (0xFE) is read
# as an NBSS message type, which is not a valid one, and srvnet resets the
# connection before any NEGOTIATE processing happens. The request was malformed
# in three further ways regardless: it wrote StructureSize 0x20 where the SMB2
# header requires 64, it packed the NEGOTIATE request body fields (SecurityMode,
# DialectCount, ClientGuid) into SMB2 *header* offsets instead of into a 36-byte
# body at offset 64, and it sent a 40-byte message where the header alone is 64.
# Its response parsing was off by the same 4 bytes it never sent, so even a
# successful reply would have been read from the wrong offsets.
param(
    [string] $TargetHost = '127.0.0.1',
    [int]    $Port       = 445,
    [int]    $TimeoutMs  = 5000
)

$ErrorActionPreference = 'Stop'

$EXIT_VULNERABLE    = 0
$EXIT_REMEDIATED    = 2
$EXIT_INDETERMINATE = 3

$SMB2_NEGOTIATE_SIGNING_ENABLED  = 0x0001
$SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002

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
    # SMB2 NEGOTIATE: 64-byte header + 36-byte body + 2 bytes per dialect.
    # Dialects 0x0202..0x0302 only. 0x0311 (SMB 3.1.1) is deliberately NOT
    # offered: it requires NegotiateContexts appended to the request, and this
    # message exists to read SecurityMode, not to establish a session.
    #
    # The client's own SecurityMode is set to SIGNING_ENABLED, never REQUIRED.
    # The response reports the SERVER's policy either way, but announcing a
    # client requirement would be a claim about the wrong end of the connection.
    $dialects = @(0x0202, 0x0210, 0x0300, 0x0302)
    $buf = New-Object byte[] (64 + 36 + (2 * $dialects.Count))

    $buf[0] = 0xFE; $buf[1] = 0x53; $buf[2] = 0x4D; $buf[3] = 0x42  # 0xFE 'SMB'
    $buf[4]  = 64          # header StructureSize = 64
    $buf[12] = 0x00        # Command = SMB2 NEGOTIATE (0x0000)
    $buf[14] = 1           # CreditRequest = 1

    $b = 64
    $buf[$b]     = 36                       # body StructureSize = 36
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

function Test-Smb2Marker {
    param([byte[]] $Payload)
    if ($null -eq $Payload -or $Payload.Length -lt 4) { return $false }
    return ($Payload[0] -eq 0xFE -and $Payload[1] -eq 0x53 -and
            $Payload[2] -eq 0x4D -and $Payload[3] -eq 0x42)
}

function Get-SigningVerdict {
    # 'required' | 'optional' | 'indeterminate', from a parsed SMB2 reply.
    param([byte[]] $Payload)

    if (-not (Test-Smb2Marker $Payload)) {
        $head = [BitConverter]::ToString($Payload, 0, [Math]::Min(8, $Payload.Length))
        return @{ Verdict = 'indeterminate'; Detail = "not an SMB2 reply (leading bytes $head)" }
    }
    $command = [BitConverter]::ToUInt16($Payload, 12)
    if ($command -ne 0) {
        return @{ Verdict = 'indeterminate'; Detail = ('reply to command 0x{0:X4}, not NEGOTIATE' -f $command) }
    }
    $status = [BitConverter]::ToUInt32($Payload, 8)
    if ($status -ne 0) {
        # The server rejected the negotiate itself. That is a statement about
        # this request, not about the signing policy, so it is not a verdict.
        return @{ Verdict = 'indeterminate'; Detail = ('NEGOTIATE returned NTSTATUS 0x{0:X8}' -f $status) }
    }
    if ($Payload.Length -lt 72) {
        return @{ Verdict = 'indeterminate'; Detail = "reply truncated ($($Payload.Length) bytes, need 72)" }
    }
    $bodySize = [BitConverter]::ToUInt16($Payload, 64)
    if ($bodySize -ne 65) {
        return @{ Verdict = 'indeterminate'; Detail = "NEGOTIATE response StructureSize=$bodySize, expected 65" }
    }
    $secMode  = [BitConverter]::ToUInt16($Payload, 66)
    $dialect  = [BitConverter]::ToUInt16($Payload, 68)
    $enabled  = ($secMode -band $SMB2_NEGOTIATE_SIGNING_ENABLED)  -ne 0
    $required = ($secMode -band $SMB2_NEGOTIATE_SIGNING_REQUIRED) -ne 0
    $desc = ('SecurityMode=0x{0:X4} (SIGNING_ENABLED={1}, SIGNING_REQUIRED={2}) on dialect 0x{3:X4}' -f `
             $secMode, $enabled, $required, $dialect)

    if ($required) { return @{ Verdict = 'required'; Detail = $desc } }
    return @{ Verdict = 'optional'; Detail = $desc }
}

# ----------------------------------------------------------------------------
Write-Host "[smb-signing-probe] target=${TargetHost}:${Port} timeout=${TimeoutMs}ms"

# The SMB2 NEGOTIATE is BOTH the liveness proof and the measurement: it is a
# call that succeeds in the vulnerable AND the remediated state (measured
# above), and its reply carries the discriminator. So a reset here can only mean
# the listener is not serving -- it can never mean "signing is required" -- and
# it is reported as unmeasurable rather than folded into a verdict. One retry,
# because a single transient would otherwise be indistinguishable from a dead
# listener.
$attempt = 0
$res = $null
while ($attempt -lt 2) {
    $attempt++
    $res = Invoke-SmbExchange (New-Smb2NegotiateRequest)
    if ($res.Outcome -eq 'response') { break }
    Write-Host "[smb-signing-probe] attempt ${attempt}: $($res.Outcome) $($res.Detail)"
    if ($attempt -lt 2) { Start-Sleep -Seconds 2 }
}

if ($res.Outcome -ne 'response') {
    Write-Host "[smb-signing-probe] INDETERMINATE: no SMB2 NEGOTIATE response from ${TargetHost}:${Port} after $attempt attempts ($($res.Outcome) $($res.Detail)). A server that requires signing still answers this message, so a transport failure says nothing about the signing policy."
    exit $EXIT_INDETERMINATE
}

$v = Get-SigningVerdict $res.Payload
switch ($v.Verdict) {
    'required' {
        Write-Host "[smb-signing-probe] REMEDIATED: live server requires SMB signing -- $($v.Detail)"
        exit $EXIT_REMEDIATED
    }
    'optional' {
        Write-Host "[smb-signing-probe] VULNERABLE: live server does NOT require SMB signing -- $($v.Detail)"
        exit $EXIT_VULNERABLE
    }
    default {
        Write-Host "[smb-signing-probe] INDETERMINATE: $($v.Detail)"
        exit $EXIT_INDETERMINATE
    }
}
