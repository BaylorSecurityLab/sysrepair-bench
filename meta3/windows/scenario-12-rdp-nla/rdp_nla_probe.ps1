# rdp_nla_probe.ps1 — TPKT + X.224 Connection Request + RDP Negotiation Request
# Exit 0 = server accepted plain RDP (VULNERABLE — NLA disabled)
# Exit 2 = server rejected plain RDP (REMEDIATED — TLS/CredSSP required)
# Exit 1 = probe error (TCP failure, timeout, malformed response)
param(
    [string]$Host = '127.0.0.1',
    [int]$Port = 3389,
    [int]$TimeoutMs = 3000
)

$ErrorActionPreference = 'Stop'

# Build packet: TPKT (4) + X.224 CR (8) + RDP Negotiation Request (7) = 19 bytes
# TPKT Header (RFC 1006) — Offset 0
#   Byte 0: Version = 3
#   Byte 1: Reserved = 0
#   Byte 2-3: Length (total PDU length) = 19 (0x0013)
# X.224 Connection Request TPDU — Offset 4
#   Byte 4: TPDU type = 0x0E (Connection Request)
#   Byte 5-6: Credit and destination reference = 0x0000
#   Byte 7-8: Source reference = 0x0000
#   Byte 9:  Class and additional options = 0x00
#   Byte 10: Implementation: calling TSAP = 0x03
#   Byte 11: Variable part: called TSAP length = 0x0B
#   Byte 12: Variable part: called TSAP (11 bytes): 03 00 00 50 4F 52 54 00 00 00 00
#   Byte 13-15: Calling TSAP length (0x00) + end
# RDP Negotiation Request (type 0x01) — Offset 17
#   Byte 17: Type = 0x01 (Negotiation Request)
#   Byte 18: Flags = 0x03 (PERSONALITY_TEST | EXTENDED_CLIENT_DATA_SUPPORTED)
#   Byte 19-20: length = 0x0008 (8 bytes for this record, little-endian)
#   Byte 21-24: requestedProtocols = 0x00000000 (PROTOCOL_RDP only — no TLS, no HYBRID)
#   Byte 25-27: padding = 0x000000

$buf = New-Object byte[] 26
$buf[0] = 0x03; $buf[1] = 0x00       # TPKT Version 3, Reserved 0
$buf[2] = 0x00; $buf[3] = 0x13       # TPKT Length = 19 (0x0013)

$buf[4] = 0x0E                        # X.224 Connection Request type
$buf[5] = 0x00; $buf[6] = 0x00        # Credit + dst ref
$buf[7] = 0x00; $buf[8] = 0x00        # src ref
$buf[9] = 0x00                        # class
$buf[10] = 0x03                       # calling TSAP length
$buf[11] = 0x0B                       # called TSAP length = 11
# called TSAP: 03 00 00 50 4F 52 54 00 00 00 00
$buf[12] = 0x03; $buf[13] = 0x00; $buf[14] = 0x00
$buf[15] = 0x50; $buf[16] = 0x4F; $buf[17] = 0x52
$buf[18] = 0x54; $buf[19] = 0x00; $buf[20] = 0x00
$buf[21] = 0x00; $buf[22] = 0x00      # calling TSAP length 0 + padding

# RDP Negotiation Request (type 0x01) starts at byte 17
$buf[17] = 0x01                        # Type = Negotiation Request
$buf[18] = 0x03                        # Flags (PERSONALITY_TEST | EXTENDED_CLIENT_DATA_SUPPORTED)
$buf[19] = 0x08; $buf[20] = 0x00       # length = 8 (little-endian)
# requestedProtocols = 0x00000000 (RDP only)
$buf[21] = 0x00; $buf[22] = 0x00
$buf[23] = 0x00; $buf[24] = 0x00
$buf[25] = 0x00                        # padding

try {
    $client = New-Object System.Net.Sockets.TcpClient
    $client.ReceiveTimeout = $TimeoutMs
    $client.SendTimeout    = $TimeoutMs
    $client.Connect($Host, $Port)
    $stream = $client.GetStream()
    $stream.Write($buf, 0, $buf.Length)
    $stream.Flush()

    # Read response: TPKT (4) + X.224 CR Confirm (11) + RDP Negotiation (8) = 23 bytes minimum
    $resp = New-Object byte[] 32
    $bytesRead = $stream.Read($resp, 0, 32)
    $client.Close()

    if ($bytesRead -lt 4) {
        Write-Host "probe: short read ($bytesRead bytes)"
        exit 1
    }

    # TPKT: verify version=3, read length
    if ($resp[0] -ne 0x03) {
        Write-Host "probe: not a TPKT response (byte 0 = $($resp[0]))"
        exit 1
    }
    $tpktLen = [int]$resp[2] -shl 8 -bor [int]$resp[3]
    if ($bytesRead -lt $tpktLen) {
        Write-Host "probe: TPKT length $tpktLen but only $bytesRead bytes received"
        exit 1
    }

    # X.224: type must be 0xD0 (Connection Confirm) or 0xE0 (Disconnect)
    $x224Type = $resp[4]
    if ($x224Type -eq 0xE0) {
        Write-Host "probe: X.224 Disconnect (0xE0)"
        exit 1
    }
    if ($x224Type -ne 0xD0) {
        Write-Host "probe: unexpected X.224 type 0x$([Convert]::ToString($x224Type, 16))"
        exit 1
    }

    # Skip TPKT(4) + X.224(11) = 15 to reach RDP negotiation data
    $rdpOffset = 15
    if ($bytesRead -le $rdpOffset) {
        Write-Host "probe: no RDP negotiation data in response"
        exit 1
    }

    $rdpType = $resp[$rdpOffset]
    if ($rdpType -eq 0x02) {
        # Negotiation Response: check selectedProtocol
        $protoOffset = $rdpOffset + 5
        if ($protoOffset + 3 -ge $bytesRead) {
            Write-Host "probe: RDP response too short for selectedProtocol"
            exit 1
        }
        $selectedProto = [int]$resp[$protoOffset] `
            -bor ([int]$resp[$protoOffset + 1] -shl 8) `
            -bor ([int]$resp[$protoOffset + 2] -shl 16) `
            -bor ([int]$resp[$protoOffset + 3] -shl 24)

        if ($selectedProto -eq 0x00000000) {
            # Accepted plain RDP — vulnerable
            Write-Host "probe: RDP Negotiation Response — selectedProtocol=RDP (0x00000000); NLA disabled"
            exit 0  # VULNERABLE
        }
        # Protocol was upgraded (SSL or HYBRID) — NLA is enforcing
        Write-Host "probe: RDP Negotiation Response — selectedProtocol=$([Convert]::ToString($selectedProto, 16)); NLA enforced"
        exit 2  # REMEDIATED

    } elseif ($rdpType -eq 0x03) {
        # Negotiation Failure: check failureCode
        $codeOffset = $rdpOffset + 5
        $failureCode = $resp[$codeOffset]
        if ($failureCode -eq 0x02 -or $failureCode -eq 0x05) {
            Write-Host "probe: RDP Negotiation Failure — failureCode=$([Convert]::ToString($failureCode, 16)); NLA required"
            exit 2  # REMEDIATED
        }
        Write-Host "probe: RDP Negotiation Failure — unexpected failureCode=$([Convert]::ToString($failureCode, 16))"
        exit 1

    } else {
        Write-Host "probe: unexpected RDP negotiation type 0x$([Convert]::ToString($rdpType, 16))"
        exit 1
    }

} catch {
    Write-Host "probe: TCP error — $_"
    exit 1
}