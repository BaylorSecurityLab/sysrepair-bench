# smb_signing_probe.ps1 — SMB2 NEGOTIATE + SecurityMode parse
# Exit 0 = signing optional (VULNERABLE — NTLM relay surface)
# Exit 2 = signing required (REMEDIATED)
# Exit 1 = probe error (TCP failure, timeout, malformed response)
param(
    [string]$Host = '127.0.0.1',
    [int]$Port = 445,
    [int]$TimeoutMs = 3000
)

$ErrorActionPreference = 'Stop'

# SMB2 NEGOTIATE Protocol Request — fixed header (32 bytes), dialects appended
# Offset  0 (4):  "FE SMB" — SMB2 ProtocolID marker
# Offset  4 (2):  StructureSize = 0x20 (32) — total fixed header length
# Offset  6 (2):  CreditCharge = 0
# Offset  8 (4):  Status = 0 (no error)
# Offset 12 (2):  CreditRequest = 0
# Offset 14 (2):  Flags = 0
# Offset 16 (2):  SecurityMode = 0x0003 (SMB2_NEGOTIATE_SIGNING_ENABLED + REQUIRED)
# Offset 18 (2):  Capabilities = 0
# Offset 20 (2):  DialectCount = 5
# Offset 22 (2):  Reserved = 0
# Offset 24 (8):  ClientGuid = zeros
# Offset 32 (4):  ClientStartTime = 0
# Offset 36 (4):  ClientSupportedDialects = 0
# Dialects at byte 40+: 5 x 2-byte LE words (0x0202, 0x0210, 0x0300, 0x0302, 0x0311)

$header = New-Object byte[] 40
$header[0] = 0xFE; $header[1] = 0x53; $header[2] = 0x4D; $header[3] = 0x42   # "FE SMB"
$header[4] = 0x20; $header[5] = 0x00                                      # StructureSize = 32
$header[6] = 0x00; $header[7] = 0x00                                      # CreditCharge
$header[8] = 0x00; $header[9] = 0x00; $header[10] = 0x00; $header[11] = 0x00  # Status = 0
$header[12] = 0x00; $header[13] = 0x00                                    # CreditRequest
$header[14] = 0x00; $header[15] = 0x00                                    # Flags = 0
$header[16] = 0x03; $header[17] = 0x00                                    # SecurityMode = signing enabled + required
$header[18] = 0x00; $header[19] = 0x00                                    # Capabilities = 0
$header[20] = 0x05; $header[21] = 0x00                                    # DialectCount = 5
# ClientGuid bytes 24-31 = zeros
# ClientStartTime bytes 32-35 = zeros

# Append 5 dialect words LE (10 bytes): 0x0202, 0x0210, 0x0300, 0x0302, 0x0311
$dialects = @(0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
$dialectBuf = New-Object byte[] 10
for ($i = 0; $i -lt $dialects.Count; $i++) {
    $dialectBuf[$i * 2]     = [byte]($dialects[$i] -band 0xFF)
    $dialectBuf[$i * 2 + 1] = [byte](($dialects[$i] -shr 8) -band 0xFF)
}

$fullBuf = New-Object byte[] ($header.Length + $dialectBuf.Length)
[Array]::Copy($header, 0, $fullBuf, 0, $header.Length)
[Array]::Copy($dialectBuf, 0, $fullBuf, $header.Length, $dialectBuf.Length)

try {
    $client = New-Object System.Net.Sockets.TcpClient
    $client.ReceiveTimeout = $TimeoutMs
    $client.SendTimeout    = $TimeoutMs
    $client.Connect($Host, $Port)
    $stream = $client.GetStream()
    $stream.Write($fullBuf, 0, $fullBuf.Length)
    $stream.Flush()

    # Read minimum 132-byte SMB2 NEGOTIATE Response (64-byte header + 132-byte body)
    $resp = New-Object byte[] 136
    $bytesRead = $stream.Read($resp, 0, 136)
    $client.Close()

    if ($bytesRead -lt 68) {
        Write-Host "probe: short read ($bytesRead bytes, need 68)"
        exit 1
    }

    # Verify SMB2 ProtocolID at offset 0
    if ($resp[0] -ne 0xFE -or $resp[1] -ne 0x53 -or $resp[2] -ne 0x4D -or $resp[3] -ne 0x42) {
        Write-Host "probe: not an SMB2 response: $([BitConverter]::ToString($resp[0..3]))"
        exit 1
    }

    # SecurityMode: SMB2 Header (64 bytes) + NEGOTIATE Response StructureSize (2 bytes, always present)
    #   = bytes 64-65. SecurityMode (2 bytes) at offset 2 of NEGOTIATE Response fields
    #   = byte 66 (low byte) + byte 67 (high byte), little-endian
    $secMode = [int]$resp[66] + ([int][byte]$resp[67] -shl 8)
    $signingRequired = ($secMode -band 0x0002) -ne 0

    if ($signingRequired) {
        Write-Host "probe: SMB2 NEGOTIATE response — signing REQUIRED (bit 1 set)"
        exit 2  # REMEDIATED
    }

    # Signing optional
    Write-Host "probe: SMB2 NEGOTIATE response — signing OPTIONAL (RequireSecuritySignature=$false)"
    exit 0  # VULNERABLE

} catch {
    Write-Host "probe: TCP error — $_"
    exit 1
}