# smb1_probe.ps1 — SMB1 NEGOTIATE probe
# Exit 0 = server accepted SMB1 dialect (VULNERABLE)
# Exit 2 = server rejected SMB1 dialect (REMEDIATED)
# Exit 1 = probe error (TCP failure, timeout, short read)
param(
    [string]$Host = '127.0.0.1',
    [int]$Port = 445,
    [int]$TimeoutMs = 3000
)

$ErrorActionPreference = 'Stop'

# Build SMB1 NEGOTIATE Protocol Request (36 bytes)
# Byte[0-3]   : Protocol (0xFF 'SMB') — SMB1 marker
# Byte[4]     : Command 0x72 (SMB_COM_NEGOTIATE)
# Byte[5-9]   : ErrorClass(4) + ErrorCode(4) = 10 zero bytes
# Byte[10]    : Flags 0x00
# Byte[11-12] : Flags2 0x0000
# Byte[13-21] : Reserved (9 zero bytes): PID high(2), Reserved(2), PID low(4), CID(2), UserID(2)
# Byte[22]    : Number of dialects = [dialect count], value 0x08 (8 dialects)
# Byte[23]    : Dialect buffer offset (0x18 = 24 decimal, relative to SMB header start)
# Dialects start at byte 24, null-terminated ASCII strings follow:
$dialects = @(
    "PC NETWORK PROGRAM 1.0",
    "LANMAN1.0",
    "Windows for Workgroups 3.1a",
    "LM1.2X002",
    "LANMAN2.1",
    "NT LM 0.12",
    "SMB 2.002",
    "SMB 2.???"
)
$dialectData = -join ($dialects | ForEach-Object { "$_`0" })

# Build full packet — SMB header (24 bytes) + dialect data
$buf = New-Object byte[] (24 + $dialectData.Length)
$buf[0] = 0xFF; $buf[1] = 0x53; $buf[2] = 0x4D; $buf[3] = 0x42  # "FFSMB"
$buf[4] = 0x72                                            # SMB_COM_NEGOTIATE
$buf[10] = 0x00                                           # Flags
$buf[11] = 0x00; $buf[12] = 0x00                          # Flags2
$buf[22] = [byte]$dialects.Count                          # Number of dialects
$buf[23] = 0x18                                           # Dialect buffer offset = 24
[Array]::Copy([System.Text.Encoding]::ASCII.GetBytes($dialectData), 0, $buf, 24, $dialectData.Length)

try {
    $client = New-Object System.Net.Sockets.TcpClient
    $client.ReceiveTimeout = $TimeoutMs
    $client.SendTimeout    = $TimeoutMs
    $client.Connect($Host, $Port)
    $stream = $client.GetStream()
    $stream.Write($buf, 0, $buf.Length)
    $stream.Flush()

    $resp = New-Object byte[] 4
    $bytesRead = $stream.Read($resp, 0, 4)
    $client.Close()

    if ($bytesRead -lt 4) {
        Write-Host "probe: short read ($bytesRead bytes)"
        exit 1
    }

    # Discriminator: 0xFF 0x53 0x4D 0x42 = server spoke SMB1 (vulnerable)
    if ($resp[0] -eq 0xFF -and $resp[1] -eq 0x53 -and $resp[2] -eq 0x4D -and $resp[3] -eq 0x42) {
        Write-Host "probe: SMB1 NEGOTIATE accepted (server confirmed SMB1 dialect)"
        exit 0  # VULNERABLE
    }

    # 0xFE = server auto-upgraded to SMB2 (SMB1 disabled) — remediated
    if ($resp[0] -eq 0xFE -and $resp[1] -eq 0x53 -and $resp[2] -eq 0x4D -and $resp[3] -eq 0x42) {
        Write-Host "probe: SMB1 rejected; server responded SMB2 (EnableSMB1Protocol=$false)"
        exit 2  # REMEDIATED
    }

    # Unexpected protocol marker
    Write-Host "probe: unexpected response bytes: $([BitConverter]::ToString($resp))"
    exit 1

} catch {
    Write-Host "probe: TCP error — $_"
    exit 1
}