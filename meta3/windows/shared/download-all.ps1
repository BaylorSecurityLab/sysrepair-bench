# Fetch every artifact listed in shared/downloads/manifest.json into shared/downloads/.
# Idempotent: files whose sha256 matches the manifest are skipped. Empty sha256
# means 'pin to whatever we get this time' — the manifest is updated in place
# so subsequent runs verify the same bits.
#
# Usage (from anywhere):
#   pwsh meta3/windows/shared/download-all.ps1
#   pwsh meta3/windows/shared/download-all.ps1 -Refresh   # re-download even if hash matches

[CmdletBinding()]
param(
    [switch]$Refresh
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls

$here       = Split-Path -Parent $MyInvocation.MyCommand.Path
$dlDir      = Join-Path $here 'downloads'
$manifestPath = Join-Path $dlDir 'manifest.json'

if (-not (Test-Path $manifestPath)) {
    throw "manifest not found: $manifestPath"
}

$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
$artifacts = $manifest.artifacts
$updated  = $false

function Get-Sha256 {
    param([string]$Path)
    (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
}

function Download-WithRetry {
    param(
        [string]$Url,
        [string]$Dest,
        [int]$MaxAttempts = 5
    )
    for ($i = 1; $i -le $MaxAttempts; $i++) {
        try {
            # WebClient is markedly faster than Invoke-WebRequest for large files
            # and follows redirects without needing -UseBasicParsing tweaks.
            $wc = New-Object Net.WebClient
            $wc.Headers.Add('User-Agent', 'sysrepair-bench-prefetch/1.0')
            $wc.DownloadFile($Url, $Dest)
            return
        } catch {
            $delay = [Math]::Min(60, [int][Math]::Pow(2, $i))
            Write-Host ("    attempt {0}/{1} failed: {2}; retrying in {3}s" -f $i, $MaxAttempts, $_.Exception.Message, $delay)
            if (Test-Path $Dest) { Remove-Item $Dest -Force }
            Start-Sleep -Seconds $delay
        }
    }
    throw "Giving up on $Url after $MaxAttempts attempts"
}

foreach ($a in $artifacts) {
    $name = $a.name
    $url  = $a.url
    $want = if ($null -ne $a.sha256) { $a.sha256.ToString().ToLowerInvariant() } else { '' }
    $dest = Join-Path $dlDir $name

    Write-Host ("=> {0}" -f $name)

    if ((Test-Path $dest) -and -not $Refresh) {
        $have = Get-Sha256 $dest
        if (-not $want) {
            Write-Host ("   present, pinning sha256 = {0}" -f $have)
            $a.sha256 = $have
            $updated = $true
            continue
        }
        if ($have -eq $want) {
            Write-Host "   already present, sha256 matches"
            continue
        }
        Write-Host ("   present but sha256 mismatch (have {0}, want {1}); re-downloading" -f $have, $want)
        Remove-Item $dest -Force
    }

    Write-Host ("   fetching {0}" -f $url)
    Download-WithRetry -Url $url -Dest $dest

    $have = Get-Sha256 $dest
    Write-Host ("   sha256 = {0}" -f $have)
    if (-not $want) {
        $a.sha256 = $have
        $updated = $true
    } elseif ($have -ne $want) {
        throw "Hash mismatch for $name`: got $have, manifest wants $want"
    }
}

if ($updated) {
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -Path $manifestPath -Encoding utf8
    Write-Host "manifest.json updated with newly-pinned hashes"
}

Write-Host "all artifacts present in $dlDir"
