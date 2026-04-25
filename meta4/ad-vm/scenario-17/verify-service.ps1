$ErrorActionPreference = 'Stop'
try {
    $tmp = New-Item -ItemType Directory -Force -Path 'C:\meta4-setup\efs-probe-17'
    $f = Join-Path $tmp 'probe.txt'
    'EFS service probe' | Out-File -FilePath $f -Encoding ascii

    & cipher /e $f | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "cipher /e returned $LASTEXITCODE" }

    & cipher /d $f | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "cipher /d returned $LASTEXITCODE" }

    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[verify-service-17] local EFS encrypt+decrypt OK -- service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-17] $_"; exit 1
}
