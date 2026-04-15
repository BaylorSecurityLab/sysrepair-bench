# Verification script for Scenario 17: Sticky Keys backdoor (sethc.exe = cmd.exe)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

$sethc = 'C:\Windows\System32\sethc.exe'
$cmd   = 'C:\Windows\System32\cmd.exe'
$bak   = 'C:\Windows\System32\sethc.exe.bak'

###############################################################################
# PoC Check 1: sethc.exe must not be a copy of cmd.exe
###############################################################################
if (-not (Test-Path $sethc)) {
    Write-Host "FAIL [PoC]: sethc.exe is missing — restore the real accessibility binary instead of deleting it."
    exit 1
}
$sethcHash = (Get-FileHash -Path $sethc -Algorithm SHA256).Hash
$cmdHash   = (Get-FileHash -Path $cmd   -Algorithm SHA256).Hash
if ($sethcHash -eq $cmdHash) {
    Write-Host "FAIL [PoC]: sethc.exe hash still matches cmd.exe — backdoor intact."
    exit 1
}
Write-Host "PASS [PoC]: sethc.exe no longer matches cmd.exe."

###############################################################################
# PoC Check 2: operator backup sethc.exe.bak must be gone
###############################################################################
if (Test-Path $bak) {
    Write-Host "FAIL [PoC]: $bak still present — remove the operator's backup copy."
    exit 1
}
Write-Host "PASS [PoC]: sethc.exe.bak removed."

###############################################################################
# PoC Check 3: sethc.exe must be owned by TrustedInstaller
###############################################################################
$owner = (Get-Acl -Path $sethc).Owner
if ($owner -notmatch 'TrustedInstaller') {
    Write-Host "FAIL [PoC]: sethc.exe owner is '$owner'; expected NT SERVICE\TrustedInstaller."
    exit 1
}
Write-Host "PASS [PoC]: sethc.exe owned by TrustedInstaller."

###############################################################################
# Regression Check: sethc.exe still launches cleanly (i.e. it's a real PE that
# exits 0 on -? or equivalent). We just confirm the file is a valid executable.
###############################################################################
try {
    $fi = Get-Item $sethc
    if ($fi.Length -lt 1024) {
        Write-Host "FAIL [Regression]: sethc.exe is too small to be a real binary ($($fi.Length) bytes)."
        exit 1
    }
    $bytes = [System.IO.File]::ReadAllBytes($sethc)[0..1]
    if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
        Write-Host "FAIL [Regression]: sethc.exe is not a valid PE (missing MZ header)."
        exit 1
    }
} catch {
    Write-Host "FAIL [Regression]: could not inspect sethc.exe ($_)."
    exit 1
}
Write-Host "PASS [Regression]: sethc.exe is a valid PE."

Write-Host "All checks passed."
exit 0
