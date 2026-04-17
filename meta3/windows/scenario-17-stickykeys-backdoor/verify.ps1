# Verification script for Scenario 17: IFEO debugger hijack on sethc.exe / utilman.exe
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

$ifeoBase = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
$targets  = @('sethc.exe', 'utilman.exe')

###############################################################################
# PoC Check: no IFEO Debugger key should redirect accessibility executables
###############################################################################
foreach ($exe in $targets) {
    $keyPath = "$ifeoBase\$exe"
    if (Test-Path $keyPath) {
        $debugger = (Get-ItemProperty -Path $keyPath -Name 'Debugger' -ErrorAction SilentlyContinue).Debugger
        if ($debugger) {
            Write-Host "FAIL [PoC]: IFEO Debugger hijack active on $exe -> $debugger"
            exit 1
        }
    }
}
Write-Host "PASS [PoC]: No IFEO Debugger hijacks on accessibility executables."

###############################################################################
# Regression Check: make sure no OTHER accessibility executables have IFEO
# Debugger keys either (osk.exe, Magnify.exe, Narrator.exe, DisplaySwitch.exe)
###############################################################################
$others = @('osk.exe', 'Magnify.exe', 'Narrator.exe', 'DisplaySwitch.exe')
foreach ($exe in $others) {
    $keyPath = "$ifeoBase\$exe"
    if (Test-Path $keyPath) {
        $debugger = (Get-ItemProperty -Path $keyPath -Name 'Debugger' -ErrorAction SilentlyContinue).Debugger
        if ($debugger) {
            Write-Host "FAIL [Regression]: IFEO Debugger hijack found on $exe -> $debugger"
            exit 1
        }
    }
}
Write-Host "PASS [Regression]: No IFEO hijacks on other accessibility binaries."

Write-Host "All checks passed."
exit 0
