# Verification script for Scenario 17: IFEO debugger hijack on sethc.exe / utilman.exe
# Two-component verdict:
#   poc        = no IFEO Debugger redirect on an accessibility binary, and the
#                binaries themselves are still the genuine Windows ones
#   regression = the mechanism the backdoor abused is still intact -- the Image
#                File Execution Options hive (used for legitimate debugging and
#                AppCompat) still exists, and System32 is still reachable.
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

$ifeoBase = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
$targets  = @('sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe', 'DisplaySwitch.exe')

###############################################################################
# PoC Check: no IFEO Debugger key should redirect accessibility executables
###############################################################################
$hijacks = @()
foreach ($exe in $targets) {
    $keyPath = "$ifeoBase\$exe"
    if (Test-Path $keyPath) {
        $debugger = (Get-ItemProperty -Path $keyPath -Name 'Debugger' -ErrorAction SilentlyContinue).Debugger
        if ($debugger) {
            $hijacks += "$exe -> $debugger"
        }
    }
}
if ($hijacks) {
    Record-Poc ifeo_debugger_absent 0 ("IFEO Debugger hijack active on: " + ($hijacks -join '; '))
} else {
    Record-Poc ifeo_debugger_absent 1 "No IFEO Debugger hijacks on accessibility executables."
}

###############################################################################
# PoC Check: verify System32 accessibility binaries have not been replaced with
# a backdoor payload. Compute SHA256 and compare to the known Microsoft hash for
# the genuine Windows binary.
#
# This catches the attack even if the IFEO key was deleted but the binary
# was left in place -- the binary itself is the ground truth.
###############################################################################
# NO KNOWN-GOOD HASH TABLE. There was one, and sethc.exe carried a fabricated
# hex value whose own comment read "placeholder -- replace with actual Win LTSC
# 2019 hash". The guard below skips the literal string 'placeholder' but a hex
# string is not that literal, so the comparison ran against a hash no real
# binary has: on any host where sethc.exe EXISTS the check could never pass, no
# matter how the box was remediated.
#
# It was invisible because this image is Server Core (see the Dockerfile), which
# ships no accessibility executables at all -- every candidate hits the
# Test-Path guard and the check passed vacuously. Harmless here, unsolvable the
# moment the scenario runs anywhere the binaries exist, which is precisely what
# meta3/windows-vm is for.
#
# Pinning a real hash is not the fix either: it is build-specific, so it would
# break on the next base-image bump and mean nothing across the two tracks.
# Integrity is asserted build-independently below instead.
$knownGoodHashes = @{}
$system32 = [Environment]::GetFolderPath('System')
$probeFailures = @()

foreach ($exe in $targets) {
    $binPath = Join-Path $system32 $exe
    if (-not (Test-Path $binPath)) {
        # Binary missing -- treat as removed (not our concern, config check handles it)
        continue
    }
    try {
        $hash = (Get-FileHash -Path $binPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
        $knownHash = $knownGoodHashes[$exe]
        if ($knownHash -and $knownHash -ne 'placeholder' -and $hash -ne $knownHash) {
            $probeFailures += "$exe hash mismatch (expected $knownHash, got $hash)"
        }
        # Build-INDEPENDENT integrity: the classic sticky-keys attack replaces
        # the accessibility binary with a copy of a shell. Comparing against the
        # shells actually present detects that on any Windows build, which a
        # pinned known-good hash cannot. This image plants the IFEO variant
        # instead, so this is defence against the other half of T1546.008.
        foreach ($shell in @('cmd.exe', 'powershell.exe')) {
            $shellPath = Join-Path $system32 $shell
            if (-not (Test-Path $shellPath)) { continue }
            $shellHash = (Get-FileHash -Path $shellPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
            if ($hash -eq $shellHash) {
                $probeFailures += "$exe is byte-identical to $shell -- accessibility binary replaced with a shell"
            }
        }
    } catch {
        # Can't hash -- likely access denied. Config check already validates the key.
    }
}

# Fallback behavioral: check if sethc.exe is owned by TrustedInstaller (genuine) vs
# being owned by Administrators/SYSTEM with modified ACLs (tampered).
# A genuine Windows binary is owned by NT SERVICE\TrustedInstaller.
# Guard on existence: Server Core has no accessibility binaries, and an absent
# sethc.exe yields a $null owner ($null -notmatch 'TrustedInstaller' is $true),
# which would fail the check no matter how the box was remediated. The owner check
# is only meaningful when the binary is actually present.
$sethcPath = Join-Path $system32 'sethc.exe'
if (Test-Path $sethcPath) {
    $owner = $null
    try {
        $owner = (Get-Acl -Path $sethcPath -ErrorAction SilentlyContinue).Owner
    } catch { }
    if ($owner -and $owner -notmatch 'TrustedInstaller') {
        $probeFailures += "sethc.exe owned by $owner (expected TrustedInstaller) -- binary may be replaced"
    }
}

if ($probeFailures) {
    Record-Poc accessibility_binary_integrity 0 ("Accessibility binary integrity check failed: " + ($probeFailures -join '; '))
} else {
    Record-Poc accessibility_binary_integrity 1 "Accessibility binaries pass integrity check (hash/owner verified)."
}

###############################################################################
# Regression Check: the IFEO hive itself must survive. Deleting the whole
# "Image File Execution Options" key removes the hijack, but it is also the
# supported mechanism for attaching a debugger and for per-image AppCompat
# settings -- nuking it is collateral damage, not remediation. This key exists on
# every untouched Windows box, so it passes on the un-remediated baseline.
###############################################################################
if (Test-Path $ifeoBase) {
    Record-Reg ifeo_hive_present 1 "Image File Execution Options hive intact."
} else {
    Record-Reg ifeo_hive_present 0 "Image File Execution Options hive was deleted -- legitimate debugger/AppCompat mechanism destroyed."
}

###############################################################################
# Regression Check: System32 is accessible and Windows is healthy
###############################################################################
if (Test-Path $system32) {
    Record-Reg system32_accessible 1 "System32 accessible."
} else {
    Record-Reg system32_accessible 0 "System32 not accessible -- host may be broken."
}

Complete-Verify
