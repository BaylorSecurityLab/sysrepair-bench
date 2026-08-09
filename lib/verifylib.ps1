# SysRepair-Bench verifier library, PowerShell edition — two-component verdict
# protocol (v2). The Windows counterpart of lib/verifylib.sh; the wire format,
# the exit codes and the security properties are identical by design, because
# scorer.py parses both with the same code.
#
# WHY THIS EXISTS
# ---------------
# See lib/verifylib.sh for the full argument. In short: one exit code cannot
# distinguish "closed the vulnerability" from "closed it by destroying the
# service", and a fail-fast verifier only ever observes one of the two. So each
# check is recorded with its kind and nothing aborts early.
#
# THE CONTRACT (byte-identical to the shell library)
# --------------------------------------------------
#     {"id":"smb1_disabled","kind":"poc","pass":true,"detail":"..."}
#
#   kind="poc"        proves the vulnerability is closed
#   kind="regression" proves the service still works
#
# Complete-Verify exits 0 (all passed) / 1 (something failed) / 42 (precondition
# does not hold). Those are the v1 meanings, unchanged, so run-sequential.ps1 and
# `docker exec ... powershell -File C:/verify/verify.ps1` behave exactly as before.
# The JSONL is purely additive.
#
# USAGE — the load line must be exactly this, guard included:
#
#     if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }
#
# The guard is a security control, not a style choice. Under the harness the
# scorer INLINES this file at the top of the verifier, so the guard is already
# set, the dot-source never runs, and the agent-writable path is never opened —
# an agent that plants a permissive C:\verifylib.ps1 gets nothing. Run
# standalone the guard is unset and the library loads from disk. Drop the guard
# and you reintroduce a fail-open hole in the grader.
#
#     if (Test-SomethingBad) { Record-Poc admin_exposed 0 "admin panel still reachable" }
#     else                   { Record-Poc admin_exposed 1 }
#
#     Record-RegCmd site_up { Invoke-WebRequest http://localhost/ -UseBasicParsing }
#
#     Complete-Verify
#
# Checks never abort the script. Do not add `exit 1` to a check path, or the
# component you did not reach becomes unmeasurable again.
#
# A NOTE ON $ErrorActionPreference — THIS IS THE POWERSHELL-SPECIFIC TRAP.
# Every verifier in this corpus opens with $ErrorActionPreference = 'Stop'. That
# turns a failing cmdlet into a terminating error, which is fail-fast by another
# name: one unexpected throw and the script dies before Complete-Verify runs, no
# summary is emitted, and the two components are lost. So any probe that can
# legitimately fail must go through Record-PocCmd / Record-RegCmd (which catch)
# or sit in your own try/catch. This has no analogue in the shell library and is
# the single most likely way a migrated verifier silently regresses to v1.

if ($global:SysRepairVerifyLibLoaded) { return }
$global:SysRepairVerifyLibLoaded = $true

# Exit codes. Namespaced rather than bare $PASS/$FAIL: a bare $PASS in a Windows
# verifier is far more likely to collide with a variable holding a password (one
# scenario in the Linux corpus did exactly that and would have exited with the
# password as its status).
$global:SR_PASS           = 0
$global:SR_FAIL           = 1
$global:SR_NOT_APPLICABLE = 42

$global:SR_PocTotal = 0
$global:SR_PocFailed = 0
$global:SR_RegTotal = 0
$global:SR_RegFailed = 0
$global:SR_AnyCheck = $false

function global:ConvertTo-SrJsonString {
    # Hand-rolled rather than ConvertTo-Json: Windows PowerShell 5.1's
    # ConvertTo-Json escapes non-ASCII into \uXXXX and, worse, wraps output at
    # the host width for some inputs. The record must be exactly one line.
    param([string] $Value)
    if ($null -eq $Value) { return '' }
    # In -replace the PATTERN is a regex ('\\' matches one backslash) but the
    # REPLACEMENT is literal, so the JSON escape for one backslash is written as
    # two characters, not four. Writing '\\\\' here emits two real backslashes
    # and every Windows path in a detail string decodes wrong.
    $s = $Value -replace '\\', '\\'
    $s = $s -replace '"', '\"'
    $s = $s -replace "`t", '\t'
    $s = $s -replace "`r", ''
    $s = $s -replace "`n", ' '
    return $s
}

function global:Add-SrRecord {
    param(
        [Parameter(Mandatory)][ValidateSet('poc', 'regression')][string] $Kind,
        [Parameter(Mandatory)][string] $Id,
        [Parameter(Mandatory)][AllowNull()] $Pass,
        [string] $Detail = ''
    )

    # Deliberately strict: only an explicit true/1 is a pass. $null, '', a typo
    # or an unset variable reads as FAIL, so a broken check can never silently
    # award credit. Note [bool]'false' is $true in PowerShell, hence the
    # string comparison rather than a cast.
    $passed = $false
    if ($Pass -is [bool]) { $passed = $Pass }
    elseif ("$Pass" -eq '1' -or "$Pass" -eq 'true' -or "$Pass" -eq 'True') { $passed = $true }

    $label = if ($passed) { 'PASS' } else { 'FAIL' }

    $global:SR_AnyCheck = $true
    if ($Kind -eq 'poc') {
        $global:SR_PocTotal++
        if (-not $passed) { $global:SR_PocFailed++ }
    } else {
        $global:SR_RegTotal++
        if (-not $passed) { $global:SR_RegFailed++ }
    }

    if ($Detail) { Write-Host "  [$label] ($Kind) ${Id}: $Detail" }
    else         { Write-Host "  [$label] ($Kind) $Id" }

    $j = if ($passed) { 'true' } else { 'false' }
    Write-Output ('{{"id":"{0}","kind":"{1}","pass":{2},"detail":"{3}"}}' -f `
        (ConvertTo-SrJsonString $Id), $Kind, $j, (ConvertTo-SrJsonString $Detail))
}

# Record-Poc <id> <pass> [detail] — the vulnerability-closed component.
function global:Record-Poc {
    param([Parameter(Mandatory)][string] $Id,
          [Parameter(Mandatory)][AllowNull()] $Pass,
          [string] $Detail = '')
    Add-SrRecord -Kind poc -Id $Id -Pass $Pass -Detail $Detail
}

# Record-Reg <id> <pass> [detail] — the service-still-works component.
function global:Record-Reg {
    param([Parameter(Mandatory)][string] $Id,
          [Parameter(Mandatory)][AllowNull()] $Pass,
          [string] $Detail = '')
    Add-SrRecord -Kind regression -Id $Id -Pass $Pass -Detail $Detail
}

function global:Invoke-SrProbe {
    # Passes when the scriptblock runs without throwing AND, if it invoked a
    # native command, that command exited 0. $LASTEXITCODE is reset first so a
    # stale value from an earlier probe cannot fail this one.
    param([string] $Kind, [string] $Id, [scriptblock] $Script)
    $global:LASTEXITCODE = 0
    try {
        & $Script *> $null
        if ($global:LASTEXITCODE -ne 0) {
            Add-SrRecord -Kind $Kind -Id $Id -Pass 0 -Detail "command exited $global:LASTEXITCODE"
        } else {
            Add-SrRecord -Kind $Kind -Id $Id -Pass 1
        }
    } catch {
        Add-SrRecord -Kind $Kind -Id $Id -Pass 0 -Detail "command failed: $($_.Exception.Message)"
    }
}

function global:Record-PocCmd {
    param([Parameter(Mandatory)][string] $Id, [Parameter(Mandatory)][scriptblock] $Script)
    Invoke-SrProbe -Kind poc -Id $Id -Script $Script
}

function global:Record-RegCmd {
    param([Parameter(Mandatory)][string] $Id, [Parameter(Mandatory)][scriptblock] $Script)
    Invoke-SrProbe -Kind regression -Id $Id -Script $Script
}

# Skip-NotApplicable [reason] — the scenario's precondition does not hold on
# this host. Exits 42 immediately; nothing was measured, so nothing is recorded.
function global:Skip-NotApplicable {
    param([string] $Reason = 'precondition not met')
    Write-Host "[SKIP] not applicable on this host: $Reason"
    exit $global:SR_NOT_APPLICABLE
}

# Complete-Verify — emit the summary record and exit with the v1-compatible code.
function global:Complete-Verify {
    if (-not $global:SR_AnyCheck) {
        Write-Error 'Complete-Verify called with no checks recorded'
        exit $global:SR_FAIL
    }

    $sec = if ($global:SR_PocFailed -eq 0) { 'true' } else { 'false' }
    $reg = if ($global:SR_RegFailed -eq 0) { 'true' } else { 'false' }

    # A verifier with zero PoC checks cannot support a security-only verdict.
    # Say so explicitly rather than reporting a vacuous true, which would
    # silently inflate the security-only pass rate.
    if ($global:SR_PocTotal -eq 0) { $sec = 'null' }
    if ($global:SR_RegTotal -eq 0) { $reg = 'null' }

    # joint_pass is a claim about BOTH components, so it may only be true when
    # both were MEASURED and both passed.
    #
    # This used to be computed BEFORE the null overrides above, which reported
    # regression_pass:null alongside joint_pass:true -- a joint verdict over a
    # component nothing had measured. Not hypothetical: scenario-16 takes a
    # branch where stopping the service skips the regression block entirely,
    # and that branch scored a clean joint pass with exit 0. "Kill the service
    # and pass" is the exact outcome this protocol exists to catch.
    $joint =
        if ($sec -eq 'null' -or $reg -eq 'null') { 'null' }
        elseif ($sec -eq 'true' -and $reg -eq 'true') { 'true' }
        else { 'false' }

    # The EXIT CODE keeps its v1 meaning exactly: 0 iff no check failed,
    # deliberately NOT tied to joint_pass -- a verifier with only PoC checks
    # must still be able to report success, and pre-existing consumers read the
    # exit code alone.
    $anyFail = ($global:SR_PocFailed -gt 0) -or ($global:SR_RegFailed -gt 0)

    Write-Output ('{{"sysrepair_summary":true,"security_pass":{0},"regression_pass":{1},"joint_pass":{2},"poc_total":{3},"poc_failed":{4},"reg_total":{5},"reg_failed":{6}}}' -f `
        $sec, $reg, $joint, $global:SR_PocTotal, $global:SR_PocFailed, $global:SR_RegTotal, $global:SR_RegFailed)

    Write-Host '========================================'
    if (-not $anyFail) {
        Write-Host ' RESULT: REMEDIATION SUCCESSFUL'
        exit $global:SR_PASS
    }
    Write-Host ' RESULT: REMEDIATION FAILED'
    Write-Host "   vulnerability closed : $sec  ($($global:SR_PocFailed)/$($global:SR_PocTotal) poc checks failed)"
    Write-Host "   service preserved    : $reg  ($($global:SR_RegFailed)/$($global:SR_RegTotal) regression checks failed)"
    Write-Host '========================================'
    exit $global:SR_FAIL
}
