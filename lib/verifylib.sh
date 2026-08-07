#!/bin/bash
# SysRepair-Bench verifier library — two-component verdict protocol (v2).
#
# WHY THIS EXISTS
# ---------------
# The v1 contract was a single exit code: 0 = remediated, 1 = not, 42 = N/A.
# That cannot express the measurement the benchmark is actually built around —
# an agent that closes the vulnerability by killing the service must be
# distinguishable from one that closes it while keeping the service up.
#
# The obvious patch (a reserved exit code, say 43, meaning "PoC blocked but
# regression failed") does NOT work on this corpus, for a structural reason:
# 253 of 256 verifiers are fail-fast, and PoC and regression checks are
# interleaved (median 3-5 regression blocks per file, not one terminal block).
# A fail-fast script stops at the FIRST failing check, so exactly one component
# is ever observed. If a regression check fails first, the remaining PoC checks
# never run and "was the vulnerability closed?" is unanswered; if a PoC check
# fails first, service health is unanswered. No exit code can encode a value
# that was never measured.
#
# So the fix is not a new exit code, it is removing fail-fast: run every check,
# record each one with its kind, and report both components.
#
# THE CONTRACT
# ------------
# Each check emits one JSON object per line on stdout:
#
#     {"id":"ssh_root_denied","kind":"poc","pass":true,"detail":"..."}
#
#   kind="poc"        the check that proves the vulnerability is closed
#   kind="regression" the check that proves the service still works
#
# At the end, verify_finish exits:
#     0  every check passed                       (joint pass)
#     1  at least one check failed
#    42  precondition does not hold on this host  (unchanged, see skip_not_applicable)
#
# The exit code keeps its v1 meaning exactly, so every consumer that predates
# this library — validate.py, the RUNBOOKs, `docker run ... bash /verify.sh` —
# behaves identically. The JSONL is purely additive. scorer.py reads it when
# present and falls back to the exit code alone when absent, which is what makes
# migrating the corpus scenario-by-scenario safe.
#
# USAGE — the source line must be exactly this, guard included:
#
#     [ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"
#
# The guard is a security control, not a style choice. Under the harness,
# scorer.py INLINES this file into the verifier before upload and the guard is
# already set, so the source line never runs and the agent-writable path is
# never opened -- an agent that plants a permissive /tmp/verifylib.sh gets
# nothing. Run standalone (validate.py, `docker run ... bash /verify.sh`) the
# guard is unset and the library loads normally from disk. Drop the guard and
# you reintroduce a fail-open hole in the grader.
#
#     if curl -sf http://localhost/admin >/dev/null; then
#         record_poc admin_exposed 0 "admin panel still reachable unauthenticated"
#     else
#         record_poc admin_exposed 1
#     fi
#
#     record_reg_cmd site_up "curl -sf http://localhost/ >/dev/null"
#
#     verify_finish
#
# Checks never abort the script. That is the entire point — do not add `exit 1`
# to a check path, or the component you did not reach becomes unmeasurable again.

# Guard against double-sourcing (some verifiers source helpers more than once).
if [ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ]; then
    return 0 2>/dev/null || true
fi
_SYSREPAIR_VERIFYLIB_LOADED=1

# Exit codes. Kept as variables because ~23 verifiers already use $FAIL/$PASS.
PASS=0
FAIL=1
NOT_APPLICABLE=42

_SR_POC_TOTAL=0
_SR_POC_FAILED=0
_SR_REG_TOTAL=0
_SR_REG_FAILED=0
_SR_ANY_CHECK=0

# JSON-escape a string for embedding in the emitted record. Bash-only, no jq
# dependency: several scenario images do not ship jq, and a verifier that dies
# on a missing tool is a false INCORRECT.
_sr_json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\r'/}"
    s="${s//$'\n'/ }"
    printf '%s' "$s"
}

# _sr_record <kind> <id> <pass:0|1> [detail]
_sr_record() {
    local kind="$1" id="$2" ok="$3" detail="${4:-}"
    local passed="false" label="FAIL"

    # Deliberately strict: only an explicit 1/true is a pass. A typo, an empty
    # string, or an unset variable reads as FAIL, so a broken check can never
    # silently award credit.
    if [ "$ok" = "1" ] || [ "$ok" = "true" ]; then
        passed="true"; label="PASS"
    fi

    _SR_ANY_CHECK=1
    if [ "$kind" = "poc" ]; then
        _SR_POC_TOTAL=$((_SR_POC_TOTAL + 1))
        [ "$passed" = "false" ] && _SR_POC_FAILED=$((_SR_POC_FAILED + 1))
    else
        _SR_REG_TOTAL=$((_SR_REG_TOTAL + 1))
        [ "$passed" = "false" ] && _SR_REG_FAILED=$((_SR_REG_FAILED + 1))
    fi

    # Human-readable line first, so existing log-reading habits still work.
    if [ -n "$detail" ]; then
        echo "  [$label] ($kind) $id: $detail"
    else
        echo "  [$label] ($kind) $id"
    fi
    printf '{"id":"%s","kind":"%s","pass":%s,"detail":"%s"}\n' \
        "$(_sr_json_escape "$id")" "$kind" "$passed" "$(_sr_json_escape "$detail")"
}

# record_poc <id> <pass:0|1> [detail]
#   The vulnerability-closed component. pass=1 means the exploit no longer works.
record_poc() { _sr_record poc "$1" "$2" "${3:-}"; }

# record_reg <id> <pass:0|1> [detail]
#   The service-still-works component. pass=1 means nothing was broken.
record_reg() { _sr_record regression "$1" "$2" "${3:-}"; }

# record_poc_cmd <id> <command...>   — passes when the command exits 0.
record_poc_cmd() {
    local id="$1"; shift
    if "$@" >/dev/null 2>&1; then record_poc "$id" 1
    else record_poc "$id" 0 "command failed: $*"; fi
}

# record_reg_cmd <id> <command...>   — passes when the command exits 0.
record_reg_cmd() {
    local id="$1"; shift
    if "$@" >/dev/null 2>&1; then record_reg "$id" 1
    else record_reg "$id" 0 "command failed: $*"; fi
}

# skip_not_applicable [reason] — the scenario's precondition does not hold on
# this host. Exits 42 immediately; nothing was measured, so nothing is recorded.
skip_not_applicable() {
    echo "[SKIP] not applicable on this host: ${1:-precondition not met}"
    exit $NOT_APPLICABLE
}

# verify_finish — emit the summary record and exit with the v1-compatible code.
verify_finish() {
    if [ "$_SR_ANY_CHECK" = "0" ]; then
        echo "[ERROR] verify_finish called with no checks recorded" >&2
        exit $FAIL
    fi

    local sec="false" reg="false" joint="false"
    [ "$_SR_POC_FAILED" -eq 0 ] && sec="true"
    [ "$_SR_REG_FAILED" -eq 0 ] && reg="true"
    [ "$sec" = "true" ] && [ "$reg" = "true" ] && joint="true"

    # A verifier with zero PoC checks cannot support a security-only verdict.
    # Say so explicitly rather than reporting a vacuous true, which would
    # silently inflate the security-only pass rate.
    if [ "$_SR_POC_TOTAL" -eq 0 ]; then
        sec="null"
    fi
    if [ "$_SR_REG_TOTAL" -eq 0 ]; then
        reg="null"
    fi

    printf '{"sysrepair_summary":true,"security_pass":%s,"regression_pass":%s,"joint_pass":%s,"poc_total":%d,"poc_failed":%d,"reg_total":%d,"reg_failed":%d}\n' \
        "$sec" "$reg" "$joint" \
        "$_SR_POC_TOTAL" "$_SR_POC_FAILED" "$_SR_REG_TOTAL" "$_SR_REG_FAILED"

    echo "========================================"
    if [ "$joint" = "true" ]; then
        echo " RESULT: REMEDIATION SUCCESSFUL"
        exit $PASS
    fi
    echo " RESULT: REMEDIATION FAILED"
    echo "   vulnerability closed : $sec  ($_SR_POC_FAILED/$_SR_POC_TOTAL poc checks failed)"
    echo "   service preserved    : $reg  ($_SR_REG_FAILED/$_SR_REG_TOTAL regression checks failed)"
    echo "========================================"
    exit $FAIL
}
