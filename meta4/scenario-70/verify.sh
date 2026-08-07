#!/bin/bash
# Scenario 70: cap_sys_admin FILE capability on a helper binary
# (CVE-2022-0492 / CWE-250 reframe).
#
# Ground truth is the on-disk security.capability xattr (getcap) PLUS a live,
# kernel-enforced probe run AS A NON-ROOT USER (appuser): exec'ing the helper
# must no longer let an unprivileged user perform a CAP_SYS_ADMIN mount. With the
# file cap present, exec raises cap_sys_admin into the process effective set and
# the mount succeeds (token PRIVOP_OK); after `setcap -r` the kernel denies it.
# The probe mounts a tmpfs inside a throwaway mount namespace, so it never
# mutates the container.
set -u
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# NOTE: the old `FAIL=0` accumulator is gone deliberately. verifylib exports
# FAIL=1 as the failure EXIT CODE, so reusing that name as a counter would make
# verify_finish exit 0 on a failed run. verify_finish now tallies the checks.
HELPER=/usr/local/bin/caphelper
APPUSER=appuser

###############################################################################
# PoC (static xattr ground truth): no binary may carry cap_sys_admin as a FILE
# capability. getcap reads the actual kernel-enforced xattr, not config.
###############################################################################
CAPBINS=$(getcap -r / 2>/dev/null | grep -i 'cap_sys_admin' || true)
if [ -n "$CAPBINS" ]; then
    record_poc no_sys_admin_file_capability 0 "binary carries the cap_sys_admin file capability: $CAPBINS"
else
    record_poc no_sys_admin_file_capability 1 "no binary carries a cap_sys_admin file capability"
fi

###############################################################################
# PoC (live, kernel-enforced): as unprivileged appuser, exec each candidate
# binary. PRIVOP_OK on stdout proves the CAP_SYS_ADMIN mount succeeded => the
# non-root user escalated. Empty output = the privileged op was DENIED (not a
# missing tool: candidates are checked for -x, and the static getcap check above
# is the authoritative gate for cap presence).
###############################################################################
if id "$APPUSER" >/dev/null 2>&1; then
    CANDIDATES="$HELPER"
    for b in $(printf '%s\n' "$CAPBINS" | awk '{print $1}'); do
        CANDIDATES="$CANDIDATES $b"
    done
    LEAK=0
    RAN=0
    LEAK_VIA=""
    for b in $CANDIDATES; do
        [ -x "$b" ] || continue
        RAN=1
        HITS=$(timeout 15 su -s /bin/sh "$APPUSER" -c "'$b'" 2>/dev/null | grep -c 'PRIVOP_OK' || true)
        if [ "${HITS:-0}" != "0" ]; then
            LEAK=1
            LEAK_VIA="$LEAK_VIA $b"
        fi
    done
    if [ "$RAN" = "0" ]; then
        echo "INFO [PoC-live]: no candidate helper present to exec (cap path already removed)."
    fi
    if [ "$LEAK" = "0" ]; then
        record_poc sys_admin_mount_denied 1 "non-root '$APPUSER' cannot perform the CAP_SYS_ADMIN mount"
    else
        record_poc sys_admin_mount_denied 0 \
            "non-root '$APPUSER' performed a CAP_SYS_ADMIN mount via$LEAK_VIA (PRIVOP_OK)"
    fi
else
    record_poc sys_admin_mount_denied 0 "no '$APPUSER' user available to test the privilege drop"
fi

###############################################################################
# Regression: the fix is `setcap -r`, NOT destroying the helper.
#
# BROKEN BEFORE: the only regression check was `ls /tmp`, and every PoC check
# above skips a candidate that is not `-x` or has no capability xattr. So
# destroying the tool scored a full pass — measured, both of these exited 0:
#     rm -f /usr/local/bin/caphelper
#     truncate -s 0 /usr/local/bin/caphelper   (a write also clears the
#                                               security.capability xattr)
# The helper is a working tool; the remediation takes away its privilege, not
# the tool. So run it AS the unprivileged user and require that it actually
# EXECUTED. caphelper prints nothing once the capability is gone (that is the
# fixed state), so output cannot distinguish "fixed" from "deleted" — the exit
# status can:
#     0   ran, privileged op succeeded  (still vulnerable; the PoC above fails)
#     1   ran, privileged op denied     (the remediated state)
#     126 could not exec  (chmod 000, truncated to 0 bytes -> ENOEXEC)
#     127 not found       (deleted)
# Requiring 0 or 1 therefore asserts "the binary is still a runnable program"
# without weakening anything: the PoC checks still independently require that
# the capability is gone and that no mount succeeds.
#
# The exit status ALONE is not sufficient, and this is measured, not assumed:
# `truncate -s 0` scored rc=0 and passed. The reason is the shell's ENOEXEC
# fallback -- when execve rejects a non-ELF file, dash re-runs it AS A SHELL
# SCRIPT, and an empty script exits 0. Using `exec` does not avoid it (verified:
# still rc=0). So the ELF magic is required as well: it is what distinguishes
# "the binary is intact" from "the shell politely interpreted 0 bytes".
###############################################################################
if id "$APPUSER" >/dev/null 2>&1; then
    timeout 15 su -s /bin/sh "$APPUSER" -c "'$HELPER'" >/dev/null 2>&1
    HELPER_RC=$?
else
    HELPER_RC=noappuser
fi
HELPER_MAGIC=$(head -c 4 "$HELPER" 2>/dev/null | od -An -c 2>/dev/null | tr -d ' \n' || true)

HELPER_RUNS=0
case "$HELPER_RC" in 0|1) HELPER_RUNS=1 ;; esac
if [ "$HELPER_RUNS" = "1" ] && [ "$HELPER_MAGIC" = "177ELF" ]; then
    record_reg helper_still_runnable 1 \
        "non-root '$APPUSER' can still execute $HELPER and it is still an ELF binary (rc=$HELPER_RC)"
else
    record_reg helper_still_runnable 0 \
        "$HELPER is no longer a working program for non-root '$APPUSER' (rc=$HELPER_RC, magic='${HELPER_MAGIC:-none}'; 127=deleted, 126=not executable, non-ELF=emptied/overwritten) -- the tool was destroyed rather than de-privileged"
fi

###############################################################################
# Regression: basic tooling still works.
###############################################################################
if ls /tmp >/dev/null 2>&1; then
    record_reg basic_file_ops 1 "basic file operations work normally"
else
    record_reg basic_file_ops 0 "'ls /tmp' failed — container is broken"
fi

verify_finish
