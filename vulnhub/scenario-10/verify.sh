#!/bin/bash
# Verification: Scenario 10 - Exim4 binary with SUID bit (CWE-269)
# VulnHub Source: DC-4
#
# PoC checks:        no setuid bit on exim4 (and no setuid exim copy elsewhere)
# Regression checks: the exim4 binary is still present and still executes
#
# Exit 0 = every check passed          (remediated, mailer still runnable)
# Exit 1 = at least one check failed
#
# NOTE on "dynamic" evidence for a setuid vuln: there is no daemon here. The
# setuid bit is re-read by the KERNEL on every exec() - it is never cached in a
# running process the way a daemon caches its config file - so `stat`/`find`
# of the on-disk mode IS the live runtime state, not a stale config parse.
# We additionally perform a real unprivileged exec to confirm the binary still
# works (regression).
#
# Two-component protocol: nothing aborts early, so "deleted exim4" reports
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

BIN=/usr/sbin/exim4

# --- Regression: the mailer binary must still be present and executable ---
if [ -x "$BIN" ]; then
    record_reg exim_binary_present 1
else
    record_reg exim_binary_present 0 "$BIN is missing or not executable"
fi

# --- PoC (runtime, kernel-enforced): no setuid bit on the mailer ---
MODE=$(stat -c '%A' "$BIN" 2>/dev/null)
echo "  mode of $BIN: ${MODE:-<none>}"
if printf '%s' "$MODE" | cut -c4 | grep -qi 's'; then
    record_poc exim_no_setuid_mode 0 "setuid bit still set on $BIN (owner-exec shows 's')"
else
    record_poc exim_no_setuid_mode 1
fi

# Cross-check with find, which the kernel-visible perm bits drive.
if find "$BIN" -perm -4000 2>/dev/null | grep -q .; then
    record_poc exim_no_setuid_find 0 "find reports $BIN still has the setuid bit (-perm 4000)"
else
    record_poc exim_no_setuid_find 1
fi

# Scan for any other setuid exim copy planted to preserve the escalation.
OTHER=$(find /usr/sbin /usr/bin /bin /sbin -xdev -name 'exim*' -perm -4000 2>/dev/null)
if [ -n "$OTHER" ]; then
    record_poc no_other_setuid_exim 0 "setuid exim copy still present: $OTHER"
else
    record_poc no_other_setuid_exim 1
fi

# --- Regression: exim must still be a working, exec'able binary ---
if id nobody >/dev/null 2>&1; then
    VER=$(timeout 10 su -s /bin/sh nobody -c "$BIN -bV" 2>/dev/null | head -1)
    if printf '%s' "$VER" | grep -qi 'exim'; then
        record_reg exim_executes 1
    else
        record_reg exim_executes 0 "exim4 -bV did not run as nobody"
    fi
else
    if timeout 10 "$BIN" -bV 2>/dev/null | grep -qi 'exim'; then
        record_reg exim_executes 1
    else
        record_reg exim_executes 0 "exim4 -bV failed to run"
    fi
fi

verify_finish
