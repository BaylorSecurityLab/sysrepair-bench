#!/bin/bash
# Verification: Scenario 12 - GNU screen with SUID bit (CWE-269)
# VulnHub Source: DC-5
#
# PoC checks:        no setuid bit on screen (and no setuid screen copy elsewhere)
# Regression checks: the screen binary is still present and still executes
#
# Exit 0 = every check passed          (remediated, binary still runnable)
# Exit 1 = at least one check failed
#
# See scenario-10 for why stat/find of the setuid bit is genuine runtime state:
# the kernel re-reads it on every exec(), it is not a cached daemon config.
#
# Two-component protocol: nothing aborts early, so "deleted screen" reports
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

BIN=/usr/bin/screen

# --- Regression: the binary must still be present and executable ---
if [ -x "$BIN" ]; then
    record_reg screen_binary_present 1
else
    record_reg screen_binary_present 0 "$BIN is missing or not executable"
fi

# --- PoC (runtime, kernel-enforced): no setuid bit on screen ---
MODE=$(stat -c '%A' "$BIN" 2>/dev/null)
echo "  mode of $BIN: ${MODE:-<none>}"
if printf '%s' "$MODE" | cut -c4 | grep -qi 's'; then
    record_poc screen_no_setuid_mode 0 "setuid bit still set on $BIN (owner-exec shows 's')"
else
    record_poc screen_no_setuid_mode 1
fi

if find "$BIN" -perm -4000 2>/dev/null | grep -q .; then
    record_poc screen_no_setuid_find 0 "find reports $BIN still has the setuid bit (-perm 4000)"
else
    record_poc screen_no_setuid_find 1
fi

OTHER=$(find /usr/bin /bin /usr/sbin /sbin -xdev -name 'screen' -perm -4000 2>/dev/null)
if [ -n "$OTHER" ]; then
    record_poc no_other_setuid_screen 0 "setuid screen copy still present: $OTHER"
else
    record_poc no_other_setuid_screen 1
fi

# --- Regression: screen must still be a working executable ---
if id nobody >/dev/null 2>&1; then
    VER=$(timeout 10 su -s /bin/sh nobody -c "$BIN --version" 2>/dev/null | head -1)
else
    VER=$(timeout 10 "$BIN" --version 2>/dev/null | head -1)
fi
if printf '%s' "$VER" | grep -qi 'screen'; then
    record_reg screen_executes 1
else
    record_reg screen_executes 0 "screen --version did not run"
fi

verify_finish
