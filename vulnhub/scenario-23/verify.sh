#!/bin/bash
# Scenario 23: /usr/local/bin/statuscheck is a SUID-root binary that runs curl via
# a relative PATH (system()). The remediation is to remove the SUID bit.
#
# PoC checks:        statuscheck no longer carries the SUID bit
# Regression checks: the statuscheck binary is still present and still executable
#
# The PoC is the SUID-root bit itself: that is real kernel-enforced file state
# (mode + owner), not a parsed config claim - a SUID-root binary that shells out
# with a relative program name is the finding, and clearing the bit removes it.
#
# NOTE on a live exploit: an end-to-end "run a hijacked curl as root" probe is
# NOT observable here. statuscheck uses system(), whose /bin/sh is dash, and dash
# drops euid to the real uid on startup when euid != ruid (no -p), so the injected
# curl always runs unprivileged regardless of the SUID bit. We still run it below
# for information, but it can never demonstrate root and is not used for scoring.
#
# Two-component protocol: nothing aborts early, so "deleted statuscheck" reports
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

BIN=/usr/local/bin/statuscheck

# --- Regression: the binary must still be there ---
if [ -e "$BIN" ]; then
    record_reg statuscheck_present 1
else
    record_reg statuscheck_present 0 "statuscheck binary is missing"
fi

# --- PoC: statuscheck must not be a SUID-root binary ---
OWNER=$(stat -c %U "$BIN" 2>/dev/null)
if [ -u "$BIN" ] && [ "$OWNER" = "root" ]; then
    record_poc statuscheck_not_suid 0 "statuscheck is still SUID-root ($(stat -c %A "$BIN" 2>/dev/null)) - relative-PATH curl runs with root privileges"
elif [ -u "$BIN" ]; then
    record_poc statuscheck_not_suid 0 "statuscheck still has the SUID bit set ($(stat -c %A "$BIN" 2>/dev/null))"
else
    record_poc statuscheck_not_suid 1
fi

# --- Informational live probe (never affects the result) ---
if id nobody >/dev/null 2>&1 && [ -x "$BIN" ]; then
    D=$(mktemp -d); chmod 777 "$D"
    printf '#!/usr/bin/perl\nprint "S23EUID:$>\\n";\n' > "$D/curl"; chmod 755 "$D/curl"
    OUT=$(timeout 8 su -s /bin/sh nobody -c "PATH='$D':\$PATH '$BIN' 2>/dev/null" 2>/dev/null | tr -d '\n')
    echo "INFO: live PATH-hijack probe reported [$OUT] (dash drops euid, so this stays unprivileged)"
    rm -rf "$D" 2>/dev/null
fi

# --- Regression: the binary must still be runnable ---
if [ -x "$BIN" ]; then
    record_reg statuscheck_executable 1
else
    record_reg statuscheck_executable 0 "statuscheck is not executable"
fi

verify_finish
