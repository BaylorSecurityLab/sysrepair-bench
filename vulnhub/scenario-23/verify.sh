#!/bin/bash
# Scenario 23: /usr/local/bin/statuscheck is a SUID-root binary that runs curl via
# a relative PATH (system()). The remediation is to remove the SUID bit.
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
PASS=true
BIN=/usr/local/bin/statuscheck

if [ ! -e "$BIN" ]; then
    echo "FAIL [Regression]: statuscheck binary is missing"; exit 1
fi

# --- PoC: statuscheck must not be a SUID-root binary ---
OWNER=$(stat -c %U "$BIN" 2>/dev/null)
if [ -u "$BIN" ] && [ "$OWNER" = "root" ]; then
    echo "FAIL [PoC]: statuscheck is still SUID-root ($(stat -c %A "$BIN")) - relative-PATH curl runs with root privileges"
    PASS=false
elif [ -u "$BIN" ]; then
    echo "FAIL [PoC]: statuscheck still has the SUID bit set ($(stat -c %A "$BIN"))"
    PASS=false
else
    echo "PASS [PoC]: SUID bit removed from statuscheck ($(stat -c %A "$BIN"))"
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
if [ -x "$BIN" ]; then echo "PASS [Regression]: statuscheck is still executable"; else echo "FAIL [Regression]: statuscheck is not executable"; PASS=false; fi

if $PASS; then echo "All checks passed."; exit 0; else exit 1; fi
