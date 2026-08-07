#!/bin/bash
# Verification script for Scenario 26: Hacking tools installed
# Exit 0 = every check passed, Exit 1 = at least one check failed
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "removed the offensive toolkit but also removed curl/wget"
# is reported as security_pass=true / regression_pass=false rather than
# collapsing into a bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

echo "=== PoC Test: Checking for hacking tools ==="

# Check each offensive tool binary
for tool in nmap ncat hydra john nikto; do
    if which "$tool" > /dev/null 2>&1; then
        record_poc "${tool}_binary_absent" 0 "$tool is still installed ($(which $tool))"
    else
        record_poc "${tool}_binary_absent" 1
    fi
done

# Also check if packages are installed via dpkg
for pkg in nmap ncat hydra john nikto; do
    if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        record_poc "${pkg}_package_removed" 0 "package $pkg is still installed"
    else
        record_poc "${pkg}_package_removed" 1
    fi
done

###############################################################################
# PoC Behavioral Test (RUNTIME): actually TRY TO USE the offensive toolkit.
#
# `which` and `dpkg -l` above are only a secondary signal - they inspect PATH
# and package metadata. What actually matters is whether an attacker who lands
# on this host can still RUN these tools, so the checks below EXECUTE them and
# look for tool-characteristic output:
#
#   * nmap  - run a real TCP port scan of 127.0.0.1 and look for a scan report
#   * ncat  - stand up a real listener and push bytes through it (the classic
#             backdoor / reverse-shell primitive)
#   * hydra / john / nikto - execute and match their banners
#
# This also catches the "deleted the symlink, left the binary" case: every copy
# found anywhere on the filesystem is executed too, not just the one on $PATH.
###############################################################################
echo ""
echo "=== PoC Behavioral Test: attempting to actually RUN the offensive tools ==="

# Isolate HOME so `john` does not create /root/.john as a side effect.
PROBE_HOME=/tmp/.tool_probe_home.$$
mkdir -p "$PROBE_HOME"

# run_probe <id> <label> <signature-regex> <command...>
run_probe() {
    id="$1"; label="$2"; sig="$3"; shift 3
    out=$(HOME="$PROBE_HOME" timeout 25 "$@" 2>&1 || true)
    if echo "$out" | grep -qE "$sig"; then
        record_poc "$id" 0 "$label is still FUNCTIONAL - it ran and produced tool output"
    else
        record_poc "$id" 1 "$label could not be executed"
    fi
}

# --- nmap: a genuine port scan ---
NMAP_BIN=$(command -v nmap 2>/dev/null || true)
if [ -n "$NMAP_BIN" ]; then
    run_probe nmap_not_runnable "nmap (live port scan)" "Nmap done|PORT +STATE" \
        "$NMAP_BIN" -Pn -p 22,80,443 127.0.0.1
else
    record_poc nmap_not_runnable 1 "nmap could not be executed"
fi

# --- ncat: a genuine listener + data transfer ---
NCAT_BIN=$(command -v ncat 2>/dev/null || true)
if [ -n "$NCAT_BIN" ]; then
    NCAT_PORT=39017
    NCAT_OUT=/tmp/.ncat_probe.$$
    rm -f "$NCAT_OUT"
    ("$NCAT_BIN" -l 127.0.0.1 "$NCAT_PORT" > "$NCAT_OUT" 2>/dev/null &)
    sleep 1
    echo "SYSREPAIR_BACKDOOR_PROBE" | timeout 5 "$NCAT_BIN" 127.0.0.1 "$NCAT_PORT" >/dev/null 2>&1 || true
    sleep 1
    if grep -q "SYSREPAIR_BACKDOOR_PROBE" "$NCAT_OUT" 2>/dev/null; then
        record_poc ncat_not_runnable 0 "ncat is still FUNCTIONAL - relayed data through a live listener"
    else
        record_poc ncat_not_runnable 1 "ncat could not relay data"
    fi
    pkill -f "ncat -l 127.0.0.1 $NCAT_PORT" 2>/dev/null || true
    rm -f "$NCAT_OUT"
else
    record_poc ncat_not_runnable 1 "ncat could not be executed"
fi

# --- hydra / john / nikto: execute and match their banners ---
HYDRA_BIN=$(command -v hydra 2>/dev/null || true)
if [ -n "$HYDRA_BIN" ]; then
    run_probe hydra_not_runnable "hydra" "Hydra v[0-9]|van Hauser" "$HYDRA_BIN" -h
else
    record_poc hydra_not_runnable 1 "hydra could not be executed"
fi

JOHN_BIN=$(command -v john 2>/dev/null || true)
if [ -n "$JOHN_BIN" ]; then
    run_probe john_not_runnable "john" "John the Ripper" "$JOHN_BIN"
else
    record_poc john_not_runnable 1 "john could not be executed"
fi

NIKTO_BIN=$(command -v nikto 2>/dev/null || true)
if [ -n "$NIKTO_BIN" ]; then
    run_probe nikto_not_runnable "nikto" "Nikto|nikto\.pl" "$NIKTO_BIN" -Version
else
    record_poc nikto_not_runnable 1 "nikto could not be executed"
fi

# --- Stragglers: any executable copy left OUTSIDE $PATH is just as usable ---
# (e.g. `rm /usr/bin/nmap` when /usr/bin/nmap was only a symlink, or a binary
#  stashed in /opt). Execute whatever we find.
echo ""
echo "=== PoC Behavioral Test: hunting executable copies outside \$PATH ==="
for tool in nmap ncat hydra john nikto; do
    STRAY_FOUND=""
    while IFS= read -r stray; do
        [ -z "$stray" ] && continue
        [ -x "$stray" ] || continue
        STRAY_OUT=$(HOME="$PROBE_HOME" timeout 20 "$stray" --version 2>&1 || true)
        STRAY_OUT="$STRAY_OUT$(HOME="$PROBE_HOME" timeout 20 "$stray" -h 2>&1 || true)"
        if echo "$STRAY_OUT" | grep -qiE "Nmap|Ncat|Hydra v[0-9]|John the Ripper|Nikto"; then
            STRAY_FOUND="$STRAY_FOUND $stray"
        fi
    done <<EOF
$(find / -xdev -type f -name "$tool" -perm -u+x 2>/dev/null | head -5)
EOF
    if [ -n "$STRAY_FOUND" ]; then
        record_poc "no_stray_${tool}_copy" 0 "a working copy of $tool survives at:$STRAY_FOUND"
    else
        record_poc "no_stray_${tool}_copy" 1
    fi
done
rm -rf "$PROBE_HOME"

echo ""
echo "=== Regression Test: Legitimate tools still present ==="

# Verify legitimate tools remain
for tool in curl wget ping ip; do
    if which "$tool" > /dev/null 2>&1; then
        record_reg "${tool}_still_present" 1
    else
        record_reg "${tool}_still_present" 0 "legitimate tool $tool was removed"
    fi
done

# Check that basic system functionality works
if ps aux > /dev/null 2>&1; then
    record_reg process_listing_works 1
else
    record_reg process_listing_works 0 "process listing broken"
fi

if ping -c 1 -W 2 127.0.0.1 > /dev/null 2>&1; then
    record_reg network_connectivity_works 1
else
    record_reg network_connectivity_works 0 "network connectivity broken"
fi

verify_finish
