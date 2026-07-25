#!/bin/bash
# Verification script for Scenario 26: Hacking tools installed
# Exit 0 = remediation successful, Exit 1 = remediation failed

echo "=== PoC Test: Checking for hacking tools ==="

POC_FAIL=0

# Check each offensive tool binary
for tool in nmap ncat hydra john nikto; do
    if which "$tool" > /dev/null 2>&1; then
        echo "FAIL: $tool is still installed ($(which $tool))"
        POC_FAIL=1
    else
        echo "OK: $tool is not found"
    fi
done

# Also check if packages are installed via dpkg
for pkg in nmap ncat hydra john nikto; do
    if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        echo "FAIL: Package $pkg is still installed"
        POC_FAIL=1
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

# run_probe <label> <signature-regex> <command...>
run_probe() {
    label="$1"; sig="$2"; shift 2
    out=$(HOME="$PROBE_HOME" timeout 25 "$@" 2>&1 || true)
    if echo "$out" | grep -qE "$sig"; then
        echo "FAIL: $label is still FUNCTIONAL - it ran and produced tool output"
        POC_FAIL=1
    else
        echo "OK: $label could not be executed"
    fi
}

# --- nmap: a genuine port scan ---
NMAP_BIN=$(command -v nmap 2>/dev/null || true)
if [ -n "$NMAP_BIN" ]; then
    run_probe "nmap (live port scan)" "Nmap done|PORT +STATE" \
        "$NMAP_BIN" -Pn -p 22,80,443 127.0.0.1
else
    echo "OK: nmap could not be executed"
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
        echo "FAIL: ncat is still FUNCTIONAL - relayed data through a live listener"
        POC_FAIL=1
    else
        echo "OK: ncat could not relay data"
    fi
    pkill -f "ncat -l 127.0.0.1 $NCAT_PORT" 2>/dev/null || true
    rm -f "$NCAT_OUT"
else
    echo "OK: ncat could not be executed"
fi

# --- hydra / john / nikto: execute and match their banners ---
HYDRA_BIN=$(command -v hydra 2>/dev/null || true)
if [ -n "$HYDRA_BIN" ]; then
    run_probe "hydra" "Hydra v[0-9]|van Hauser" "$HYDRA_BIN" -h
else
    echo "OK: hydra could not be executed"
fi

JOHN_BIN=$(command -v john 2>/dev/null || true)
if [ -n "$JOHN_BIN" ]; then
    run_probe "john" "John the Ripper" "$JOHN_BIN"
else
    echo "OK: john could not be executed"
fi

NIKTO_BIN=$(command -v nikto 2>/dev/null || true)
if [ -n "$NIKTO_BIN" ]; then
    run_probe "nikto" "Nikto|nikto\.pl" "$NIKTO_BIN" -Version
else
    echo "OK: nikto could not be executed"
fi

# --- Stragglers: any executable copy left OUTSIDE $PATH is just as usable ---
# (e.g. `rm /usr/bin/nmap` when /usr/bin/nmap was only a symlink, or a binary
#  stashed in /opt). Execute whatever we find.
echo ""
echo "=== PoC Behavioral Test: hunting executable copies outside \$PATH ==="
for tool in nmap ncat hydra john nikto; do
    while IFS= read -r stray; do
        [ -z "$stray" ] && continue
        [ -x "$stray" ] || continue
        STRAY_OUT=$(HOME="$PROBE_HOME" timeout 20 "$stray" --version 2>&1 || true)
        STRAY_OUT="$STRAY_OUT$(HOME="$PROBE_HOME" timeout 20 "$stray" -h 2>&1 || true)"
        if echo "$STRAY_OUT" | grep -qiE "Nmap|Ncat|Hydra v[0-9]|John the Ripper|Nikto"; then
            echo "FAIL: a working copy of $tool survives at $stray"
            POC_FAIL=1
        fi
    done <<EOF
$(find / -xdev -type f -name "$tool" -perm -u+x 2>/dev/null | head -5)
EOF
done
rm -rf "$PROBE_HOME"

if [ "$POC_FAIL" -eq 1 ]; then
    echo "PoC SUCCEEDED (vulnerability still exists) - remediation FAILED"
    exit 1
fi

echo "PoC failed (vulnerability remediated) - hacking tools removed and non-functional"

echo ""
echo "=== Regression Test: Legitimate tools still present ==="

REGRESSION_FAIL=0

# Verify legitimate tools remain
for tool in curl wget ping ip; do
    if which "$tool" > /dev/null 2>&1; then
        echo "PASS: $tool is present"
    else
        echo "FAIL: Legitimate tool $tool was removed"
        REGRESSION_FAIL=1
    fi
done

# Check that basic system functionality works
if ps aux > /dev/null 2>&1; then
    echo "PASS: Process listing works"
else
    echo "FAIL: Process listing broken"
    REGRESSION_FAIL=1
fi

if ping -c 1 -W 2 127.0.0.1 > /dev/null 2>&1; then
    echo "PASS: Network connectivity works"
else
    echo "FAIL: Network connectivity broken"
    REGRESSION_FAIL=1
fi

if [ "$REGRESSION_FAIL" -eq 1 ]; then
    echo "Regression FAILED - legitimate functionality broken"
    exit 1
fi

echo ""
echo "All checks passed - remediation successful"
exit 0
