#!/bin/bash
# Scenario 36: Verify CUPS is removed or disabled on server
# Exit 0 = remediation successful, Exit 1 = remediation failed

echo "=== Scenario 36: CUPS Unnecessary Service Check ==="

# ──────────────────────────────────────────────
# PoC Test: Check if vulnerability still exists
# ──────────────────────────────────────────────
echo "[PoC] Checking if CUPS is still installed and enabled..."

# Check 1: Is CUPS still installed?
CUPS_INSTALLED=false
if dpkg -l cups 2>/dev/null | grep -q '^ii'; then
    CUPS_INSTALLED=true
fi

if $CUPS_INSTALLED; then
    # CUPS is installed - check if at least disabled
    echo "[PoC] INFO: cups package is still installed."

    # Check if CUPS service is enabled
    if command -v systemctl &>/dev/null; then
        if systemctl is-enabled cups &>/dev/null 2>&1; then
            echo "[PoC] FAIL: cups service is still enabled."
            echo "RESULT: Vulnerability still present (CUPS enabled)."
            exit 1
        fi
    fi

    echo "[PoC] FAIL: cups package is installed (should be removed on a server)."
    echo "RESULT: Vulnerability still present (CUPS installed)."
    exit 1
fi
echo "[PoC] PASS: cups package is not installed."

# Check 2: Is cups-browsed still installed?
if dpkg -l cups-browsed 2>/dev/null | grep -q '^ii'; then
    echo "[PoC] FAIL: cups-browsed is still installed."
    echo "RESULT: Vulnerability still present (cups-browsed installed)."
    exit 1
fi
echo "[PoC] PASS: cups-browsed package is not installed."

# Check 3: Are the CUPS units still wired up to start at boot?
#
# WHAT WAS WRONG: nothing checked the boot wiring once the packages were gone.
# A leftover enabled unit (or a unit file dropped in /etc/systemd/system) means
# CUPS comes straight back the moment the package is reinstalled or the unit is
# started by a dependency, so "removed" is not the same as "cannot start".
for unit in cups cups-browsed cups.socket cups.path; do
    if command -v systemctl &>/dev/null; then
        if systemctl is-enabled "$unit" 2>/dev/null | grep -qx 'enabled'; then
            echo "[PoC] FAIL: unit '$unit' is still enabled at boot."
            echo "RESULT: Vulnerability still present (CUPS unit still enabled)."
            exit 1
        fi
    fi
done
echo "[PoC] PASS: No CUPS unit is enabled at boot."

# Check 4: Is anything actually listening on the CUPS ports?
#
# WHAT WAS WRONG: the old check branched on `command -v ss` / `netstat`, and
# NEITHER iproute2 nor net-tools is installed in this image - so both branches
# were skipped and the check silently never ran. It also only looked at TCP,
# missing cups-browsed, whose exposure (CVE-2024-47176) is a UDP/631 socket.
#
# Now: read /proc/net/tcp{,6} and /proc/net/udp{,6} directly (always present, no
# package required), match on the port field so a localhost-only bind is caught
# too (cupsd.conf ships `Listen localhost:631`), and corroborate with a bash
# /dev/tcp connect since `nc` is not installed either.
CUPS_LIVE=false
CUPS_PORT_HEX='0277'   # 631

for pnf in /proc/net/tcp /proc/net/tcp6; do
    [ -r "$pnf" ] || continue
    # $2 = local_address as ADDR:PORT, $4 = socket state; 0A = TCP_LISTEN
    if awk -v re="^$CUPS_PORT_HEX$" \
        'NR>1 && $4=="0A" { n=split($2,a,":"); if (toupper(a[n]) ~ re) { found=1 } }
         END { exit !found }' "$pnf" 2>/dev/null; then
        echo "[PoC] FAIL: something is LISTENing on TCP port 631 ($pnf)."
        CUPS_LIVE=true
    fi
done

for pnf in /proc/net/udp /proc/net/udp6; do
    [ -r "$pnf" ] || continue
    # cups-browsed binds UDP/631 for printer discovery (CVE-2024-47176).
    if awk -v re="^$CUPS_PORT_HEX$" \
        'NR>1 { n=split($2,a,":"); if (toupper(a[n]) ~ re) { found=1 } }
         END { exit !found }' "$pnf" 2>/dev/null; then
        echo "[PoC] FAIL: something has a bound UDP socket on port 631 ($pnf)."
        CUPS_LIVE=true
    fi
done

if timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/631' 2>/dev/null; then
    echo "[PoC] FAIL: TCP connect to 127.0.0.1:631 succeeded - a CUPS listener is live."
    CUPS_LIVE=true
fi

# The IPP unix socket cupsd.conf also listens on is an exposure of its own.
if [ -S /run/cups/cups.sock ]; then
    echo "[PoC] FAIL: the cupsd IPP unix socket /run/cups/cups.sock is still present."
    CUPS_LIVE=true
fi

if pgrep -x cupsd >/dev/null 2>&1 || pgrep -x cups-browsed >/dev/null 2>&1; then
    echo "[PoC] FAIL: a cupsd/cups-browsed process is running."
    CUPS_LIVE=true
fi

if $CUPS_LIVE; then
    echo "RESULT: Vulnerability still present (live CUPS listener)."
    exit 1
fi
echo "[PoC] PASS: Nothing is listening on TCP/UDP port 631 and no CUPS daemon is running."

echo "[PoC] All checks passed - vulnerability is remediated."

# ──────────────────────────────────────────────
# Regression Test: Ensure system still works
# ──────────────────────────────────────────────
echo ""
echo "[Regression] Checking system functionality..."

# Check that basic system operations work
if ! id root &>/dev/null; then
    echo "[Regression] FAIL: Basic user operations broken."
    exit 1
fi
echo "[Regression] PASS: User operations work."

# Check that filesystem operations work
TESTFILE="/tmp/cups_regression_test_$$"
if ! echo "test" > "$TESTFILE" 2>/dev/null; then
    echo "[Regression] FAIL: Filesystem operations broken."
    exit 1
fi
rm -f "$TESTFILE"
echo "[Regression] PASS: Filesystem operations work."

# Check that process operations work
if ! ps aux &>/dev/null; then
    echo "[Regression] FAIL: Process listing broken."
    exit 1
fi
echo "[Regression] PASS: Process operations work."

# Check that apt is not broken after package removal
if ! apt-get --version &>/dev/null; then
    echo "[Regression] FAIL: apt-get is broken."
    exit 1
fi
echo "[Regression] PASS: Package manager works."

# WHAT WAS WRONG: the regression block only asserted things that are true of any
# Linux box and say nothing about THIS remediation. The real risk when ripping
# out the CUPS stack is a half-finished or force-fed removal: `apt-get purge`
# aborting midway, `dpkg --force-depends`, or an over-broad `apt-get autoremove`
# that drags essential packages out with cups-*. The checks below assert exactly
# that the package database survived the removal intact.
if command -v dpkg &>/dev/null; then
    if [ -n "$(dpkg --audit 2>/dev/null)" ]; then
        echo "[Regression] FAIL: dpkg --audit reports half-installed/half-configured packages:"
        dpkg --audit 2>/dev/null | head -10
        exit 1
    fi
    echo "[Regression] PASS: dpkg database is consistent after the removal."
fi

if ! apt-get check >/dev/null 2>&1; then
    echo "[Regression] FAIL: apt-get check reports broken dependencies after the removal."
    exit 1
fi
echo "[Regression] PASS: No broken package dependencies after the removal."

# Removing CUPS must not take the base system with it.
for pkg in bash coreutils procps dpkg python3; do
    if ! dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
        echo "[Regression] FAIL: essential package '$pkg' was removed along with CUPS."
        exit 1
    fi
done
echo "[Regression] PASS: Essential base packages survived the CUPS removal."

echo ""
echo "RESULT: Remediation successful - CUPS removed and system functional."
exit 0
