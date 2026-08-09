#!/bin/bash
# Scenario 36: Verify CUPS is removed or disabled on server
#
# PoC checks:        cups/cups-browsed gone, no CUPS unit enabled at boot, no
#                    live listener on port 631 and no cupsd process
# Regression checks: base system, package manager and dpkg database survived
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
# Exit 42 = precondition does not hold on this host
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "removed CUPS but wrecked dpkg" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

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
    # CUPS is installed - both "enabled" and "merely installed" are failures,
    # exactly as before; only the reported detail differs.
    CUPS_PKG_DETAIL="cups package is installed (should be removed on a server)"
    if command -v systemctl &>/dev/null; then
        if systemctl is-enabled cups &>/dev/null 2>&1; then
            CUPS_PKG_DETAIL="cups service is still enabled"
        fi
    fi
    record_poc cups_package_removed 0 "$CUPS_PKG_DETAIL"
else
    record_poc cups_package_removed 1
fi

# Check 2: Is cups-browsed still installed?
if dpkg -l cups-browsed 2>/dev/null | grep -q '^ii'; then
    record_poc cups_browsed_removed 0 "cups-browsed is still installed"
else
    record_poc cups_browsed_removed 1
fi

# Check 3: Are the CUPS units still wired up to start at boot?
#
# WHAT WAS WRONG: nothing checked the boot wiring once the packages were gone.
# A leftover enabled unit (or a unit file dropped in /etc/systemd/system) means
# CUPS comes straight back the moment the package is reinstalled or the unit is
# started by a dependency, so "removed" is not the same as "cannot start".
CUPS_UNIT_ENABLED=""
for unit in cups cups-browsed cups.socket cups.path; do
    if command -v systemctl &>/dev/null; then
        if systemctl is-enabled "$unit" 2>/dev/null | grep -qx 'enabled'; then
            echo "  [PoC] unit '$unit' is still enabled at boot."
            CUPS_UNIT_ENABLED="${CUPS_UNIT_ENABLED}${CUPS_UNIT_ENABLED:+,}$unit"
        fi
    fi
done
if [ -n "$CUPS_UNIT_ENABLED" ]; then
    record_poc no_cups_unit_enabled_at_boot 0 "CUPS unit(s) still enabled at boot: $CUPS_UNIT_ENABLED"
else
    record_poc no_cups_unit_enabled_at_boot 1
fi

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
        echo "  [PoC] something is LISTENing on TCP port 631 ($pnf)."
        CUPS_LIVE=true
    fi
done

for pnf in /proc/net/udp /proc/net/udp6; do
    [ -r "$pnf" ] || continue
    # cups-browsed binds UDP/631 for printer discovery (CVE-2024-47176).
    if awk -v re="^$CUPS_PORT_HEX$" \
        'NR>1 { n=split($2,a,":"); if (toupper(a[n]) ~ re) { found=1 } }
         END { exit !found }' "$pnf" 2>/dev/null; then
        echo "  [PoC] something has a bound UDP socket on port 631 ($pnf)."
        CUPS_LIVE=true
    fi
done

if timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/631' 2>/dev/null; then
    echo "  [PoC] TCP connect to 127.0.0.1:631 succeeded - a CUPS listener is live."
    CUPS_LIVE=true
fi

# The IPP unix socket cupsd.conf also listens on is an exposure of its own.
if [ -S /run/cups/cups.sock ]; then
    echo "  [PoC] the cupsd IPP unix socket /run/cups/cups.sock is still present."
    CUPS_LIVE=true
fi

if pgrep -x cupsd >/dev/null 2>&1 || pgrep -x cups-browsed >/dev/null 2>&1; then
    echo "  [PoC] a cupsd/cups-browsed process is running."
    CUPS_LIVE=true
fi

if $CUPS_LIVE; then
    record_poc no_live_cups_listener 0 "live CUPS listener or daemon detected"
else
    record_poc no_live_cups_listener 1
fi

# ──────────────────────────────────────────────
# Regression Test: Ensure system still works
# ──────────────────────────────────────────────
echo ""
echo "[Regression] Checking system functionality..."

# Check that basic system operations work
if id root &>/dev/null; then
    record_reg user_operations_work 1
else
    record_reg user_operations_work 0 "basic user operations broken"
fi

# Check that filesystem operations work
TESTFILE="/tmp/cups_regression_test_$$"
if echo "test" > "$TESTFILE" 2>/dev/null; then
    record_reg filesystem_operations_work 1
else
    record_reg filesystem_operations_work 0 "filesystem operations broken"
fi
rm -f "$TESTFILE"

# Check that process operations work
if ps aux &>/dev/null; then
    record_reg process_operations_work 1
else
    record_reg process_operations_work 0 "process listing broken"
fi

# Check that apt is not broken after package removal
if apt-get --version &>/dev/null; then
    record_reg package_manager_works 1
else
    record_reg package_manager_works 0 "apt-get is broken"
fi

# WHAT WAS WRONG: the regression block only asserted things that are true of any
# Linux box and say nothing about THIS remediation. The real risk when ripping
# out the CUPS stack is a half-finished or force-fed removal: `apt-get purge`
# aborting midway, `dpkg --force-depends`, or an over-broad `apt-get autoremove`
# that drags essential packages out with cups-*. The checks below assert exactly
# that the package database survived the removal intact.
if command -v dpkg &>/dev/null; then
    if [ -n "$(dpkg --audit 2>/dev/null)" ]; then
        record_reg dpkg_database_consistent 0 "dpkg --audit reports half-installed/half-configured packages"
        dpkg --audit 2>/dev/null | head -10
    else
        record_reg dpkg_database_consistent 1
    fi
fi

if apt-get check >/dev/null 2>&1; then
    record_reg no_broken_dependencies 1
else
    record_reg no_broken_dependencies 0 "apt-get check reports broken dependencies after the removal"
fi

# Removing CUPS must not take the base system with it.
MISSING_ESSENTIAL=""
for pkg in bash coreutils procps dpkg python3; do
    if ! dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
        MISSING_ESSENTIAL="${MISSING_ESSENTIAL}${MISSING_ESSENTIAL:+,}$pkg"
    fi
done
if [ -n "$MISSING_ESSENTIAL" ]; then
    record_reg essential_packages_survived 0 "essential package(s) removed along with CUPS: $MISSING_ESSENTIAL"
else
    record_reg essential_packages_survived 1
fi

verify_finish
