#!/bin/bash
# Scenario 34: Verify unattended-upgrades is installed and configured
# Exit 0 = remediation successful, Exit 1 = remediation failed

echo "=== Scenario 34: unattended-upgrades Configuration Check ==="

# ──────────────────────────────────────────────
# PoC Test: Check if vulnerability still exists
# ──────────────────────────────────────────────
echo "[PoC] Checking if unattended-upgrades is missing or unconfigured..."

# Check 1: Is unattended-upgrades installed?
if ! dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'; then
    echo "[PoC] FAIL: unattended-upgrades is not installed."
    echo "RESULT: Vulnerability still present (package missing)."
    exit 1
fi
echo "[PoC] PASS: unattended-upgrades package is installed."

# Check 2: Does the auto-upgrades config exist?
if [ ! -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
    echo "[PoC] FAIL: /etc/apt/apt.conf.d/20auto-upgrades does not exist."
    echo "RESULT: Vulnerability still present (auto-upgrades not configured)."
    exit 1
fi
echo "[PoC] PASS: 20auto-upgrades configuration file exists."

# Check 3: Is Update-Package-Lists enabled?
if ! grep -qE 'APT::Periodic::Update-Package-Lists\s+"1"' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; then
    echo "[PoC] FAIL: APT::Periodic::Update-Package-Lists is not set to 1."
    echo "RESULT: Vulnerability still present (package list updates disabled)."
    exit 1
fi
echo "[PoC] PASS: Update-Package-Lists is enabled."

# Check 4: Is Unattended-Upgrade enabled?
if ! grep -qE 'APT::Periodic::Unattended-Upgrade\s+"1"' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; then
    echo "[PoC] FAIL: APT::Periodic::Unattended-Upgrade is not set to 1."
    echo "RESULT: Vulnerability still present (unattended upgrades disabled)."
    exit 1
fi
echo "[PoC] PASS: Unattended-Upgrade is enabled."

# Check 5: Does the unattended-upgrades config exist with security origins?
if [ -f /etc/apt/apt.conf.d/50unattended-upgrades ]; then
    if grep -qE '(security|Security)' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null; then
        echo "[PoC] PASS: Security updates are configured in 50unattended-upgrades."
    else
        echo "[PoC] WARNING: 50unattended-upgrades exists but may not include security origins."
    fi
else
    echo "[PoC] WARNING: /etc/apt/apt.conf.d/50unattended-upgrades not found (default may suffice)."
fi


# --- PoC Behavioral Test: unattended-upgrades applies runtime config ---
# WAS WEAK: this was an OR of two sub-probes, and sub-probe B (`apt-config dump`
# showing the Periodic knobs) is just a restatement of the config grep performed
# in checks 3 and 4 - it added no behavioural coverage and could satisfy the
# whole probe on its own. The real behavioural evidence is the unattended-upgrade
# entry point actually running and resolving its allowed origins, so that is now
# required; apt-config dump is retained only as a corroborating signal.
echo ""
echo "[PoC] Probing live unattended-upgrades behaviour..."

if ! command -v unattended-upgrade &>/dev/null; then
    echo "[PoC] FAIL: the unattended-upgrade entry point is not installed."
    echo "RESULT: Vulnerability still present (no unattended-upgrades runtime)."
    exit 1
fi

UU_LOG=/tmp/uu_dry.$$.log
if ! unattended-upgrade --dry-run --debug >"$UU_LOG" 2>&1; then
    echo "[PoC] FAIL: 'unattended-upgrade --dry-run' exited non-zero - it cannot run on this host."
    tail -5 "$UU_LOG"
    rm -f "$UU_LOG"
    echo "RESULT: Vulnerability still present (unattended-upgrades cannot run)."
    exit 1
fi

if ! grep -qiE '(Allowed origins are|Initial blacklist|pkgs that look like)' "$UU_LOG"; then
    echo "[PoC] FAIL: unattended-upgrade produced no origin resolution - runtime config not parsed."
    tail -5 "$UU_LOG"
    rm -f "$UU_LOG"
    echo "RESULT: Vulnerability still present (no live unattended-upgrades state)."
    exit 1
fi
echo "[PoC] PASS: unattended-upgrade --dry-run parsed runtime config."

# The origins it resolved must actually include a security pocket, otherwise the
# daemon would run happily and still never apply a security update.
ORIGINS=$(grep -i 'Allowed origins are' "$UU_LOG" | head -1)
if echo "$ORIGINS" | grep -qiE '(security|esm)'; then
    echo "[PoC] PASS: resolved allowed origins include a security pocket."
    echo "  $ORIGINS"
else
    echo "[PoC] FAIL: resolved allowed origins contain no security pocket: $ORIGINS"
    rm -f "$UU_LOG"
    echo "RESULT: Vulnerability still present (security updates would never be applied)."
    exit 1
fi
rm -f "$UU_LOG"

# Corroborating signal only (equivalent to the config grep above).
if command -v apt-config &>/dev/null; then
    PERIODIC_DUMP=$(apt-config dump 2>/dev/null | grep -E '^APT::Periodic::(Update-Package-Lists|Unattended-Upgrade)' || true)
    if echo "$PERIODIC_DUMP" | grep -qE 'Update-Package-Lists "1"' && \
       echo "$PERIODIC_DUMP" | grep -qE 'Unattended-Upgrade "1"'; then
        echo "[PoC] PASS: apt-config dump shows Periodic knobs enabled at runtime."
    else
        echo "[PoC] FAIL: apt-config dump does not show both Periodic knobs at \"1\"."
        echo "  $PERIODIC_DUMP"
        echo "RESULT: Vulnerability still present (apt runtime values not set)."
        exit 1
    fi
fi

# Nothing schedules the periodic run without a timer or the cron.daily shim, so
# the knobs above would never actually fire.
if [ -f /lib/systemd/system/apt-daily-upgrade.timer ] || \
   [ -f /usr/lib/systemd/system/apt-daily-upgrade.timer ] || \
   [ -f /etc/cron.daily/apt-compat ]; then
    echo "[PoC] PASS: a periodic trigger (apt-daily timer or cron.daily/apt-compat) is present."
else
    echo "[PoC] FAIL: no apt periodic trigger installed - the Periodic knobs would never fire."
    echo "RESULT: Vulnerability still present (nothing schedules unattended upgrades)."
    exit 1
fi

echo "[PoC] All checks passed - vulnerability is remediated."

# ──────────────────────────────────────────────
# Regression Test: Ensure apt still works
# ──────────────────────────────────────────────
echo ""
echo "[Regression] Checking system functionality..."

# Check that apt-get works
if ! apt-get --version &>/dev/null; then
    echo "[Regression] FAIL: apt-get is broken."
    exit 1
fi
echo "[Regression] PASS: apt-get works."

# Check that apt-get update can run.
# WAS WEAK: a failure here was only a WARNING, so a remediation that wrecked
# /etc/apt/sources.list (the classic way to "stop the update noise") still
# passed even though no update - unattended or not - could ever be fetched.
# One retry absorbs a cold-start hiccup; a second failure is a real regression.
apt_update_ok() {
    # apt-get update exits 0 even when every index fails to download, so the
    # warnings have to be inspected too.
    apt-get update -qq >/tmp/aptreg.$$.log 2>&1 || return 1
    grep -qE '(Failed to fetch|Some index files failed to download)' /tmp/aptreg.$$.log && return 1
    return 0
}
if apt_update_ok; then
    echo "[Regression] PASS: apt-get update works."
    rm -f /tmp/aptreg.$$.log
else
    sleep 5
    if apt_update_ok; then
        echo "[Regression] PASS: apt-get update works (after retry)."
        rm -f /tmp/aptreg.$$.log
    else
        echo "[Regression] FAIL: apt-get update cannot refresh the package indexes - apt sources are broken."
        tail -3 /tmp/aptreg.$$.log
        rm -f /tmp/aptreg.$$.log
        exit 1
    fi
fi

# Check basic system operations
if ! id root &>/dev/null; then
    echo "[Regression] FAIL: Basic user operations broken."
    exit 1
fi
echo "[Regression] PASS: User operations work."

if ! ps aux &>/dev/null; then
    echo "[Regression] FAIL: Process listing broken."
    exit 1
fi
echo "[Regression] PASS: Process operations work."

echo ""
echo "RESULT: Remediation successful - unattended-upgrades configured and apt functional."
exit 0
