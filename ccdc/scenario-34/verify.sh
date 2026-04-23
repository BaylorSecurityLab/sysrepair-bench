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
# Hybrid probe: config grep is already above; here we exercise the actual
# apt periodic evaluation and the dry-run unattended-upgrade entrypoint.
# Baseline has neither the binary nor the config, so both sub-checks fail.
echo ""
echo "[PoC] Probing live unattended-upgrades behaviour..."
LIVE_OK=false

# Sub-probe A: the unattended-upgrade binary actually runs in dry-run mode
# (this parses the merged /etc/apt/apt.conf.d/* tree at runtime).
if command -v unattended-upgrade &>/dev/null; then
    if unattended-upgrade --dry-run --debug >/tmp/uu_dry.$$.log 2>&1; then
        if grep -qiE '(Allowed origins are|Initial blacklist|pkgs that look like)' /tmp/uu_dry.$$.log; then
            LIVE_OK=true
            echo "[PoC] PASS: unattended-upgrade --dry-run parsed runtime config."
        fi
    fi
    rm -f /tmp/uu_dry.$$.log
fi

# Sub-probe B: apt-config dump reflects the merged runtime periodic values
if command -v apt-config &>/dev/null; then
    PERIODIC_DUMP=$(apt-config dump 2>/dev/null | grep -E '^APT::Periodic::(Update-Package-Lists|Unattended-Upgrade)' || true)
    if echo "$PERIODIC_DUMP" | grep -qE 'Update-Package-Lists "1"' && \
       echo "$PERIODIC_DUMP" | grep -qE 'Unattended-Upgrade "1"'; then
        LIVE_OK=true
        echo "[PoC] PASS: apt-config dump shows Periodic knobs enabled at runtime."
    fi
fi

if ! $LIVE_OK; then
    echo "[PoC] FAIL: live unattended-upgrades behaviour not verified (binary missing or apt runtime values not set)."
    echo "RESULT: Vulnerability still present (no live unattended-upgrades state)."
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

# Check that apt-get update can run (basic connectivity test)
if ! apt-get update -qq 2>/dev/null; then
    echo "[Regression] WARNING: apt-get update failed (may be network-restricted in container)."
else
    echo "[Regression] PASS: apt-get update works."
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
