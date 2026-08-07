#!/bin/bash
# Scenario 34: Verify unattended-upgrades is installed and configured
#
# PoC checks:        unattended-upgrades is installed, enabled, scheduled, and
#                    resolves a security origin at runtime
# Regression checks: apt still works and can still refresh its indexes
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
# Exit 42 = precondition does not hold on this host
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "closed the vulnerability but broke apt" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

echo "=== Scenario 34: unattended-upgrades Configuration Check ==="

# ──────────────────────────────────────────────
# PoC Test: Check if vulnerability still exists
# ──────────────────────────────────────────────
echo "[PoC] Checking if unattended-upgrades is missing or unconfigured..."

# Check 1: Is unattended-upgrades installed?
if dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'; then
    record_poc unattended_upgrades_installed 1
else
    record_poc unattended_upgrades_installed 0 "unattended-upgrades package is not installed"
fi

# Check 2: Does the auto-upgrades config exist?
if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
    record_poc auto_upgrades_conf_present 1
else
    record_poc auto_upgrades_conf_present 0 "/etc/apt/apt.conf.d/20auto-upgrades does not exist"
fi

# Check 3: Is Update-Package-Lists enabled?
if grep -qE 'APT::Periodic::Update-Package-Lists\s+"1"' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; then
    record_poc update_package_lists_enabled 1
else
    record_poc update_package_lists_enabled 0 "APT::Periodic::Update-Package-Lists is not set to 1"
fi

# Check 4: Is Unattended-Upgrade enabled?
if grep -qE 'APT::Periodic::Unattended-Upgrade\s+"1"' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; then
    record_poc unattended_upgrade_enabled 1
else
    record_poc unattended_upgrade_enabled 0 "APT::Periodic::Unattended-Upgrade is not set to 1"
fi

# Check 5: Does the unattended-upgrades config exist with security origins?
# Advisory only in the original verifier - kept advisory here on purpose; the
# authoritative security-origin evidence is the runtime probe further down.
if [ -f /etc/apt/apt.conf.d/50unattended-upgrades ]; then
    if grep -qE '(security|Security)' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null; then
        echo "[PoC] INFO: Security updates are configured in 50unattended-upgrades."
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

UU_BIN_OK=false
if command -v unattended-upgrade &>/dev/null; then
    UU_BIN_OK=true
    record_poc unattended_upgrade_binary_present 1
else
    record_poc unattended_upgrade_binary_present 0 "the unattended-upgrade entry point is not installed"
fi

UU_LOG=/tmp/uu_dry.$$.log
if $UU_BIN_OK; then
    if unattended-upgrade --dry-run --debug >"$UU_LOG" 2>&1; then
        record_poc unattended_upgrade_dry_run_ok 1
    else
        record_poc unattended_upgrade_dry_run_ok 0 "'unattended-upgrade --dry-run' exited non-zero - it cannot run on this host"
        tail -5 "$UU_LOG" 2>/dev/null || true
    fi
else
    record_poc unattended_upgrade_dry_run_ok 0 "no unattended-upgrades runtime to dry-run"
fi

if [ -f "$UU_LOG" ] && grep -qiE '(Allowed origins are|Initial blacklist|pkgs that look like)' "$UU_LOG"; then
    record_poc unattended_upgrade_parses_runtime_config 1
else
    record_poc unattended_upgrade_parses_runtime_config 0 "unattended-upgrade produced no origin resolution - runtime config not parsed"
    tail -5 "$UU_LOG" 2>/dev/null || true
fi

# The origins it resolved must actually include a security pocket, otherwise the
# daemon would run happily and still never apply a security update.
ORIGINS="$(grep -i 'Allowed origins are' "$UU_LOG" 2>/dev/null | head -1 || true)"
if echo "$ORIGINS" | grep -qiE '(security|esm)'; then
    record_poc security_pocket_in_allowed_origins 1
    echo "  $ORIGINS"
else
    record_poc security_pocket_in_allowed_origins 0 "resolved allowed origins contain no security pocket: ${ORIGINS:-<none resolved>}"
fi
rm -f "$UU_LOG"

# Corroborating signal only (equivalent to the config grep above).
if command -v apt-config &>/dev/null; then
    PERIODIC_DUMP="$(apt-config dump 2>/dev/null | grep -E '^APT::Periodic::(Update-Package-Lists|Unattended-Upgrade)' || true)"
    if echo "$PERIODIC_DUMP" | grep -qE 'Update-Package-Lists "1"' && \
       echo "$PERIODIC_DUMP" | grep -qE 'Unattended-Upgrade "1"'; then
        record_poc apt_periodic_knobs_live 1
    else
        record_poc apt_periodic_knobs_live 0 "apt-config dump does not show both Periodic knobs at \"1\": ${PERIODIC_DUMP:-<empty>}"
    fi
fi

# Nothing schedules the periodic run without a timer or the cron.daily shim, so
# the knobs above would never actually fire.
if [ -f /lib/systemd/system/apt-daily-upgrade.timer ] || \
   [ -f /usr/lib/systemd/system/apt-daily-upgrade.timer ] || \
   [ -f /etc/cron.daily/apt-compat ]; then
    record_poc periodic_trigger_installed 1
else
    record_poc periodic_trigger_installed 0 "no apt periodic trigger installed - the Periodic knobs would never fire"
fi

# ──────────────────────────────────────────────
# Regression Test: Ensure apt still works
# ──────────────────────────────────────────────
echo ""
echo "[Regression] Checking system functionality..."

# Check that apt-get works
if apt-get --version &>/dev/null; then
    record_reg apt_get_usable 1
else
    record_reg apt_get_usable 0 "apt-get is broken"
fi

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
    record_reg apt_update_works 1
    rm -f /tmp/aptreg.$$.log
else
    sleep 5
    if apt_update_ok; then
        record_reg apt_update_works 1
        rm -f /tmp/aptreg.$$.log
    else
        record_reg apt_update_works 0 "apt-get update cannot refresh the package indexes - apt sources are broken"
        tail -3 /tmp/aptreg.$$.log 2>/dev/null || true
        rm -f /tmp/aptreg.$$.log
    fi
fi

# Check basic system operations
if id root &>/dev/null; then
    record_reg user_operations_work 1
else
    record_reg user_operations_work 0 "basic user operations broken"
fi

if ps aux &>/dev/null; then
    record_reg process_operations_work 1
else
    record_reg process_operations_work 0 "process listing broken"
fi

verify_finish
