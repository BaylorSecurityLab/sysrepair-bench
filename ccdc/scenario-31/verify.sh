#!/bin/bash
# Scenario 31: Verify auditd is installed, running, and has rules configured
# Exit 0 = remediation successful, Exit 1 = remediation failed

echo "=== Scenario 31: auditd Installation and Configuration Check ==="

# ──────────────────────────────────────────────
# PoC Test: Check if vulnerability still exists
# ──────────────────────────────────────────────
echo "[PoC] Checking if auditd is missing or unconfigured..."

# Check 1: Is auditd installed?
if ! command -v auditd &>/dev/null && ! dpkg -l auditd 2>/dev/null | grep -q '^ii'; then
    echo "[PoC] FAIL: auditd is not installed."
    echo "RESULT: Vulnerability still present (auditd not installed)."
    exit 1
fi
echo "[PoC] PASS: auditd package is installed."

# Check 2: Is auditd service enabled?
if command -v systemctl &>/dev/null; then
    if ! systemctl is-enabled auditd &>/dev/null 2>&1; then
        echo "[PoC] FAIL: auditd service is not enabled."
        echo "RESULT: Vulnerability still present (auditd not enabled)."
        exit 1
    fi
    echo "[PoC] PASS: auditd service is enabled."
fi

# Check 3: Do audit rules exist?
RULES_COUNT=0
if command -v auditctl &>/dev/null; then
    RULES_COUNT=$(auditctl -l 2>/dev/null | grep -cv "^No rules" || echo "0")
fi

# Also check for rules files on disk
RULES_FILES=0
if [ -d /etc/audit/rules.d ]; then
    RULES_FILES=$(find /etc/audit/rules.d -name "*.rules" -type f 2>/dev/null | wc -l)
fi

if [ "$RULES_COUNT" -le 0 ] && [ "$RULES_FILES" -le 0 ]; then
    echo "[PoC] FAIL: No audit rules are configured."
    echo "RESULT: Vulnerability still present (no audit rules)."
    exit 1
fi
echo "[PoC] PASS: Audit rules are configured (files: $RULES_FILES, active rules: $RULES_COUNT)."

# Check 4: Verify critical audit rules exist (at minimum, some key areas)
RULES_CONTENT=""
if [ -d /etc/audit/rules.d ]; then
    RULES_CONTENT=$(cat /etc/audit/rules.d/*.rules 2>/dev/null)
fi
if command -v auditctl &>/dev/null; then
    RULES_CONTENT="$RULES_CONTENT $(auditctl -l 2>/dev/null)"
fi

# Check for at least some security-relevant audit rules
HAS_TIME_RULES=false
HAS_IDENTITY_RULES=false
HAS_ACCESS_RULES=false

if echo "$RULES_CONTENT" | grep -qE '(adjtimex|settimeofday|clock_settime)'; then
    HAS_TIME_RULES=true
fi
if echo "$RULES_CONTENT" | grep -qE '(/etc/passwd|/etc/shadow|/etc/group|identity)'; then
    HAS_IDENTITY_RULES=true
fi
if echo "$RULES_CONTENT" | grep -qE '(EACCES|EPERM|access)'; then
    HAS_ACCESS_RULES=true
fi

if ! $HAS_TIME_RULES && ! $HAS_IDENTITY_RULES && ! $HAS_ACCESS_RULES; then
    echo "[PoC] FAIL: No meaningful security audit rules found."
    echo "RESULT: Vulnerability still present (audit rules insufficient)."
    exit 1
fi
echo "[PoC] PASS: Security-relevant audit rules are present."

# --- PoC Behavioral Test: audit subsystem is live in the running kernel ---
# auditctl -s / auditctl -l talk to the kernel via netlink; a bare baseline
# has no auditd binary so these calls are absent entirely. On a remediated
# host the kernel reports enabled=1 / enabled=2.
echo "[PoC] Probing live audit subsystem..."
AUDIT_LIVE=false
if command -v auditctl &>/dev/null; then
    AUDIT_STATUS=$(auditctl -s 2>/dev/null || true)
    if echo "$AUDIT_STATUS" | grep -qE 'enabled[[:space:]]+[12]'; then
        AUDIT_LIVE=true
        echo "[PoC] PASS: kernel audit subsystem reports enabled (auditctl -s)."
    fi
    # auditd process should be running OR at least one rule loaded in-kernel
    if pgrep -x auditd >/dev/null 2>&1; then
        AUDIT_LIVE=true
        echo "[PoC] PASS: auditd daemon process is running."
    fi
    LIVE_RULES=$(auditctl -l 2>/dev/null | grep -cvE '^(No rules|$)' || true)
    if [ "${LIVE_RULES:-0}" -gt 0 ]; then
        AUDIT_LIVE=true
        echo "[PoC] PASS: $LIVE_RULES rule(s) loaded in live kernel audit table."
    fi
fi
if ! $AUDIT_LIVE; then
    echo "[PoC] FAIL: audit subsystem is not active in the running kernel (no daemon, no live rules, auditctl -s not enabled)."
    echo "RESULT: Vulnerability still present (audit not live)."
    exit 1
fi

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
TESTFILE="/tmp/audit_regression_test_$$"
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

echo ""
echo "RESULT: Remediation successful - auditd installed, configured, and system functional."
exit 0
