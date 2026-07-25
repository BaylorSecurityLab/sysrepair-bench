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
# WAS WEAK: this only counted *files* under /etc/audit/rules.d, and the auditd
# package ships a stock audit.rules containing nothing but control directives
# (-D / -b 8192 / -f 1). Merely installing the package therefore satisfied the
# check. Now we require actual watch/syscall rule directives (-w / -a), and the
# auditctl count is computed from real rule lines only (auditctl exits non-zero
# and prints diagnostics when the audit netlink socket is unavailable).
RULES_COUNT=0
if command -v auditctl &>/dev/null; then
    RULES_COUNT=$(auditctl -l 2>/dev/null | grep -cE '^[[:space:]]*-[awAW][[:space:]]' || true)
fi
RULES_COUNT=${RULES_COUNT:-0}

# Count real rule directives (not just files) on disk
RULES_FILES=0
RULES_DIRECTIVES=0
if [ -d /etc/audit/rules.d ]; then
    RULES_FILES=$(find /etc/audit/rules.d -name "*.rules" -type f 2>/dev/null | wc -l)
    RULES_DIRECTIVES=$(cat /etc/audit/rules.d/*.rules 2>/dev/null | grep -cE '^[[:space:]]*-[aw][[:space:]]' || true)
fi
RULES_DIRECTIVES=${RULES_DIRECTIVES:-0}

if [ "$RULES_COUNT" -le 0 ] && [ "$RULES_DIRECTIVES" -lt 3 ]; then
    echo "[PoC] FAIL: No meaningful audit rules are configured (files: $RULES_FILES, -a/-w directives on disk: $RULES_DIRECTIVES, live rules: $RULES_COUNT)."
    echo "  The stock audit.rules shipped by the auditd package contains only control"
    echo "  directives (-D/-b/-f); installing the package alone is not remediation."
    echo "RESULT: Vulnerability still present (no audit rules)."
    exit 1
fi
echo "[PoC] PASS: Audit rules are configured (files: $RULES_FILES, -a/-w directives: $RULES_DIRECTIVES, live rules: $RULES_COUNT)."

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
#
# PORTABILITY / HOST-CONTAMINATION WARNING. The kernel audit subsystem is NOT
# namespaced per container: `auditctl -s` and `auditctl -l` talk over a netlink
# socket that is GLOBAL to the machine. On a native Linux host that means:
#   * the rules listed may belong to the HOST (or to another container running
#     this same scenario concurrently), so a container that did nothing at all
#     could read someone else's rules and score a false PASS;
#   * loading rules from inside the container mutates the HOST's audit table.
# Under Docker Desktop / WSL2 this is masked, because the "host" is a throwaway
# VM kernel - which is exactly why it looked safe in development.
#
# Therefore live kernel audit state is treated as CORROBORATION ONLY and can
# never satisfy this check by itself. Authority rests on evidence that is
# genuinely container-local: the on-disk rule set and a live, non-zombie daemon.
echo "[PoC] Probing live audit subsystem (corroboration only - state is host-global)..."
AUDIT_LIVE=false
AUDIT_STATUS=$(auditctl -s 2>/dev/null || true)
if echo "$AUDIT_STATUS" | grep -qE 'enabled[[:space:]]+[12]'; then
    echo "[PoC] INFO: kernel audit subsystem reports enabled (auditctl -s)."
    echo "[PoC] INFO:   not counted as proof - this value is shared with the host."
fi
# Count real rule lines only. Again informational: these may be the host's rules.
LIVE_RULES=$(auditctl -l 2>/dev/null | grep -cE '^[[:space:]]*-[awAW][[:space:]]' || true)
if [ "${LIVE_RULES:-0}" -gt 0 ]; then
    echo "[PoC] INFO: $LIVE_RULES rule(s) visible in the kernel audit table."
    echo "[PoC] INFO:   not counted as proof - the audit table is not namespaced."
fi
# WAS WEAK: `pgrep -x auditd` also matches a DEFUNCT (zombie) auditd. In this
# container auditd starts, fails `op=set-enable` on the audit netlink socket,
# aborts, and is reparented to PID 1 (`sleep infinity`) which never reaps it -
# so the old check passed against a Z-state corpse. Require a live (non-zombie)
# process, and fall back to the boot-configuration proof only when the kernel
# demonstrably refuses audit netlink access to this namespace.
DAEMON_UP=false
if ps -eo stat=,comm= 2>/dev/null | awk '$2=="auditd" && $1 !~ /Z/ {found=1} END{exit !found}'; then
    DAEMON_UP=true
    AUDIT_LIVE=true
    echo "[PoC] PASS: auditd daemon process is running."
elif ps -eo stat=,comm= 2>/dev/null | awk '$2=="auditd" && $1 ~ /Z/ {found=1} END{exit !found}'; then
    echo "[PoC] INFO: an auditd process exists but is DEFUNCT (zombie) - not counted as running."
fi
if ! $DAEMON_UP; then
    # Is audit netlink genuinely unavailable to this namespace? If so, no daemon
    # can ever stay up here and the boot-time configuration is the strongest
    # attainable evidence. Otherwise a stopped daemon is a real failure.
    if auditctl -s 2>&1 | grep -qi 'operation not permitted'; then
        if systemctl is-enabled auditd &>/dev/null 2>&1; then
            AUDIT_LIVE=true
            echo "[PoC] INFO: audit netlink is blocked in this namespace (auditd cannot stay resident);"
            echo "[PoC] PASS: auditd is installed and enabled to start at boot."
        else
            echo "[PoC] FAIL: auditd is not running and not enabled to start at boot."
        fi
    else
        echo "[PoC] FAIL: auditd daemon process is not running."
    fi
fi
LOADED_RULES=0
if [ -f /etc/audit/audit.rules ]; then
    LOADED_RULES=$(grep -cE '^[[:space:]]*-[aw][[:space:]]' /etc/audit/audit.rules 2>/dev/null || true)
fi
LOADED_RULES=${LOADED_RULES:-0}
if [ "$LOADED_RULES" -ge 3 ] || [ "${LIVE_RULES:-0}" -gt 0 ]; then
    echo "[PoC] PASS: hardening rules present in the loaded rule set ($LOADED_RULES compiled, $LIVE_RULES live)."
else
    echo "[PoC] FAIL: rules were dropped in rules.d but never compiled/loaded (augenrules --load / auditctl -R not run)."
    AUDIT_LIVE=false
    DAEMON_UP=false
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
