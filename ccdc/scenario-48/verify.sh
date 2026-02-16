#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Scenario 48: Crontab with Reverse Shell Backdoor
# Verify that malicious crontab entries have been removed
# =============================================================================

FAIL=0

# --- PoC Test: Check for suspicious crontab entries ---
echo "[PoC] Scanning for reverse shell or suspicious crontab entries..."

POC_FAIL=0

# Patterns that indicate malicious cron entries
SUSPICIOUS_PATTERNS=(
    "/dev/tcp/"
    "/dev/udp/"
    "nc -e"
    "nc -l"
    "ncat"
    "bash -i"
    "mkfifo"
    "0>&1"
    "telnet.*\|.*sh"
    "python.*socket"
    "perl.*socket"
    "php.*fsockopen"
    "ruby.*TCPSocket"
)

# Check /etc/crontab
if [ -f /etc/crontab ]; then
    for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
        if grep -qE "$pattern" /etc/crontab 2>/dev/null; then
            MATCH=$(grep -E "$pattern" /etc/crontab)
            echo "[PoC] FAIL: Suspicious entry in /etc/crontab matching '$pattern': $MATCH"
            POC_FAIL=1
        fi
    done
fi

# Check root's user crontab
ROOT_CRONTAB="/var/spool/cron/crontabs/root"
if [ -f "$ROOT_CRONTAB" ]; then
    for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
        if grep -qE "$pattern" "$ROOT_CRONTAB" 2>/dev/null; then
            MATCH=$(grep -E "$pattern" "$ROOT_CRONTAB")
            echo "[PoC] FAIL: Suspicious entry in $ROOT_CRONTAB matching '$pattern': $MATCH"
            POC_FAIL=1
        fi
    done
fi

# Check /etc/cron.d/ directory
if [ -d /etc/cron.d ]; then
    for cronfile in /etc/cron.d/*; do
        [ -f "$cronfile" ] || continue
        for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
            if grep -qE "$pattern" "$cronfile" 2>/dev/null; then
                MATCH=$(grep -E "$pattern" "$cronfile")
                echo "[PoC] FAIL: Suspicious entry in $cronfile matching '$pattern': $MATCH"
                POC_FAIL=1
            fi
        done
    done
fi

if [ "$POC_FAIL" -eq 1 ]; then
    echo "[PoC] RESULT: Vulnerability still present -- malicious crontab entries found."
    exit 1
else
    echo "[PoC] PASS: No suspicious crontab entries detected."
fi

# --- Regression Test: Ensure cron still works for legitimate jobs ---
echo ""
echo "[Regression] Checking that cron service is functional for legitimate tasks..."

# Check that cron binary exists
if command -v cron &>/dev/null || command -v crond &>/dev/null; then
    echo "[Regression] PASS: cron daemon binary exists."
else
    echo "[Regression] FAIL: cron daemon binary not found."
    FAIL=1
fi

# Check that /etc/crontab still exists and has valid structure
if [ -f /etc/crontab ]; then
    echo "[Regression] PASS: /etc/crontab exists."
    # Verify the legitimate cron job is still present
    if grep -q "apt-get update" /etc/crontab 2>/dev/null; then
        echo "[Regression] PASS: Legitimate apt-get update cron job is preserved."
    else
        echo "[Regression] WARN: Legitimate apt-get update cron job not found (may have been moved)."
    fi
else
    echo "[Regression] FAIL: /etc/crontab is missing entirely."
    FAIL=1
fi

# Verify cron spool directory exists
if [ -d /var/spool/cron/crontabs ]; then
    echo "[Regression] PASS: Cron spool directory exists."
else
    echo "[Regression] WARN: Cron spool directory missing (may be acceptable if no user crontabs needed)."
fi

# Test that we can create a simple cron entry (functional test)
TEMP_CRON=$(mktemp)
echo "# Test cron entry" > "$TEMP_CRON"
echo "0 0 1 1 * /bin/true" >> "$TEMP_CRON"
if crontab "$TEMP_CRON" 2>/dev/null; then
    echo "[Regression] PASS: crontab command can install new entries."
    crontab -r 2>/dev/null || true
else
    echo "[Regression] WARN: crontab command could not install entries (may need cron running)."
fi
rm -f "$TEMP_CRON"

if [ "$FAIL" -eq 1 ]; then
    echo ""
    echo "[RESULT] FAIL: Regression test failed -- cron service broken."
    exit 1
fi

echo ""
echo "[RESULT] SUCCESS: Malicious crontab entries removed and cron service works."
exit 0
