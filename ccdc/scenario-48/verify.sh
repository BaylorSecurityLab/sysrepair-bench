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

# Patterns that indicate malicious cron entries.
# WAS WEAK: the original list was 13 fixed strings aimed at one specific payload,
# so a reverse shell that avoided those literals sailed through. These now also
# cover raw IP:port callbacks, download-and-execute pipelines, encoded payloads
# and the common interpreter one-liners.
SUSPICIOUS_PATTERNS=(
    "/dev/tcp/"
    "/dev/udp/"
    "nc -e"
    "nc -l"
    "ncat"
    "socat"
    "bash -i"
    "sh -i"
    "mkfifo"
    "0>&1"
    "telnet.*\|.*sh"
    "python.*socket"
    "perl.*socket"
    "php.*fsockopen"
    "ruby.*TCPSocket"
    # generic reverse/So-called "callback" indicators
    "[0-9]{1,3}(\.[0-9]{1,3}){3}[:/][0-9]{2,5}"
    "(curl|wget)[^|]*\|[[:space:]]*(ba)?sh"
    "base64[[:space:]]+(-d|--decode)"
    "(python[0-9]?|perl|ruby|php|lua)[[:space:]]+-(c|e|r)[[:space:]]"
    "chmod[[:space:]]+[0-7]*[24]7[0-7]*"
    "/tmp/[^[:space:]]*[[:space:]]*(&|$)"
)

scan_file() {
    local f="$1" label="$2" pattern MATCH
    [ -f "$f" ] || return 0
    for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
        if grep -qE "$pattern" "$f" 2>/dev/null; then
            MATCH=$(grep -E "$pattern" "$f" | head -2)
            echo "[PoC] FAIL: Suspicious entry in $label matching '$pattern': $MATCH"
            POC_FAIL=1
        fi
    done
}

# WAS WEAK: only /etc/crontab, /var/spool/cron/crontabs/root and /etc/cron.d were
# scanned. A backdoor in any other user's spool file, in /etc/cron.{hourly,daily,
# weekly,monthly} or in /etc/anacrontab was invisible.
scan_file /etc/crontab "/etc/crontab"
scan_file /etc/anacrontab "/etc/anacrontab"

if [ -d /var/spool/cron/crontabs ]; then
    for cronfile in /var/spool/cron/crontabs/*; do
        [ -f "$cronfile" ] || continue
        scan_file "$cronfile" "$cronfile"
    done
fi

for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    [ -d "$d" ] || continue
    for cronfile in "$d"/*; do
        [ -f "$cronfile" ] || continue
        scan_file "$cronfile" "$cronfile"
    done
done

if [ "$POC_FAIL" -eq 1 ]; then
    echo "[PoC] RESULT: Vulnerability still present -- malicious crontab entries found."
    exit 1
else
    echo "[PoC] PASS: No suspicious crontab entries detected in any cron source."
fi

# --- PoC Behavioural Test: watch what the cron DAEMON actually dispatches ---
# WAS WEAK: everything above is a text scan of files on disk. Editing the files
# is not the same as the daemon's live view, and nothing here ever ran cron at all.
#
# WAS ALSO SLOW AND FLAKY: the previous version slept up to 70s waiting for a
# wall-clock minute boundary so it could watch the `* * * * *` backdoors fire, then
# looked at the log exactly once. That risked blowing a harness verify timeout, and
# on a loaded box the job could miss the window entirely and the check would silently
# see nothing. We now make every real cron job DUE IMMEDIATELY - vixie cron runs
# @reboot entries at daemon start - in a backed-up rewrite of the real cron sources,
# and POLL for the dispatch log instead of sleeping a fixed duration. Setting
# SHELL=/bin/true means the daemon still parses, schedules, forks and logs every real
# command verbatim without the payload actually being executed. Every file we touch
# is restored by the EXIT/INT/TERM trap, as is whether cron was running to begin with.
echo ""
echo "[PoC] Driving the live cron daemon and watching what it dispatches..."

if ! command -v cron >/dev/null 2>&1; then
    echo "[PoC] FAIL: the cron binary is missing - the live cron behaviour cannot be observed."
    exit 1
fi

CRON_WAS_RUNNING=0
if pgrep -x cron >/dev/null 2>&1; then CRON_WAS_RUNNING=1; fi
# Debian cron drops a zero-byte stamp in /run and refuses to run @reboot jobs a
# second time while it exists ("Skipping @reboot jobs -- not system startup"). If
# anything has already started cron on this box the probe would silently observe
# nothing, so the stamp has to be cleared and then put back as it was.
REBOOT_STAMP=/run/crond.reboot
REBOOT_STAMP_EXISTED=0
if [ -e "$REBOOT_STAMP" ]; then REBOOT_STAMP_EXISTED=1; fi

PROBE_DIR=""
CRON_BK=""
CRON_PID=""
restore_cron_state() {
    if [ -n "$CRON_PID" ]; then
        kill "$CRON_PID" 2>/dev/null || true
        wait "$CRON_PID" 2>/dev/null || true
        CRON_PID=""
    fi
    # Put the real cron sources back byte-for-byte before anything else.
    if [ -n "$CRON_BK" ] && [ -f "$CRON_BK" ]; then
        tar -C / -xpf "$CRON_BK" 2>/dev/null || true
    fi
    if [ -n "$PROBE_DIR" ]; then rm -rf "$PROBE_DIR"; fi
    PROBE_DIR=""; CRON_BK=""
    # Leave the box's cron process state exactly as we found it.
    if [ "$CRON_WAS_RUNNING" -eq 0 ]; then
        pkill -x cron >/dev/null 2>&1 || true
    elif ! pgrep -x cron >/dev/null 2>&1; then
        cron >/dev/null 2>&1 || true
    fi
    if [ "$REBOOT_STAMP_EXISTED" -eq 1 ]; then
        if [ ! -e "$REBOOT_STAMP" ]; then
            : > "$REBOOT_STAMP" 2>/dev/null || true
            chmod 000 "$REBOOT_STAMP" 2>/dev/null || true
        fi
    else
        rm -f "$REBOOT_STAMP" 2>/dev/null || true
    fi
    return 0
}
trap restore_cron_state EXIT INT TERM

PROBE_DIR=$(mktemp -d)
CRON_BK="$PROBE_DIR/cron-sources.tar"
BK_PATHS=()
for p in etc/crontab etc/cron.d var/spool/cron/crontabs; do
    if [ -e "/$p" ]; then BK_PATHS+=("$p"); fi
done
if [ "${#BK_PATHS[@]}" -gt 0 ]; then
    tar -C / -cpf "$CRON_BK" "${BK_PATHS[@]}" 2>/dev/null || true
fi
# Never touch the real cron sources unless we are certain we can put them back.
if [ ! -s "$CRON_BK" ]; then
    echo "[PoC] FAIL: could not snapshot the cron sources, so the live probe is refused"
    echo "  rather than risk leaving the schedule modified."
    exit 1
fi

# Rewrite each cron source so that every job keeps its command VERBATIM but becomes
# due right now (@reboot). Comments and environment assignments are dropped and
# replaced by SHELL=/bin/true so nothing is really executed.
DUE_NOW_AWK='
BEGIN { print "SHELL=/bin/true"; print "MAILTO=\"\"" }
/^[[:space:]]*#/ { next }
/^[[:space:]]*$/ { next }
/^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=/ { next }
{
    line = $0
    if ($1 ~ /^@/) n = 1; else if (NF >= 6) n = 5; else next
    pos = 1
    for (i = 1; i <= n; i++) { p = index(substr(line, pos), $i); pos = pos + p - 1 + length($i) }
    rest = substr(line, pos); sub(/^[[:space:]]+/, "", rest)
    if (rest == "") next
    print "@reboot " rest
}'

EXPECTED=0
make_due_now() {
    local f="$1" n
    [ -f "$f" ] || return 0
    awk "$DUE_NOW_AWK" "$f" > "$PROBE_DIR/rewritten" 2>/dev/null || return 0
    n=$(grep -c '^@reboot ' "$PROBE_DIR/rewritten" 2>/dev/null || true)
    [ -n "$n" ] || n=0
    cat "$PROBE_DIR/rewritten" > "$f"
    EXPECTED=$((EXPECTED + n))
}
make_due_now /etc/crontab
for cronfile in /etc/cron.d/* /var/spool/cron/crontabs/*; do
    make_due_now "$cronfile"
done

LIVE_LOG="$PROBE_DIR/cron.log"
pkill -x cron >/dev/null 2>&1 || true
rm -f "$REBOOT_STAMP" 2>/dev/null || true
cron -f -x load >"$LIVE_LOG" 2>&1 &
CRON_PID=$!

# kill -0 succeeds on a ZOMBIE, so it cannot tell "daemon running" from "daemon
# exited and we have not reaped it yet". Ask for the process state instead.
probe_cron_alive() {
    [ -n "$CRON_PID" ] || return 1
    case "$(ps -o stat= -p "$CRON_PID" 2>/dev/null | tr -d ' ')" in
        ""|Z*) return 1 ;;
        *) return 0 ;;
    esac
}

# Poll for the dispatch evidence (bounded) instead of sleeping a fixed duration.
PROBE_START=$(date +%s)
DEADLINE=$((PROBE_START + 15))
DISPATCHED=0
LAST=-1
STABLE=0
while :; do
    DISPATCHED=$(grep -c 'CMD (' "$LIVE_LOG" 2>/dev/null || true)
    [ -n "$DISPATCHED" ] || DISPATCHED=0
    if [ "$EXPECTED" -gt 0 ] && [ "$DISPATCHED" -ge "$EXPECTED" ]; then break; fi
    if grep -q 'Running @reboot jobs' "$LIVE_LOG" 2>/dev/null; then
        if [ "$DISPATCHED" -eq "$LAST" ]; then STABLE=$((STABLE + 1)); else STABLE=0; fi
        if [ "$STABLE" -ge 5 ]; then break; fi
    fi
    LAST=$DISPATCHED
    if ! probe_cron_alive; then break; fi
    if [ "$(date +%s)" -ge "$DEADLINE" ]; then break; fi
    sleep 0.2
done

if ! probe_cron_alive; then
    echo "[PoC] FAIL: the cron daemon exited immediately - its live behaviour cannot be observed."
    tail -5 "$LIVE_LOG" 2>/dev/null || true
    echo "RESULT: cron daemon is not functional."
    exit 1
fi

# FAIL CLOSED: if there are jobs on this box but the daemon dispatched none of them,
# the live evidence was never collected and this check must not silently pass.
if [ "$EXPECTED" -gt 0 ] && [ "$DISPATCHED" -eq 0 ]; then
    echo "[PoC] FAIL: the cron daemon dispatched none of the $EXPECTED scheduled job(s) - the live check could not be performed."
    tail -5 "$LIVE_LOG" 2>/dev/null || true
    exit 1
fi

kill "$CRON_PID" >/dev/null 2>&1 || true
wait "$CRON_PID" 2>/dev/null || true
CRON_PID=""

EXECUTED=$(sed -n 's/.*CMD (\(.*\))[[:space:]]*$/\1/p' "$LIVE_LOG" 2>/dev/null | sort -u || true)
echo "[PoC] INFO: the live daemon dispatched $DISPATCHED of $EXPECTED job(s) in $(( $(date +%s) - PROBE_START ))s:"
if [ -n "$EXECUTED" ]; then
    echo "$EXECUTED" | sed 's/^/    /'
fi

LIVE_BAD=0
for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
    if echo "$EXECUTED" | grep -qE "$pattern" 2>/dev/null; then
        echo "[PoC] FAIL: the running cron daemon EXECUTED a command matching '$pattern'."
        LIVE_BAD=1
    fi
done

# The static scan above can only see the text of the crontab line, so a backdoor that
# hides behind an innocuous script name (`* * * * * root /usr/local/sbin/healthcheck`)
# matches none of the patterns. Follow the daemon's own dispatch list to the files it
# would really execute and scan those too. Text files only - a binary can match these
# regexes by accident.
set -f
while IFS= read -r cmdline; do
    [ -n "$cmdline" ] || continue
    for tok in $cmdline; do
        case "$tok" in /*) ;; *) continue ;; esac
        tok=${tok%%;*}; tok=${tok%\"}; tok=${tok%\'}
        [ -f "$tok" ] || continue
        grep -Iq . "$tok" 2>/dev/null || continue
        for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
            if grep -qE "$pattern" "$tok" 2>/dev/null; then
                echo "[PoC] FAIL: cron dispatches $tok, whose contents match '$pattern': $(grep -E "$pattern" "$tok" | head -1)"
                LIVE_BAD=1
            fi
        done
    done
done <<< "$EXECUTED"
set +f

restore_cron_state

if [ "$LIVE_BAD" -eq 1 ]; then
    echo "[PoC] RESULT: Vulnerability still present -- the live cron daemon is still running the backdoor."
    exit 1
fi
echo "[PoC] PASS: the live cron daemon dispatched nothing suspicious."

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

# WAS WEAK: `command -v cron` was the only mandatory regression check, so the
# daemon never had to be able to run. Start it for real and require it to stay
# resident (a defunct process does not count).
# WAS ALSO SLOW: three seconds of fixed sleeps. Poll for the daemon instead, then
# re-check once a second later so "stays resident" still means something.
# The EXIT trap restores the process state we found (see restore_cron_state).
cron_alive() { ps -eo stat=,comm= 2>/dev/null | awk '$2=="cron" && $1 !~ /Z/ {found=1} END{exit !found}'; }
pkill -x cron >/dev/null 2>&1 || true
cron >/dev/null 2>&1 || true
CRON_UP=0
for _ in $(seq 1 25); do
    if cron_alive; then CRON_UP=1; break; fi
    sleep 0.2
done
sleep 1
if [ "$CRON_UP" -eq 1 ] && cron_alive; then
    echo "[Regression] PASS: the cron daemon starts and stays resident."
else
    echo "[Regression] FAIL: the cron daemon does not stay running."
    FAIL=1
fi

# Check that /etc/crontab still exists and has valid structure.
# WAS WEAK: the preservation of the legitimate job was only a WARNING, so
# `> /etc/crontab` - wiping every scheduled job on the box - passed cleanly.
if [ -f /etc/crontab ]; then
    echo "[Regression] PASS: /etc/crontab exists."
    if grep -q "apt-get update" /etc/crontab 2>/dev/null; then
        echo "[Regression] PASS: Legitimate apt-get update cron job is preserved."
    else
        echo "[Regression] FAIL: the legitimate apt-get update cron job was destroyed."
        echo "  Removing the backdoor must not take the legitimate schedule with it."
        FAIL=1
    fi
    # The environment header cron needs must survive too.
    if grep -qE '^\s*(SHELL|PATH)\s*=' /etc/crontab 2>/dev/null; then
        echo "[Regression] PASS: /etc/crontab retains its SHELL/PATH environment header."
    else
        echo "[Regression] FAIL: /etc/crontab lost its SHELL/PATH header - jobs would run with no PATH."
        FAIL=1
    fi
else
    echo "[Regression] FAIL: /etc/crontab is missing entirely."
    FAIL=1
fi

# Verify cron spool directory exists
if [ -d /var/spool/cron/crontabs ]; then
    echo "[Regression] PASS: Cron spool directory exists."
else
    echo "[Regression] FAIL: Cron spool directory missing - no user crontab can be installed."
    FAIL=1
fi

# WAS WEAK: this functional test was WARN-only, so a remediation that destroyed
# the spool permissions (or removed crontab(1)) still passed.
TEMP_CRON=$(mktemp)
echo "# Test cron entry" > "$TEMP_CRON"
echo "0 0 1 1 * /bin/true" >> "$TEMP_CRON"
if crontab "$TEMP_CRON" 2>/dev/null; then
    if crontab -l 2>/dev/null | grep -q '/bin/true'; then
        echo "[Regression] PASS: crontab command can install and read back new entries."
    else
        echo "[Regression] FAIL: crontab installed an entry but cannot read it back."
        FAIL=1
    fi
    crontab -r 2>/dev/null || true
else
    echo "[Regression] FAIL: crontab command cannot install entries - legitimate scheduling is broken."
    FAIL=1
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
