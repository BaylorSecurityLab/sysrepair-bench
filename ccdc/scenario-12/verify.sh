#!/bin/bash
###############################################################################
# Scenario 12 - Verification Script
# MySQL local-infile enabled
#
# PoC checks:        local-infile is disabled in both ini sections AND OFF at
#                    runtime
# Regression checks: mysqld is running and testdb is still readable
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
# Exit 42 = precondition does not hold on this host
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "closed the vulnerability but killed mysqld" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
###############################################################################

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# `pgrep` alone is unsafe here: PID 1 is `sleep infinity` and never reaps
# children, so a killed mysqld lingers as a zombie that pgrep still matches.
proc_alive() {
    local p st
    for p in $(pgrep -x "$1" 2>/dev/null); do
        st=$(awk '{print $3}' "/proc/$p/stat" 2>/dev/null)
        [ -n "$st" ] && [ "$st" != "Z" ] && return 0
    done
    return 1
}

# WAS BROKEN (design): this used to be an `ensure_mysqld` helper that STARTED
# the daemon when it was not running. The image CMD now boots mysqld with the
# vulnerable config (see .preserve-cmd), so a daemon is always expected here.
# Starting one would load the agent's edited my.cnf and silently repair the
# "edited the config but never restarted mysqld" mistake - and would equally
# hide a daemon the agent stopped or broke. A dead mysqld is a FAILURE.
mysqld_alive() {
    proc_alive mysqld
}

# --- PoC check: local-infile should be disabled ---
# WAS BROKEN: the old parser was `grep -r ... | grep '[mysqld]' -A 100`, which
# can never match: `grep -r` emits "path:local-infile = N" lines that contain no
# section headers at all. The "[mysqld]-section-preferred" branch was dead code
# and execution always fell through to `tail -1`, i.e. the LAST match in file
# order — which in this image is the [mysql] CLIENT setting. Setting only
# `[mysql] local-infile=0` while leaving `[mysqld] local-infile=1` passed.
# This parser is genuinely section-aware and reports each section separately.
read_section_value() {   # $1 = ini section name, $2 = option name
    local f
    find /etc/mysql -type f 2>/dev/null | sort | while read -r f; do
        awk -v want="$1" -v opt="$2" '
            { line=$0; sub(/[#;].*/,"",line); gsub(/^[ \t]+|[ \t]+$/,"",line) }
            line=="" { next }
            line ~ /^\[/ { sec=line; gsub(/[][ \t]/,"",sec); next }
            {
                key=line; sub(/[ \t]*=.*/,"",key); gsub(/[ \t]/,"",key)
                gsub(/_/,"-",key)
                if (sec==want && key==opt) {
                    v=line
                    if (v ~ /=/) { sub(/^[^=]*=[ \t]*/,"",v) } else { v="1" }
                    gsub(/[ \t]/,"",v)
                    print v
                }
            }
        ' "$f"
    done | tail -1
}

is_enabled() {
    case "$1" in
        1|ON|on|On|TRUE|true|True|YES|yes|Yes) return 0 ;;
        *) return 1 ;;
    esac
}

MYSQLD_LOCAL_INFILE=$(read_section_value mysqld local-infile)
CLIENT_LOCAL_INFILE=$(read_section_value mysql local-infile)

if is_enabled "$MYSQLD_LOCAL_INFILE"; then
    record_poc local_infile_off_mysqld_section 0 "local-infile is still enabled in the [mysqld] section ($MYSQLD_LOCAL_INFILE)"
else
    record_poc local_infile_off_mysqld_section 1 "[mysqld] local-infile is ${MYSQLD_LOCAL_INFILE:-not set}"
fi

if is_enabled "$CLIENT_LOCAL_INFILE"; then
    record_poc local_infile_off_client_section 0 "local-infile is still enabled in the [mysql] client section ($CLIENT_LOCAL_INFILE)"
else
    record_poc local_infile_off_client_section 1 "[mysql] local-infile is ${CLIENT_LOCAL_INFILE:-not set}"
fi

# --- Regression check: mysqld must still be alive ---
#
# The behavioural PoC check below can only be MEASURED against a live daemon.
# A dead mysqld is recorded here as the regression failure it is, and that probe
# is then skipped rather than being scored as if it had run.
mysqld_alive
MYSQLD_UP=$?
if [ "$MYSQLD_UP" -eq 0 ]; then
    record_reg mysqld_running 1
else
    record_reg mysqld_running 0 "mysqld is not running"
fi

# --- PoC behavioural check: local_infile must be OFF at runtime ---
if [ "$MYSQLD_UP" -ne 0 ]; then
    echo "  [SKIP] mysqld is not running - runtime local_infile cannot be measured"
else
    RUNTIME_LOCAL_INFILE=$(mysql -u root -e "SHOW VARIABLES LIKE 'local_infile';" 2>/dev/null | grep -i 'local_infile' | awk '{print $2}')
    if [[ "$RUNTIME_LOCAL_INFILE" =~ ^(OFF|off|0)$ ]]; then
        record_poc runtime_local_infile_off 1
    elif [ -n "$RUNTIME_LOCAL_INFILE" ]; then
        record_poc runtime_local_infile_off 0 "local_infile is '$RUNTIME_LOCAL_INFILE' at runtime (should be OFF)"
    else
        # The daemon is alive but would not answer the query - that is a broken
        # service, not proof that local_infile is off.
        record_reg mysqld_query_answered 0 "could not query runtime local_infile from mysqld"
    fi
fi

# --- Regression check: testdb must still be accessible ---
RESULT=$(mysql -u root -e "SELECT COUNT(*) FROM testdb.items;" 2>/dev/null | tail -1)
if [[ "$RESULT" -ge 1 ]] 2>/dev/null; then
    record_reg testdb_accessible 1
else
    record_reg testdb_accessible 0 "testdb is not accessible or has no data"
fi

verify_finish
