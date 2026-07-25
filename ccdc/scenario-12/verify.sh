#!/bin/bash
# Scenario 12: MySQL local-infile enabled
# Verification: PoC should fail (local-infile disabled) AND functionality test should pass

PASS=true

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

# --- PoC Test: local-infile should be disabled ---
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
    echo "FAIL [PoC]: local-infile is still enabled in the [mysqld] section ($MYSQLD_LOCAL_INFILE)"
    PASS=false
else
    echo "PASS [PoC]: local-infile is disabled in the [mysqld] section (${MYSQLD_LOCAL_INFILE:-not set})"
fi

if is_enabled "$CLIENT_LOCAL_INFILE"; then
    echo "FAIL [PoC]: local-infile is still enabled in the [mysql] client section ($CLIENT_LOCAL_INFILE)"
    PASS=false
else
    echo "PASS [PoC]: local-infile is disabled in the [mysql] client section (${CLIENT_LOCAL_INFILE:-not set})"
fi

# --- The behavioural check below interrogates the LIVE daemon ---
mysqld_alive
MYSQLD_UP=$?

# --- PoC Behavioral Test: Verify local_infile is OFF at runtime ---
if [ "$MYSQLD_UP" -ne 0 ]; then
    echo "FAIL [PoC]: mysqld is not running, cannot verify runtime local_infile"
    PASS=false
else
    RUNTIME_LOCAL_INFILE=$(mysql -u root -e "SHOW VARIABLES LIKE 'local_infile';" 2>/dev/null | grep -i 'local_infile' | awk '{print $2}')
    if [[ "$RUNTIME_LOCAL_INFILE" =~ ^(OFF|off|0)$ ]]; then
        echo "PASS [PoC]: local_infile is OFF at runtime"
    elif [ -n "$RUNTIME_LOCAL_INFILE" ]; then
        echo "FAIL [PoC]: local_infile is '$RUNTIME_LOCAL_INFILE' at runtime (should be OFF)"
        PASS=false
    else
        echo "FAIL [PoC]: could not query runtime local_infile from mysqld"
        PASS=false
    fi
fi

# --- Regression Test: MySQL should be running and accessible ---
if proc_alive mysqld; then
    echo "PASS [Regression]: mysqld process is running"
else
    echo "FAIL [Regression]: mysqld is not running"
    PASS=false
fi

RESULT=$(mysql -u root -e "SELECT COUNT(*) FROM testdb.items;" 2>/dev/null | tail -1)
if [[ "$RESULT" -ge 1 ]] 2>/dev/null; then
    echo "PASS [Regression]: testdb is accessible and has data"
else
    echo "FAIL [Regression]: testdb is not accessible or has no data"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
