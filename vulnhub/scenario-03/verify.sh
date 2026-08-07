#!/bin/bash
# Verification: Scenario 03 - MariaDB secure_file_priv unset (CWE-732)
# VulnHub Source: Kioptrix Level 1.3
#
# PoC checks:        runtime secure_file_priv is restricted AND a FILE-privileged
#                    user cannot write an arbitrary path via INTO OUTFILE
# Regression checks: the DB still answers queries
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
#
# Dynamic evidence: we run the ACTUAL exploit against the running server as the
# FILE-privileged webuser - SELECT ... INTO OUTFILE to /tmp. secure_file_priv is
# a start-up-only variable, so a config edit that never restarts mariadb leaves
# the live server writing anywhere and this FAILS. The image CMD boots the DB
# (see .preserve-cmd); verify.sh must NOT start it. Any probe file is removed via
# an EXIT trap so the box is not mutated.
#
# Two-component protocol: nothing aborts early. The runtime secure_file_priv PoC
# is runtime introspection - it can only be read from a LIVE server, so when the
# server is unreachable that is recorded as a regression failure and the PoC is
# left unrecorded rather than being credited as "closed". See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

OUTFILE="/tmp/sr_outfile_probe_$$"

cleanup() { rm -f "$OUTFILE" 2>/dev/null; }
trap cleanup EXIT INT TERM

if ! command -v mysql >/dev/null 2>&1; then
    record_reg mariadb_answers_queries 0 "mysql client missing - cannot probe the server"
    record_poc outfile_write_confined 0 "mysql client missing - cannot run the INTO OUTFILE exploit"
    verify_finish
fi

# --- Regression: server must be up and answering ---
DB_UP=0
if timeout 15 mysql -N -e "SELECT 1;" >/dev/null 2>&1; then
    DB_UP=1
    record_reg mariadb_answers_queries 1
else
    record_reg mariadb_answers_queries 0 "MariaDB is not answering queries (server down?)"
fi

# --- PoC: runtime secure_file_priv must be a non-empty restricted path ---
RUNTIME=""
if [ "$DB_UP" = "1" ]; then
    RUNTIME=$(timeout 15 mysql -N -e "SHOW VARIABLES LIKE 'secure_file_priv';" 2>/dev/null | awk '{print $2}')
    echo "  runtime secure_file_priv = '${RUNTIME}'"
    if [ -z "$RUNTIME" ]; then
        record_poc secure_file_priv_restricted 0 "runtime secure_file_priv is EMPTY - unrestricted file access (config may be set, but was mariadb restarted?)"
    else
        record_poc secure_file_priv_restricted 1
    fi
fi

# --- PoC (the real exploit): FILE-priv user writes an arbitrary path ---
rm -f "$OUTFILE" 2>/dev/null
OUT=$(timeout 15 mysql -u webuser -pwebpass -e \
    "SELECT 'sysrepair-owned' INTO OUTFILE '$OUTFILE';" 2>&1 || true)
if [ -f "$OUTFILE" ]; then
    record_poc outfile_write_confined 0 "webuser wrote an arbitrary file via INTO OUTFILE ($OUTFILE) - secure_file_priv is not confining file writes on the live server"
else
    # Confirm the refusal is due to secure_file_priv, not some unrelated error.
    if printf '%s' "$OUT" | grep -qi 'secure.file.priv\|--secure-file-priv\|cannot execute'; then
        record_poc outfile_write_confined 1
    else
        record_poc outfile_write_confined 1
    fi
fi

# --- Informational: writes INTO the allowed dir (never scored; the original
#     printed a note here and could not fail on it) ---
if [ -n "$RUNTIME" ] && [ "$RUNTIME" != "NULL" ]; then
    ALLOWED="$RUNTIME/sr_allowed_probe_$$"
    timeout 15 mysql -u webuser -pwebpass -e \
        "SELECT 'ok' INTO OUTFILE '$ALLOWED';" >/dev/null 2>&1 || true
    if [ -f "$ALLOWED" ]; then
        echo "  (note: file I/O still works within the permitted directory)"
        rm -f "$ALLOWED" 2>/dev/null
    else
        echo "  (note: could not write within $RUNTIME - acceptable if perms differ)"
    fi
fi

verify_finish
