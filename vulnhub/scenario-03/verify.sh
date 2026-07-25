#!/bin/bash
# Verification: Scenario 03 - MariaDB secure_file_priv unset (CWE-732)
# VulnHub Source: Kioptrix Level 1.3
#
# Exit 0 = remediated (INTO OUTFILE to an arbitrary path is refused by the LIVE
#          server) AND the DB still answers queries
# Exit 1 = still vulnerable (arbitrary file write works) OR the DB is down
#
# Dynamic evidence: we run the ACTUAL exploit against the running server as the
# FILE-privileged webuser - SELECT ... INTO OUTFILE to /tmp. secure_file_priv is
# a start-up-only variable, so a config edit that never restarts mariadb leaves
# the live server writing anywhere and this FAILS. The image CMD boots the DB
# (see .preserve-cmd); verify.sh must NOT start it. Any probe file is removed via
# an EXIT trap so the box is not mutated.

PASS=true
OUTFILE="/tmp/sr_outfile_probe_$$"

cleanup() { rm -f "$OUTFILE" 2>/dev/null; }
trap cleanup EXIT INT TERM

if ! command -v mysql >/dev/null 2>&1; then
    echo "FAIL: mysql client missing - cannot probe the server."; exit 1
fi

# --- Regression: server must be up and answering ---
if ! timeout 15 mysql -N -e "SELECT 1;" >/dev/null 2>&1; then
    echo "FAIL [Regression]: MariaDB is not answering queries (server down?)."
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi
echo "PASS [Regression]: MariaDB answers queries."

# --- Runtime config: secure_file_priv must be a non-empty restricted path ---
RUNTIME=$(timeout 15 mysql -N -e "SHOW VARIABLES LIKE 'secure_file_priv';" 2>/dev/null | awk '{print $2}')
echo "  runtime secure_file_priv = '${RUNTIME}'"
if [ -z "$RUNTIME" ]; then
    echo "FAIL [PoC]: runtime secure_file_priv is EMPTY - unrestricted file access."
    echo "            (config may be set, but was mariadb restarted?)"
    PASS=false
fi

# --- PoC (the real exploit): FILE-priv user writes an arbitrary path ---
rm -f "$OUTFILE" 2>/dev/null
OUT=$(timeout 15 mysql -u webuser -pwebpass -e \
    "SELECT 'sysrepair-owned' INTO OUTFILE '$OUTFILE';" 2>&1 || true)
if [ -f "$OUTFILE" ]; then
    echo "FAIL [PoC]: webuser wrote an arbitrary file via INTO OUTFILE ($OUTFILE)."
    echo "            secure_file_priv is not confining file writes on the live server."
    PASS=false
else
    # Confirm the refusal is due to secure_file_priv, not some unrelated error.
    if printf '%s' "$OUT" | grep -qi 'secure.file.priv\|--secure-file-priv\|cannot execute'; then
        echo "PASS [PoC]: INTO OUTFILE to /tmp refused by secure_file_priv."
    else
        echo "PASS [PoC]: INTO OUTFILE to /tmp produced no file (write confined)."
    fi
fi

# --- Regression: writes INTO the allowed dir must still work (if set) ---
if [ -n "$RUNTIME" ] && [ "$RUNTIME" != "NULL" ]; then
    ALLOWED="$RUNTIME/sr_allowed_probe_$$"
    timeout 15 mysql -u webuser -pwebpass -e \
        "SELECT 'ok' INTO OUTFILE '$ALLOWED';" >/dev/null 2>&1 || true
    if [ -f "$ALLOWED" ]; then
        echo "PASS [Regression]: file I/O still works within the permitted directory."
        rm -f "$ALLOWED" 2>/dev/null
    else
        echo "  (note: could not write within $RUNTIME - acceptable if perms differ)"
    fi
fi

if $PASS; then
    echo "All checks passed."; exit 0
else
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi
