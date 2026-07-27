#!/usr/bin/env bash
# meta4/ad-vm/scenario-19/verify-poc.sh
# PASS (exit 0) iff the default local Administrator credential is NOT accepted
# over RDP NLA -- i.e. LAPS is rotating it.
#
# FAILS CLOSED. The previous version began with:
#
#     if ! command -v xfreerdp >/dev/null 2>&1; then
#         echo "... xfreerdp unavailable on attacker -- treating as BLOCKED"
#         exit 0
#     fi
#
# xfreerdp was never installed by the provisioner, so this scenario exited 0
# before probing anything and reported PASS on an unmodified vulnerable box.
# A second fail-open branch did the same for any unrecognised output.
#
# Rules now: a missing tool is a hard error (exit 2); only an EXPLICIT
# authentication rejection counts as blocked; anything else fails.

set -uo pipefail

TARGET=10.20.30.6
DEFAULT_PW='Vagrant1DSRM!'

# freerdp3-x11 provides both /usr/bin/xfreerdp and /usr/bin/xfreerdp3 on
# current Kali. Prefer whichever is present rather than assuming.
RDP=""
for c in xfreerdp xfreerdp3; do
    if command -v "$c" >/dev/null 2>&1; then RDP=$(command -v "$c"); break; fi
done

if [ -z "$RDP" ]; then
    echo "[verify-poc-19] HARNESS ERROR: no xfreerdp/xfreerdp3 on the attacker" >&2
    echo "[verify-poc-19] install freerdp3-x11; a missing grader tool is not a pass" >&2
    exit 2
fi

# xfreerdp -auth-only performs an NLA handshake without opening a session;
# success means the credential is valid.
OUT=$(timeout 25 "$RDP" \
    /v:"$TARGET" \
    /u:Administrator /p:"$DEFAULT_PW" \
    /cert:ignore /auth-only 2>&1)
RC=$?

echo "--- ${RDP##*/} NLA probe output (rc=$RC) ---"
echo "$OUT" | head -40
echo "--- /probe ---"

if [ "$RC" -eq 124 ]; then
    echo "[verify-poc-19] NLA probe timed out - inconclusive, not a pass" >&2
    exit 1
fi

# --- cannot reach the host: HARNESS ERROR, never a verdict ---
# Checked first and kept distinct from a credential rejection. An unreachable
# or firewalled host demonstrates nothing about whether LAPS rotated anything.
if echo "$OUT" | grep -qiE 'ERRCONNECT_CONNECT_FAILED|ERRCONNECT_CONNECT_TRANSPORT_FAILED|ERRCONNECT_DNS_NAME_NOT_FOUND|Connection refused|Network is unreachable|No route to host'; then
    echo "[verify-poc-19] HARNESS ERROR: cannot reach $TARGET over RDP" >&2
    exit 2
fi

# --- credential explicitly REJECTED: LAPS is rotating (checked BEFORE success) ---
#
# Order and pattern both matter here. The success branch used to match
# 'authentication only', but freerdp prints that phrase because /auth-only was
# REQUESTED, on success and failure alike. Both of these appear in a failed
# run, verbatim from the 2026-07-26 gate run:
#
#   [INFO ][xf_pre_connect]: Authentication only. Don't connect to X.
#   [ERROR][freerdp_connect_begin]: Authentication only, exit status 0
#   [ERROR][nla_recv_pdu]: ERRCONNECT_LOGON_FAILURE [0x00020014]
#
# So a REJECTED credential matched the "accepted" branch first and the scenario
# reported "RDP NLA accepted default Administrator credential -- LAPS not
# rotating" about a login that had just been refused. The verdict was inverted:
# gate 2 failed against a fix that worked perfectly.
#
# A mode banner is not a result. Rejection signatures are unambiguous, so they
# are matched first and success is inferred only from a clean exit.
if echo "$OUT" | grep -qiE 'ERRCONNECT_LOGON_FAILURE|ERRCONNECT_AUTHENTICATION_FAILED|ERRCONNECT_ACCOUNT_LOCKED_OUT|ERRCONNECT_ACCOUNT_DISABLED|ERRCONNECT_PASSWORD_EXPIRED|authentication failure|access denied|logon_failure|error_logon'; then
    echo "[verify-poc-19] RDP NLA rejected default credential -- LAPS rotation in place"
    exit 0
fi

# --- credential ACCEPTED: LAPS is not rotating ---
# With /auth-only, freerdp exits 0 only when the NLA handshake authenticated.
if [ "$RC" -eq 0 ] && ! echo "$OUT" | grep -qi 'ERRCONNECT'; then
    echo "[verify-poc-19] RDP NLA accepted default Administrator credential -- LAPS not rotating" >&2
    exit 1
fi

# --- anything else fails closed ---
echo "[verify-poc-19] no recognised NLA result (rc=$RC) - INCONCLUSIVE, grading FAIL" >&2
echo "[verify-poc-19] unrecognised output is not evidence of remediation" >&2
exit 1
