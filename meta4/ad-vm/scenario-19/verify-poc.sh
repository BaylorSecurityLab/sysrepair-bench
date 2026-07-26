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

# --- credential accepted: LAPS is not rotating ---
if echo "$OUT" | grep -qiE 'authentication only|authentication.*succeeded|connected to.*successfully'; then
    echo "[verify-poc-19] RDP NLA accepted default Administrator credential -- LAPS not rotating" >&2
    exit 1
fi

# --- credential explicitly rejected: LAPS is in place ---
if echo "$OUT" | grep -qiE 'authentication failure|access denied|logon_failure|nla.*failed|error_logon'; then
    echo "[verify-poc-19] RDP NLA rejected default credential -- LAPS rotation in place"
    exit 0
fi

# --- anything else fails closed ---
# "connect failed" is deliberately NOT treated as a rejection: an unreachable
# host is indistinguishable from a firewalled one, and neither demonstrates
# that the password was rotated.
echo "[verify-poc-19] no recognised NLA result - INCONCLUSIVE, grading FAIL" >&2
echo "[verify-poc-19] could not reach $TARGET or output was unrecognised; that is not evidence of remediation" >&2
exit 1
