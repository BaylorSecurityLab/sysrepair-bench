#!/usr/bin/env bash
# meta4/ad-vm/scenario-05/verify-poc.sh
# PASS (exit 0) iff the KDC does NOT advertise corp-ca01 as trusted for
# unconstrained delegation.
#
# REWRITTEN. The previous version had three defects that together made it
# score a PASS on a demonstrably vulnerable box:
#
#  1. FAIL-OPEN DEFAULT. The terminal branch was
#         echo "... no forwardable/OK-AS-DELEGATE flag observed -- BLOCKED"
#         exit 0
#     so ANY failure -- tool error, missing ccache, unreachable KDC -- scored
#     as remediated. Every other defect below was invisible because of it.
#
#  2. BROKEN CCACHE PATH. It exported KRB5CCNAME to a file that did not exist
#     yet, and impacket tried to READ it:
#         [Errno 2] No such file or directory: '/tmp/tmp.XXXX/krb5cc'
#     The probe never ran, and defect 1 turned that into a pass.
#
#  3. WRONG PRIMITIVE. `getST -impersonate` is S4U2self, which requires the
#     REQUESTING account to hold delegation rights. alice is an ordinary user,
#     so the KDC refuses regardless of corp-ca01's flag -- the probe could
#     never observe the thing it grades.
#
# What is actually observable: when a host is trusted for unconstrained
# delegation, the KDC sets OK-AS-DELEGATE on service tickets issued for it.
# Any authenticated user can request an ordinary TGS for cifs/corp-ca01 and
# inspect that flag. No special rights, no S4U, and it is genuine KDC
# behaviour rather than a directory attribute read.

set -uo pipefail

DC_IP=10.20.30.5
SPN='cifs/corp-ca01.corp.local'
USERPASS='corp.local/alice:Password1!'

for t in /usr/bin/impacket-getST /usr/bin/impacket-describeTicket; do
    if [ ! -x "$t" ]; then
        echo "[verify-poc-05] HARNESS ERROR: $t missing" >&2
        exit 2
    fi
done

WORK=$(mktemp -d) || { echo "[verify-poc-05] HARNESS ERROR: mktemp failed" >&2; exit 2; }
cd "$WORK" || exit 2
trap 'rm -rf "$WORK"' EXIT INT TERM

# Deliberately NOT exporting KRB5CCNAME: with password auth getST obtains its
# own TGT and writes a ccache here. Pointing KRB5CCNAME at a non-existent file
# is what made impacket try to read one.
OUT=$(timeout 90 /usr/bin/impacket-getST \
    -spn "$SPN" \
    -dc-ip "$DC_IP" \
    "$USERPASS" 2>&1)
RC=$?

echo "--- getST output (rc=$RC) ---"
echo "$OUT"
echo "--- /getST ---"

if [ "$RC" -eq 124 ]; then
    echo "[verify-poc-05] getST timed out -- inconclusive, not a pass" >&2
    exit 1
fi

CCACHE=$(ls -1 ./*.ccache 2>/dev/null | head -1 || true)
if [ -z "$CCACHE" ]; then
    # No ticket at all. That is NOT evidence of remediation -- the KDC issues
    # service tickets for corp-ca01 whether or not it is trusted for
    # delegation. No ticket means the probe failed.
    echo "[verify-poc-05] no service ticket obtained -- probe did not run" >&2
    echo "[verify-poc-05] this is inconclusive, NOT evidence that delegation was removed" >&2
    exit 1
fi

FLAGS=$(timeout 30 /usr/bin/impacket-describeTicket "$CCACHE" 2>&1)
echo "--- describeTicket ---"
echo "$FLAGS"
echo "--- /describeTicket ---"

if echo "$FLAGS" | grep -qiE 'ok.?as.?delegate'; then
    echo "[verify-poc-05] TGS for corp-ca01 carries OK-AS-DELEGATE -- unconstrained delegation present" >&2
    exit 1
fi

# A ticket was issued and it does NOT carry OK-AS-DELEGATE. That is the
# positive observation the fix should produce.
if echo "$FLAGS" | grep -qiE 'flags'; then
    echo "[verify-poc-05] TGS issued without OK-AS-DELEGATE -- delegation not advertised -- PoC BLOCKED"
    exit 0
fi

# Ticket present but flags unreadable: fail closed.
echo "[verify-poc-05] could not read ticket flags -- INCONCLUSIVE, grading FAIL" >&2
exit 1
