#!/usr/bin/env bash
# meta4/ad-vm/scenario-08/verify-poc.sh
# PASS (exit 0) iff alice cannot coerce an Administrator PFX via ESC2.

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
    -template 'ESC2-AnyPurpose' \
    -upn 'administrator@corp.local' 2>&1 || true)

echo "--- certipy req output ---"
echo "$REQ"
echo "--- /certipy req ---"

# --- CA not serving RPC: HARNESS ERROR, never a verdict ---
#
# ept_s_not_registered means the endpoint mapper has no ICertRequestD
# (91AE6020-9E3C-11CF-8D7C-00AA00C091BE) to hand out: the CA's enrollment
# interface is not reachable from here, which says nothing about whether the
# Any Purpose template is still enrollable.
#
# This used to fall through to exit 1, which is wrong in BOTH directions.
# Observed on the 2026-07-26 gate run: gates 1 AND 2 both hit this, so the
# vulnerable baseline "failed for the right reason" and the remediated host
# "was still vulnerable" -- on identical output that only ever meant the CA
# was unreachable. Exit 2 keeps it out of the evidence pool entirely.
#
# Safe here because this scenario's reference remediation unpublishes a
# template and asserts the CA is STILL SERVING; taking the CA offline is never
# the intended fix, so this cannot swallow a legitimate repair.
if echo "$REQ" | grep -qiE 'ept_s_not_registered|Failed to get DCE RPC connection|Failed to get dynamic TCP endpoint'; then
    echo "[verify-poc-08] HARNESS ERROR: CA RPC enrollment interface not registered" >&2
    echo "[verify-poc-08] the CA is not serving ICertRequestD to this host -- fix the lab, not the scenario" >&2
    exit 2
fi

if [ -f administrator.pfx ]; then
    AUTH=$(timeout 60 /usr/bin/certipy-ad auth \
        -pfx administrator.pfx \
        -dc-ip 10.20.30.5 2>&1 || true)
    echo "--- certipy auth output ---"
    echo "$AUTH"
    if echo "$AUTH" | grep -qE 'NT hash|AS-REP received'; then
        echo "[verify-poc-08] ESC2 still exploitable - PFX + TGT + NT hash recovered" >&2
        exit 1
    fi
fi

# --- explicitly blocked? ---
#
# CERTSRV_E_TEMPLATE_DENIED (0x80094012) and CERTSRV_E_ENROLL_DENIED
# (0x80094011) were absent and had to be added. They are what the CA answers
# when the vulnerable ENROLMENT RIGHTS are revoked rather than the template
# unpublished -- remediation path 2 in the brief, and what a real defender does
# first. Neither the symbol nor the message matched any existing alternative:
# the detail text is "The permissions on the certificate template do not allow
# the current user to enroll for this type of certificate", which contains
# neither "enrollment ... denied" nor "cannot enroll" nor "access_denied", so
# an ACL-only fix graded as an inconclusive FAIL.
#
# Exact wire strings, from impacket-0.13.1 hresult_errors.ERROR_MESSAGES
# (certipy/lib/errors.py::translate_error_code formats
# "code: 0x%x - <symbol> - <detail>" and certipy/lib/req.py logs it as
# "Got error while requesting certificate: ..."):
#   code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the
#     certificate template do not allow the current user to enroll for this
#     type of certificate.
#   code: 0x80094011 - CERTSRV_E_ENROLL_DENIED - The permissions on this CA do
#     not allow the current user to enroll for certificates.
# Matched on symbol and hex code only, which is tighter than matching prose.
#
# These cannot produce a false pass on an un-remediated host: the injected
# state GRANTS Domain Users the Certificate-Enrollment right, so a permissions
# denial can only be observed after somebody removed it.
if echo "$REQ" | grep -qiE 'template.*not found|access_denied|enrollment.*denied|cannot enroll|CERTSRV_E_UNSUPPORTED_CERT_TYPE|0x80094800|not supported by this CA|CERTSRV_E_TEMPLATE_DENIED|0x80094012|CERTSRV_E_ENROLL_DENIED|0x80094011'; then
    echo "[verify-poc-08] alice denied ESC2 enrollment - PoC BLOCKED"
    exit 0
fi

# If we got here with no pfx and no denial signature, treat as blocked only
# if certipy exited with an error AND no pfx. Otherwise FAIL.
#
# A CERTIFICATE ISSUED TO ALICE LANDS HERE, AND THAT IS DELIBERATE.
#
# Clearing ENROLLEE_SUPPLIES_SUBJECT, or swapping Any Purpose for a real Client
# Authentication EKU, does not make the CA refuse the request; it makes the CA
# disregard the supplied SAN and build the subject from the requester's own
# directory identity. The request still succeeds and certipy still writes a PFX
# -- named alice.pfx, because the filename is derived from the identity in the
# ISSUED certificate (certipy/lib/req.py::_determine_output_filename), falling
# back to the requesting username when the certificate carries no SAN at all.
# No denial string is produced, so that state reaches this branch and FAILs.
#
# scenario-10 has a PASS branch for the equivalent state and this scenario
# deliberately does NOT. There the finding is a CA-wide EDITF flag and the
# template involved is the built-in User template, so a cert bound to the
# requester means the whole finding is closed. Here the seeded object IS the
# template: after the attribute change it remains published and enrollable by
# any domain user, one attribute change from exploitable again, so the coercion
# being refused today is a partial mitigation and not a closure. threat.md's
# "Acceptance criterion" states this and remediation path 3 says it explicitly.
# Do not port scenario-10's branch here without changing both.
if [ ! -f administrator.pfx ]; then
    echo "[verify-poc-08] no PFX and no recognised denial - INCONCLUSIVE, grading FAIL" >&2
    echo "[verify-poc-08] an inconclusive probe is not evidence of remediation" >&2
    exit 1
fi

echo "[verify-poc-08] unrecognised result - treating as FAIL" >&2
exit 1
