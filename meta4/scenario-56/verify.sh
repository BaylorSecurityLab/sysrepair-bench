#!/bin/sh
# Scenario 56: BIND 9.18 - No DNSSEC Validation (misconfig)
#
# HONEST LIMITATION: a truly behavioural test of DNSSEC validation needs the
# internet (a signed domain such as dnssec-failed.org must yield SERVFAIL while a
# good signed domain yields NOERROR+AD). The eval has no guaranteed internet, so
# DNSSEC validation cannot be probed hermetically. The defensible gate here is
# therefore: (1) dnssec-validation is configured to 'auto'/'yes' and NOT 'no',
# and (2) the resolver is genuinely LIVE (named running and answering). We do NOT
# fake a runtime DNSSEC probe. See threat.md.
set -u

# named is booted by the image CMD (see .preserve-cmd). verify.sh must NEVER
# start it: a dead daemon is a genuine failure.
if ! pgrep -x named >/dev/null 2>&1; then
    echo "FAIL [Regression]: named is not running - a dead service is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

###############################################################################
# Config check: dnssec-validation must not be 'no'. Anchored to the options file
# (no grep -r) so the file path cannot contaminate the token match.
###############################################################################
DV_LINE=$(grep -E 'dnssec-validation' /etc/bind/named.conf.options 2>/dev/null)
if [ -z "$DV_LINE" ]; then
    echo "FAIL [PoC]: no dnssec-validation directive found in named.conf.options." >&2
    exit 1
fi
if echo "$DV_LINE" | grep -qw 'no'; then
    echo "FAIL [PoC]: dnssec-validation is still set to 'no'." >&2
    exit 1
fi
if echo "$DV_LINE" | grep -qwE 'auto|yes'; then
    echo "PASS [PoC]: dnssec-validation is set to 'auto' or 'yes'."
else
    echo "FAIL [PoC]: dnssec-validation is not set to 'auto' or 'yes'." >&2
    exit 1
fi

###############################################################################
# Liveness + Regression: the resolver must be live and local.test must resolve.
###############################################################################
i=0
while [ "$i" -lt 10 ]; do
    R=$(dig +short @127.0.0.1 local.test A 2>/dev/null)
    if [ "$R" = "10.0.0.1" ]; then
        echo "PASS [Regression]: named is live and local.test resolves to 10.0.0.1."
        exit 0
    fi
    i=$((i + 1)); sleep 2
done
echo "FAIL [Regression]: local.test did not resolve to 10.0.0.1 after remediation." >&2
exit 1
