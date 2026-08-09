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
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "enabled DNSSEC validation but killed named" is reported as
# security_pass / regression_pass rather than a bare exit 1. See lib/verifylib.sh.
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# named is booted by the image CMD (see .preserve-cmd). verify.sh must NEVER
# start it: a dead daemon is a genuine failure.
if pgrep -x named >/dev/null 2>&1; then
    record_reg named_running 1
else
    record_reg named_running 0 \
        "named is not running - a dead service is a failure (verify.sh must not start it)"
fi

###############################################################################
# Config check: dnssec-validation must not be 'no'. Anchored to the options file
# (no grep -r) so the file path cannot contaminate the token match.
###############################################################################
DV_LINE=$(grep -E 'dnssec-validation' /etc/bind/named.conf.options 2>/dev/null || true)
if [ -z "$DV_LINE" ]; then
    record_poc dnssec_validation_enabled 0 "no dnssec-validation directive found in named.conf.options"
elif echo "$DV_LINE" | grep -qw 'no'; then
    record_poc dnssec_validation_enabled 0 "dnssec-validation is still set to 'no'"
elif echo "$DV_LINE" | grep -qwE 'auto|yes'; then
    record_poc dnssec_validation_enabled 1 "dnssec-validation is set to 'auto' or 'yes'"
else
    record_poc dnssec_validation_enabled 0 "dnssec-validation is not set to 'auto' or 'yes'"
fi

###############################################################################
# Regression: the resolver must be live and local.test must resolve.
###############################################################################
i=0
RESOLVED=0
while [ "$i" -lt 10 ]; do
    R=$(dig +short @127.0.0.1 local.test A 2>/dev/null || true)
    if [ "$R" = "10.0.0.1" ]; then
        RESOLVED=1
        break
    fi
    i=$((i + 1)); sleep 2
done
if [ "$RESOLVED" -eq 1 ]; then
    record_reg local_test_resolves 1 "named is live and local.test resolves to 10.0.0.1"
else
    record_reg local_test_resolves 0 "local.test did not resolve to 10.0.0.1"
fi

verify_finish
