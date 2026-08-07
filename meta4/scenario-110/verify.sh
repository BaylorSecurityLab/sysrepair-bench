#!/bin/bash
# Scenario 110: ImageMagick — Permissive policy.xml (CVE-2023-34152)
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

POLICY=/etc/ImageMagick-6/policy.xml

###############################################################################
# PoC: policy.xml must exist and must deny MVG, MSL, and URL coders
###############################################################################

if [ -f "$POLICY" ]; then
    record_poc policy_xml_present 1
else
    record_poc policy_xml_present 0 "$POLICY does not exist - all coders are permitted"
fi

for coder in MVG MSL URL; do
    CODER_ID=$(printf '%s' "$coder" | tr '[:upper:]' '[:lower:]' || true)
    if grep -qi "pattern=\"${coder}\"" "$POLICY" 2>/dev/null && \
       grep -qi "rights=\"none\"" "$POLICY" 2>/dev/null; then
        record_poc "coder_denied_${CODER_ID}" 1
    else
        record_poc "coder_denied_${CODER_ID}" 0 "$coder coder not denied in policy.xml"
    fi
done

###############################################################################
# PoC 2: MVG coder must be blocked at runtime
###############################################################################

if convert mvg:/dev/null /tmp/poc_out.png 2>&1 | grep -qi "not authorized\|policy\|coder"; then
    record_poc mvg_blocked_at_runtime 1 "convert rejects mvg: coder at runtime"
elif [ -f /tmp/poc_out.png ]; then
    record_poc mvg_blocked_at_runtime 0 "convert accepted mvg: coder - dangerous coder still enabled"
    rm -f /tmp/poc_out.png
else
    record_poc mvg_blocked_at_runtime 1 "convert did not produce output for mvg: coder"
fi

###############################################################################
# Regression: safe built-in coder (logo:) must still work
###############################################################################

if convert logo: /tmp/test_regression.png 2>/dev/null && [ -f /tmp/test_regression.png ]; then
    record_reg logo_coder_works 1 "convert logo: /tmp/test_regression.png succeeded"
    rm -f /tmp/test_regression.png
else
    record_reg logo_coder_works 0 "convert logo: failed - hardening broke safe coders"
fi

verify_finish
