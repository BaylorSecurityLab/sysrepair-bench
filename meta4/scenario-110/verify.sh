#!/bin/bash
# Scenario 110: ImageMagick — Permissive policy.xml (CVE-2023-34152)
set -u

POLICY=/etc/ImageMagick-6/policy.xml

###############################################################################
# PoC: policy.xml must exist and must deny MVG, MSL, and URL coders
###############################################################################

if [ ! -f "$POLICY" ]; then
    echo "FAIL [PoC]: $POLICY does not exist — all coders are permitted." >&2
    exit 1
fi
echo "PASS [PoC]: policy.xml exists."

for coder in MVG MSL URL; do
    if grep -qi "pattern=\"${coder}\"" "$POLICY" && \
       grep -qi "rights=\"none\"" "$POLICY"; then
        echo "PASS [PoC]: $coder coder denied in policy.xml."
    else
        echo "FAIL [PoC]: $coder coder not denied in policy.xml." >&2
        exit 1
    fi
done

###############################################################################
# PoC 2: MVG coder must be blocked at runtime
###############################################################################

if convert mvg:/dev/null /tmp/poc_out.png 2>&1 | grep -qi "not authorized\|policy\|coder"; then
    echo "PASS [PoC]: convert rejects mvg: coder at runtime."
elif [ -f /tmp/poc_out.png ]; then
    echo "FAIL [PoC]: convert accepted mvg: coder — dangerous coder still enabled." >&2
    rm -f /tmp/poc_out.png
    exit 1
else
    echo "PASS [PoC]: convert did not produce output for mvg: coder."
fi

###############################################################################
# Regression: safe built-in coder (logo:) must still work
###############################################################################

if convert logo: /tmp/test_regression.png 2>/dev/null && [ -f /tmp/test_regression.png ]; then
    echo "PASS [Regression]: convert logo: /tmp/test_regression.png succeeded."
    rm -f /tmp/test_regression.png
else
    echo "FAIL [Regression]: convert logo: failed — hardening broke safe coders." >&2
    exit 1
fi

exit 0
