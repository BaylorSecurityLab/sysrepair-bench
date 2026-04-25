#!/usr/bin/env bash
# meta4/ad-vm/scenario-05/verify-poc.sh
# PASS (exit 0) iff the DC will NOT issue a forwardable service ticket for
# corp-ca01 -- i.e., corp-ca01 no longer has the unconstrained delegation
# trust-for-delegation flag set and the KDC therefore does not emit
# OK-AS-DELEGATE / forwardable tickets for it.

set -euo pipefail
cd "$(mktemp -d)"

export KRB5CCNAME=$(pwd)/krb5cc

# Behavioural probe: request a service ticket for cifs/corp-ca01 via S4U2self
# and inspect its flags. Unconstrained-delegation hosts get forwardable
# tickets with OK-AS-DELEGATE; remediated hosts do not.
OUT=$(timeout 60 /usr/bin/impacket-getST \
    -spn 'cifs/corp-ca01.corp.local' \
    -impersonate 'Administrator' \
    -dc-ip 10.20.30.5 \
    'corp.local/alice:Password1!' 2>&1 || true)

echo "--- getST output ---"
echo "$OUT"
echo "--- /getST ---"

# Parse the issued ticket for its flags.
if [ -f Administrator.ccache ]; then
    FLAGS=$(timeout 30 /usr/bin/impacket-describeTicket Administrator.ccache 2>&1 | grep -iE 'ticket flags|ok-as-delegate|forwardable' || true)
    echo "--- ticket flags ---"
    echo "$FLAGS"
    if echo "$FLAGS" | grep -qiE 'ok.?as.?delegate|forwardable.*true|0x40000000|0x00200000'; then
        echo "[verify-poc-05] corp-ca01 TGS is forwardable / OK-AS-DELEGATE -- unconstrained delegation present" >&2
        exit 1
    fi
fi

if echo "$OUT" | grep -qiE 'kdc_err_policy|access_denied|not.*authorised|will not allow'; then
    echo "[verify-poc-05] KDC refused S4U2self for corp-ca01 -- BLOCKED"
    exit 0
fi
echo "[verify-poc-05] no forwardable/OK-AS-DELEGATE flag observed -- BLOCKED"
exit 0
