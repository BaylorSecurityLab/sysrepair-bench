#!/usr/bin/env bash
set -euo pipefail

WORK=$(mktemp -d)
cd "$WORK"

# Pull the SYSVOL Policies tree using credentials any authenticated user has.
smbclient //corp-dc01/SYSVOL -U 'corp\alice%Password1!' \
    -c 'prompt off; recurse on; cd corp.local/Policies; mget *' 2>&1 \
    | tail -10

CPW=$(grep -rhoE 'cpassword="[^"]+"' . 2>/dev/null | grep -v 'cpassword=""' | head -1 | cut -d'"' -f2)

echo "--- SYSVOL cpassword scan ---"
if [ -n "$CPW" ]; then
    echo "found cpassword: $CPW"
else
    echo "no cpassword attributes present"
fi
echo "--- /scan ---"

if [ -z "$CPW" ]; then
    echo "[verify-poc-18] SYSVOL contains no GPP cpassword -- MS14-025 cleanup complete"
    exit 0
fi
echo "[verify-poc-18] SYSVOL still contains GPP cpassword -- cleanup incomplete" >&2
exit 1
