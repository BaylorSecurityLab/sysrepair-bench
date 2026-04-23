#!/usr/bin/env bash
# meta4/ad-vm/reset.sh
# Restores all three VMs to their `baseline` snapshot. Idempotent.

set -euo pipefail

cd "$(dirname "$0")"

for vm in dc ca attacker; do
    if ! vagrant snapshot list "$vm" 2>/dev/null | grep -qFx "baseline"; then
        echo "ERROR: '$vm' has no baseline snapshot. Run ./capture-baselines.sh first." >&2
        exit 1
    fi
done

for vm in dc ca attacker; do
    echo "[$vm] restoring baseline snapshot"
    vagrant snapshot restore "$vm" baseline --no-provision
done

echo "[reset] all three VMs restored to baseline"
