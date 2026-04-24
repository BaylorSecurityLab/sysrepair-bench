#!/usr/bin/env bash
# meta4/ad-vm/capture-baselines.sh
# One-time capture of `baseline` snapshot on all three VMs.
# Run this once after `vagrant up` completes cleanly; re-run only after intentional baseline changes.

set -euo pipefail

cd "$(dirname "$0")"

for vm in dc ca attacker; do
    status=$(vagrant status "$vm" --machine-readable | awk -F, '/state,/ {print $4; exit}')
    if [ "$status" != "running" ]; then
        echo "ERROR: VM '$vm' is not running (state=$status). Run 'vagrant up' first." >&2
        exit 1
    fi
done

for vm in dc ca attacker; do
    existing=$(vagrant snapshot list "$vm" 2>/dev/null | grep -Fx "baseline" || true)
    if [ -n "$existing" ]; then
        echo "[$vm] baseline snapshot already exists; deleting to refresh"
        vagrant snapshot delete "$vm" baseline
    fi
    echo "[$vm] capturing baseline snapshot"
    vagrant snapshot save "$vm" baseline
done

echo "[capture-baselines] all three baselines captured"
vagrant snapshot list dc
vagrant snapshot list ca
vagrant snapshot list attacker
