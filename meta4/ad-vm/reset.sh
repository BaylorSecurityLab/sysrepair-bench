#!/usr/bin/env bash
# meta4/ad-vm/reset.sh
# Restores all three VMs to their `baseline` snapshot. Idempotent.
#
# Uses VBoxManage directly (not `vagrant snapshot restore`) because vagrant's
# live-state resume after a snapshot save-while-running leaves WinRM in a
# half-initialized state the provider can't reach inside boot_timeout. Cold
# poweroff + restore + startvm gives Windows a clean boot every time, with
# services and firewall rules coming up normally.

set -euo pipefail

cd "$(dirname "$0")"

declare -A VBNAME=(
    [dc]="meta4-ad-dc"
    [ca]="meta4-ad-ca"
    [attacker]="meta4-ad-attacker"
)

for vm in dc ca attacker; do
    if ! vagrant snapshot list "$vm" 2>/dev/null | grep -qFx "baseline"; then
        echo "ERROR: '$vm' has no baseline snapshot. Run ./capture-baselines.sh first." >&2
        exit 1
    fi
done

for vm in dc ca attacker; do
    vb="${VBNAME[$vm]}"
    echo "[$vm] poweroff"
    VBoxManage controlvm "$vb" poweroff 2>/dev/null || true  # already off is fine
    # Give VirtualBox a second to finalise the poweroff before restore.
    sleep 2
    echo "[$vm] restoring baseline snapshot"
    VBoxManage snapshot "$vb" restore baseline >/dev/null
done

for vm in dc ca attacker; do
    vb="${VBNAME[$vm]}"
    echo "[$vm] cold start"
    VBoxManage startvm "$vb" --type headless >/dev/null
done

echo "[reset] waiting for WinRM on dc + ca and SSH on attacker"

wait_winrm() {
    local port=$1 name=$2 deadline=$((SECONDS + 600))
    while [ $SECONDS -lt $deadline ]; do
        if curl -s -o /dev/null --max-time 5 "http://127.0.0.1:${port}/wsman" 2>/dev/null; then
            echo "[$name] WinRM ready"
            return 0
        fi
        sleep 5
    done
    echo "ERROR: [$name] WinRM did not come up within 10 min" >&2
    return 1
}

wait_ssh() {
    local port=$1 name=$2 deadline=$((SECONDS + 300))
    while [ $SECONDS -lt $deadline ]; do
        if nc -z 127.0.0.1 "$port" 2>/dev/null; then
            echo "[$name] SSH ready"
            return 0
        fi
        sleep 3
    done
    echo "ERROR: [$name] SSH did not come up within 5 min" >&2
    return 1
}

# Port mapping from the Vagrantfile forwarded_ports. Defaults: dc=55985, ca=2202.
wait_winrm 55985 dc
wait_winrm 2202  ca
wait_ssh   2222  attacker

echo "[reset] all three VMs restored to baseline and reachable"
