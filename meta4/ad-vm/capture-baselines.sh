#!/usr/bin/env bash
# meta4/ad-vm/capture-baselines.sh
# One-time capture of `baseline` snapshot on all three VMs.
# Run this once after `vagrant up` completes cleanly; re-run only after
# intentional baseline changes.
#
# VMs are halted via VBoxManage (not `vagrant halt`, which intermittently
# stack-traces on Windows hosts when its WinRM graceful-shutdown probe
# races the save-state lock) before snapshotting. Live-state snapshots of
# a running DC resume into a half-initialized state on restore -- SYSVOL
# replication, DNS, and WinRM listener all relaunch from mid-boot and take
# 10-15 min to settle, which blows through reset.sh's WinRM wait. Cold
# halted snapshots restore in 2-3 min on scenario reset instead.

set -euo pipefail

cd "$(dirname "$0")"

declare -A VBNAME=(
    [dc]="meta4-ad-dc"
    [ca]="meta4-ad-ca"
    [attacker]="meta4-ad-attacker"
)

echo "[capture-baselines] halting VMs for cold snapshot"
for vm in dc ca attacker; do
    vb="${VBNAME[$vm]}"
    state=$(VBoxManage showvminfo "$vb" --machinereadable 2>&1 | awk -F'=' '/^VMState=/ {gsub(/"/,"",$2); print $2}')
    if [ "$state" = "running" ]; then
        echo "[$vm] acpipowerbutton then waiting for poweroff"
        VBoxManage controlvm "$vb" acpipowerbutton >/dev/null
        # Allow up to 60s for graceful shutdown; fall back to hard poweroff.
        for _ in $(seq 1 12); do
            sleep 5
            state=$(VBoxManage showvminfo "$vb" --machinereadable 2>&1 | awk -F'=' '/^VMState=/ {gsub(/"/,"",$2); print $2}')
            if [ "$state" = "poweroff" ]; then break; fi
        done
        if [ "$state" != "poweroff" ]; then
            echo "[$vm] ACPI shutdown didn't complete in 60s; forcing poweroff"
            VBoxManage controlvm "$vb" poweroff >/dev/null 2>&1 || true
            sleep 2
        fi
    else
        echo "[$vm] already state=$state"
    fi
done

for vm in dc ca attacker; do
    vb="${VBNAME[$vm]}"
    if VBoxManage snapshot "$vb" list 2>/dev/null | grep -qF 'Name: baseline'; then
        echo "[$vm] baseline snapshot already exists; deleting to refresh"
        VBoxManage snapshot "$vb" delete baseline >/dev/null
    fi
    echo "[$vm] capturing baseline snapshot (halted)"
    VBoxManage snapshot "$vb" take baseline >/dev/null
done

echo "[capture-baselines] restarting VMs"
for vm in dc ca attacker; do
    vb="${VBNAME[$vm]}"
    echo "[$vm] startvm"
    VBoxManage startvm "$vb" --type headless >/dev/null
done

echo "[capture-baselines] all three baselines captured"
for vm in dc ca attacker; do
    vb="${VBNAME[$vm]}"
    VBoxManage snapshot "$vb" list | grep 'Name: baseline' || echo "[$vm] WARNING: no baseline listed"
done
