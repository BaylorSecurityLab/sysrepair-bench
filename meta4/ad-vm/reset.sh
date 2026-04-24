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

# Resolve guest->host forwarded port from VBoxManage rather than hardcoding:
# vagrant auto-assigns SSH ports per-VM (2200/2201/2204/...) so attacker's
# SSH port isn't fixed.
forwarded_port() {
    local vb=$1 rule=$2  # rule is "ssh" or "winrm_http" etc.
    VBoxManage showvminfo "$vb" --machinereadable 2>&1 \
      | awk -F'=' -v r="$rule" '
          /^Forwarding\(/ {
              gsub(/"/, "", $2)
              split($2, f, ",")
              if (f[1] == r) { print f[4]; exit }
          }'
}

wait_tcp() {
    local port=$1 name=$2 kind=$3 deadline=$((SECONDS + 600))
    while [ $SECONDS -lt $deadline ]; do
        if (echo > "/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
            echo "[$name] $kind ready (tcp/$port)"
            return 0
        fi
        sleep 5
    done
    echo "ERROR: [$name] $kind did not come up within 10 min (tcp/$port)" >&2
    return 1
}

DC_WINRM=$(forwarded_port meta4-ad-dc       winrm)
CA_WINRM=$(forwarded_port meta4-ad-ca       winrm)
AT_SSH=$(  forwarded_port meta4-ad-attacker ssh)

# Fallbacks if vagrant hasn't labelled the rule name as "winrm" (old boxes
# sometimes call it "winrm_http").
[ -z "$DC_WINRM" ] && DC_WINRM=$(forwarded_port meta4-ad-dc winrm_http)
[ -z "$CA_WINRM" ] && CA_WINRM=$(forwarded_port meta4-ad-ca winrm_http)

: "${DC_WINRM:?could not resolve dc WinRM forwarded port}"
: "${CA_WINRM:?could not resolve ca WinRM forwarded port}"
: "${AT_SSH:?could not resolve attacker ssh forwarded port}"

wait_tcp "$DC_WINRM" dc       winrm
wait_tcp "$CA_WINRM" ca       winrm
wait_tcp "$AT_SSH"   attacker ssh

echo "[reset] all three VMs restored to baseline and reachable"
