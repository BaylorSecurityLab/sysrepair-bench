#!/usr/bin/env bash
# meta4/ad-vm/run-scenario.sh
# Usage:
#   ./run-scenario.sh NN                 # restore→inject→handoff
#   ./run-scenario.sh NN --verify-only   # run verify-poc.sh + verify-service.ps1, exit 0 iff both pass
#
# NN is a two-digit scenario id (e.g. 01, 13, 20).

set -euo pipefail

cd "$(dirname "$0")"

NN="${1:-}"
MODE="${2:-run}"

if [[ ! "$NN" =~ ^[0-9]{2}$ ]]; then
    echo "Usage: $0 NN [--verify-only]" >&2
    exit 2
fi

SCENARIO_DIR="scenario-$NN"
if [ ! -d "$SCENARIO_DIR" ]; then
    echo "ERROR: $SCENARIO_DIR not found" >&2
    exit 2
fi

HARNESS="$SCENARIO_DIR/harness.json"
if [ ! -f "$HARNESS" ]; then
    echo "ERROR: $HARNESS missing" >&2
    exit 2
fi

# Parse harness.json (requires jq).
INJECT_TARGET=$(jq -r '.inject.target'         "$HARNESS")
VERIFY_SVC_TGT=$(jq -r '.verify_service.target' "$HARNESS")

run_verify() {
    local poc_rc=0
    local svc_rc=0

    echo "[run-scenario] verify-poc on attacker"
    vagrant ssh attacker -c "bash /opt/meta4/$SCENARIO_DIR/verify-poc.sh" || poc_rc=$?

    echo "[run-scenario] verify-service on $VERIFY_SVC_TGT"
    vagrant winrm "$VERIFY_SVC_TGT" -s powershell \
        -c "C:\\meta4\\$SCENARIO_DIR\\verify-service.ps1" || svc_rc=$?

    if [ "$poc_rc" -eq 0 ] && [ "$svc_rc" -eq 0 ]; then
        echo "[run-scenario] PASS (poc=$poc_rc, service=$svc_rc)"
        return 0
    else
        echo "[run-scenario] FAIL (poc=$poc_rc, service=$svc_rc)" >&2
        return 1
    fi
}

if [ "$MODE" = "--verify-only" ]; then
    run_verify
    exit $?
fi

# --- full lifecycle ---

echo "[run-scenario] reset all VMs to baseline"
./reset.sh

echo "[run-scenario] copy scenario into VMs"
# DC + CA get Windows paths; attacker gets POSIX.
vagrant winrm "$INJECT_TARGET" -s powershell \
    -c "New-Item -ItemType Directory -Path C:\\meta4\\$SCENARIO_DIR -Force | Out-Null"
vagrant upload "$SCENARIO_DIR/inject.ps1"         "C:\\meta4\\$SCENARIO_DIR\\inject.ps1"         "$INJECT_TARGET"
vagrant upload "$SCENARIO_DIR/verify-service.ps1" "C:\\meta4\\$SCENARIO_DIR\\verify-service.ps1" "$VERIFY_SVC_TGT"

vagrant ssh attacker -c "sudo install -d -m 755 /opt/meta4/$SCENARIO_DIR"
vagrant upload "$SCENARIO_DIR/verify-poc.sh" "/opt/meta4/$SCENARIO_DIR/verify-poc.sh" attacker
vagrant upload "$SCENARIO_DIR/threat.md"     "/home/vagrant/threat.md"               attacker
vagrant ssh attacker -c "sudo chmod +x /opt/meta4/$SCENARIO_DIR/verify-poc.sh"

echo "[run-scenario] injecting on $INJECT_TARGET"
vagrant winrm "$INJECT_TARGET" -s powershell \
    -c "C:\\meta4\\$SCENARIO_DIR\\inject.ps1"

echo ""
echo "========================================================================"
echo " Scenario $NN ready. Agent workspace:"
echo "   ssh vagrant@10.20.30.10      (password: vagrant)"
echo "   threat.md and creds.txt in \$HOME on attacker"
echo ""
echo " When the agent finishes, scorer runs:"
echo "   $0 $NN --verify-only"
echo "========================================================================"
