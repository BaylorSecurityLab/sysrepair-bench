#!/usr/bin/env bash
# meta3/windows-vm/run-scenario.sh
# Dispatch contract, mirrors meta4/ad-vm/run-scenario.sh but drives a single
# AutomatedLab/Hyper-V VM via PowerShell helpers (no vagrant — AutomatedLab uses
# PowerShell Direct / Invoke-LabCommand instead of vagrant winrm).
#
# Usage:
#   ./run-scenario.sh NN                 # restore baseline -> stage -> inject
#   ./run-scenario.sh NN --verify-only   # run verify-poc + verify-service, exit 0 iff both pass
#
# NN is a two-digit scenario id (10, 11, 12). Must run on the Hyper-V host in an
# ELEVATED shell (AutomatedLab requires admin). See lab/RUNBOOK.md.

set -euo pipefail
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

cd "$(dirname "$0")"

NN="${1:-}"
MODE="${2:-run}"

if [[ ! "$NN" =~ ^[0-9]{2}$ ]]; then
    echo "Usage: $0 NN [--verify-only]" >&2
    exit 2
fi

# Resolve the scenario dir (scenario-NN-*).
SCENARIO_DIR=$(find . -maxdepth 1 -type d -name "scenario-$NN-*" -printf '%f\n' | head -n1)
if [ -z "$SCENARIO_DIR" ]; then
    echo "ERROR: no scenario-$NN-* directory found" >&2
    exit 2
fi
if [ ! -f "$SCENARIO_DIR/harness.json" ]; then
    echo "ERROR: $SCENARIO_DIR/harness.json missing" >&2
    exit 2
fi

PWSH="powershell.exe -NoProfile -ExecutionPolicy Bypass -File"

if [ "$MODE" = "--verify-only" ]; then
    $PWSH "lab/Test-ScenarioGates.ps1" -Id "$NN"
    exit $?
fi

# --- full lifecycle: restore baseline -> stage -> inject ---
$PWSH "lab/Invoke-Scenario.ps1" -Id "$NN"

echo ""
echo "========================================================================"
echo " Scenario $NN ready on the AutomatedLab VM (META3WIN)."
echo " Agent reaches the VM over the SSH bridge (port 22, user svc_admin)."
echo " When the agent finishes, scorer runs:"
echo "   $0 $NN --verify-only"
echo "========================================================================"
