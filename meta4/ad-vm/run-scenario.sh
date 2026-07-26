#!/usr/bin/env bash
# meta4/ad-vm/run-scenario.sh
#
# Scorer entry point, preserved as the dispatch contract documented in
# lib/harness-schema.md. The implementation now delegates to the PowerShell
# lab layer -- Hyper-V and AutomatedLab are PowerShell-native, so host-side
# orchestration lives there. This file exists so the contract does not change.
#
# Usage:
#   ./run-scenario.sh NN                 # restore -> inject -> handoff
#   ./run-scenario.sh NN --verify-only   # grade; exits 0 iff both gates pass
#
# NN is a two-digit scenario id (e.g. 01, 13, 20).
#
# NOTE: PowerShell must run elevated. Hyper-V cmdlets and PowerShell Direct
# both require it.

set -euo pipefail

cd "$(dirname "$0")"

NN="${1:-}"
MODE="${2:-run}"

if [[ ! "$NN" =~ ^[0-9]{2}$ ]]; then
    echo "Usage: $0 NN [--verify-only]" >&2
    exit 2
fi

# MODE is validated rather than defaulted-and-compared. The previous version
# treated anything that was not exactly "--verify-only" as "run", so a typo
# such as `--verify` silently triggered a destructive full reset and destroyed
# an in-flight agent's work.
case "$MODE" in
    run|--verify-only) ;;
    *)
        echo "ERROR: unknown mode '$MODE'. Expected nothing, 'run', or '--verify-only'." >&2
        echo "Refusing to guess -- an unrecognised mode used to trigger a full reset." >&2
        exit 2
        ;;
esac

if ! command -v powershell.exe >/dev/null 2>&1 && ! command -v pwsh >/dev/null 2>&1; then
    echo "ERROR: no PowerShell found. This harness runs on a Hyper-V host." >&2
    exit 2
fi

PS=$(command -v powershell.exe || command -v pwsh)

if [ "$MODE" = "--verify-only" ]; then
    "$PS" -NoProfile -ExecutionPolicy Bypass -Command \
        ". ./lab/Invoke-Scenario.ps1; \$r = Invoke-ScenarioVerify -ScenarioId '$NN'; if (-not \$r.Passed) { exit 1 }"
    exit $?
fi

"$PS" -NoProfile -ExecutionPolicy Bypass -Command \
    ". ./lab/Invoke-Scenario.ps1; Invoke-ScenarioInject -ScenarioId '$NN'"
