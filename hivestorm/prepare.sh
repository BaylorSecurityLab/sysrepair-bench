#!/usr/bin/env bash
# Regenerate roles.json + task.md for one or all hivestorm scenarios.
#
# Usage:
#   hivestorm/prepare.sh                 # all scenarios, random seeds
#   hivestorm/prepare.sh 01              # scenario-01-debian9 only
#   SEED=42 hivestorm/prepare.sh 01      # reproducible
set -euo pipefail

cd "$(dirname "$0")/.."  # repo root

declare -A DIRS=(
    [01]=hivestorm/scenario-01-debian9
    [02]=hivestorm/scenario-02-ubuntu1604
    [03]=hivestorm/scenario-03-win10
    [04]=hivestorm/scenario-04-win2019
    [05]=hivestorm/scenario-05-win2016
    [06]=hivestorm/scenario-06-debian9-postgres
    [07]=hivestorm/scenario-07-ubuntu1804-samba
    [08]=hivestorm/scenario-08-win-iis
    [09]=hivestorm/scenario-09-ubuntu-nginx-phpbb
    [10]=hivestorm/scenario-10-ubuntu-faillock
    [11]=hivestorm/scenario-11-win-dc-dns
    [12]=hivestorm/scenario-12-centos7-lamp
    [13]=hivestorm/scenario-13-ad-dc-win2019
    [14]=hivestorm/scenario-14-freebsd13
    [15]=hivestorm/scenario-15-docker-host
    [16]=hivestorm/scenario-16-nginx-phpfpm
)

targets=("${@}")
if [ ${#targets[@]} -eq 0 ]; then
    targets=(01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16)   # all scenarios.
fi

for sid in "${targets[@]}"; do
    dir=${DIRS[$sid]:-}
    if [ -z "$dir" ] || [ ! -d "$dir" ]; then
        echo "skip: scenario $sid (dir missing)" >&2
        continue
    fi
    seed_arg=()
    if [ -n "${SEED:-}" ]; then seed_arg=(--seed "$SEED"); fi
    python -m hivestorm.common.roles \
        --scenario "$sid" \
        "${seed_arg[@]}" \
        --out         "${dir}/build/roles.json" \
        --render-task "${dir}/task.md"
done
