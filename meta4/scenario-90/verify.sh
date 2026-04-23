#!/bin/bash
# Scenario 90: Git History Credential Leak (misconfig)
set -u

REPO="/opt/app"
SECRET="leaked_secret_42"

###############################################################################
# PoC: git log -p --all must not contain the leaked secret
###############################################################################

if git -C "${REPO}" log -p --all 2>/dev/null | grep -qF "${SECRET}"; then
    echo "FAIL [PoC]: '${SECRET}' found in git history of ${REPO}." >&2
    exit 1
fi
echo "PASS [PoC]: '${SECRET}' not present in git log -p --all."

###############################################################################
# PoC 2 (behavioural): walk the live git object DB and stream every
# reachable blob through `git cat-file` — this exercises the running git
# plumbing (not just on-disk greps) and catches secrets that survive in
# packed, reflog, or dangling objects that `git log` may hide.
###############################################################################

OBJECTS=$(git -C "${REPO}" rev-list --objects --all --reflog 2>/dev/null | awk '{print $1}')
if [ -n "$OBJECTS" ]; then
    if printf '%s\n' "$OBJECTS" \
        | git -C "${REPO}" cat-file --batch='%(objecttype) %(objectname)' --buffer 2>/dev/null \
        | grep -qF "${SECRET}"; then
        echo "FAIL [PoC]: '${SECRET}' still reachable via git cat-file in live object DB of ${REPO}." >&2
        exit 1
    fi
fi

# Unreachable blobs: `git fsck` queries the live object store; any dangling
# blob still carrying the secret is exposed here.
UNREACH=$(git -C "${REPO}" fsck --unreachable --no-reflogs 2>/dev/null \
    | awk '/^unreachable blob/ {print $3}')
for OID in $UNREACH; do
    if git -C "${REPO}" cat-file -p "$OID" 2>/dev/null | grep -qF "${SECRET}"; then
        echo "FAIL [PoC]: unreachable blob $OID still contains '${SECRET}'." >&2
        exit 1
    fi
done
echo "PASS [PoC]: live git object DB (reachable + unreachable blobs) is free of '${SECRET}'."

###############################################################################
# Regression: repo must still be a functional git working tree and config.env
# must exist. Exercise the running git binary, not just a file test.
###############################################################################

if ! git -C "${REPO}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "FAIL [Regression]: ${REPO} is no longer a valid git working tree." >&2
    exit 1
fi

if ! git -C "${REPO}" log -1 --format=%H >/dev/null 2>&1; then
    echo "FAIL [Regression]: ${REPO} has no reachable commits after remediation." >&2
    exit 1
fi

if [ -f "${REPO}/config.env" ]; then
    echo "PASS [Regression]: ${REPO}/config.env exists and git repo is healthy."
    exit 0
fi

echo "FAIL [Regression]: ${REPO}/config.env is missing after remediation." >&2
exit 1
