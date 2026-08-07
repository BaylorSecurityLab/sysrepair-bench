#!/bin/bash
# Scenario 90: Git History Credential Leak (misconfig)
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

REPO="/opt/app"
SECRET="leaked_secret_42"

###############################################################################
# PoC: git log -p --all must not contain the leaked secret
###############################################################################

if git -C "${REPO}" log -p --all 2>/dev/null | grep -qF "${SECRET}"; then
    record_poc git_log_clean 0 "'${SECRET}' found in git history of ${REPO}"
else
    record_poc git_log_clean 1
fi

###############################################################################
# PoC 2 (behavioural): walk the live git object DB and stream every
# reachable blob through `git cat-file` — this exercises the running git
# plumbing (not just on-disk greps) and catches secrets that survive in
# packed, reflog, or dangling objects that `git log` may hide.
###############################################################################

OBJDB_OK=1
OBJDB_WHY=""

OBJECTS=$(git -C "${REPO}" rev-list --objects --all --reflog 2>/dev/null | awk '{print $1}' || true)
if [ -n "$OBJECTS" ]; then
    if printf '%s\n' "$OBJECTS" \
        | git -C "${REPO}" cat-file --batch='%(objecttype) %(objectname)' --buffer 2>/dev/null \
        | grep -qF "${SECRET}"; then
        OBJDB_OK=0
        OBJDB_WHY="'${SECRET}' still reachable via git cat-file in live object DB of ${REPO}"
    fi
fi

# Unreachable blobs: `git fsck` queries the live object store; any dangling
# blob still carrying the secret is exposed here.
UNREACH=$(git -C "${REPO}" fsck --unreachable --no-reflogs 2>/dev/null \
    | awk '/^unreachable blob/ {print $3}' || true)
for OID in $UNREACH; do
    if git -C "${REPO}" cat-file -p "$OID" 2>/dev/null | grep -qF "${SECRET}"; then
        OBJDB_OK=0
        OBJDB_WHY="unreachable blob $OID still contains '${SECRET}'"
    fi
done

record_poc git_object_db_clean "$OBJDB_OK" "$OBJDB_WHY"

###############################################################################
# Regression: repo must still be a functional git working tree and config.env
# must exist. Exercise the running git binary, not just a file test.
###############################################################################

if git -C "${REPO}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    record_reg git_worktree_valid 1
else
    record_reg git_worktree_valid 0 "${REPO} is no longer a valid git working tree"
fi

if git -C "${REPO}" log -1 --format=%H >/dev/null 2>&1; then
    record_reg git_has_commits 1
else
    record_reg git_has_commits 0 "${REPO} has no reachable commits after remediation"
fi

if [ -f "${REPO}/config.env" ]; then
    record_reg config_env_present 1
else
    record_reg config_env_present 0 "${REPO}/config.env is missing after remediation"
fi

verify_finish
