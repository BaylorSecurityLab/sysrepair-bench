#!/bin/bash
# Scenario 81: AWS SSM Plaintext Parameters (misconfig)
set -u
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

PARAMS=("/app/db-password" "/app/api-key")

# Wait for the LIVE LocalStack endpoint + SSM provisioning before probing.
#
# DEADLINE-bounded with a cap on each probe. The loop was written as 60 x
# `sleep 2`, i.e. an intended ~120s wait, but that counts only the sleeps: a
# single awslocal call against a DEAD endpoint blocks ~13.6s on botocore connect
# retries, so it actually ran ~15 minutes and the verifier was killed by the
# runner (600s) and by production scorer.py (360s) before verify_finish. A run
# with no summary is silently DROPPED from the collateral-damage denominator.
# The intended window is unchanged; it is now actually honoured.
_DEADLINE=$(( $(date +%s) + 120 ))
while [ "$(date +%s)" -lt "$_DEADLINE" ]; do
  timeout 5 awslocal ssm get-parameter --name /app/db-password >/dev/null 2>&1 && break
  sleep 2
done

###############################################################################
# PoC: both parameters must now be type SecureString
###############################################################################

for PARAM in "${PARAMS[@]}"; do
  # Short, filesystem-safe check id derived from the parameter path.
  PID="securestring_$(printf '%s' "$PARAM" | tr -c 'a-zA-Z0-9' '_' | sed 's/^_*//;s/_*$//')"

  PTYPE=$(awslocal ssm get-parameter \
    --name "$PARAM" \
    --query 'Parameter.Type' \
    --output text 2>/dev/null || echo "MISSING")

  # A dead SSM endpoint yields MISSING, which FAILS here — the PoC demands
  # affirmative evidence of SecureString, so killing LocalStack earns nothing.
  if [ "${PTYPE:-MISSING}" = "MISSING" ]; then
    record_poc "$PID" 0 "parameter $PARAM does not exist (or SSM is unreachable)"
  elif [ "$PTYPE" != "SecureString" ]; then
    record_poc "$PID" 0 "$PARAM is type '$PTYPE', expected SecureString"
  else
    record_poc "$PID" 1 "$PARAM is type SecureString"
  fi
done

###############################################################################
# Regression: parameters must still be retrievable (value accessible)
###############################################################################

for PARAM in "${PARAMS[@]}"; do
  RID="retrievable_$(printf '%s' "$PARAM" | tr -c 'a-zA-Z0-9' '_' | sed 's/^_*//;s/_*$//')"

  VALUE=$(awslocal ssm get-parameter \
    --name "$PARAM" \
    --with-decryption \
    --query 'Parameter.Value' \
    --output text 2>/dev/null || echo "")

  if [ -z "${VALUE:-}" ]; then
    record_reg "$RID" 0 "$PARAM value is empty or unreadable after remediation"
  else
    record_reg "$RID" 1 "$PARAM is retrievable after remediation"
  fi
done

verify_finish
