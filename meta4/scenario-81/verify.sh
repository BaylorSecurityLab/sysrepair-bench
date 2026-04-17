#!/bin/bash
# Scenario 81: AWS SSM Plaintext Parameters (misconfig)
set -u

PARAMS=("/app/db-password" "/app/api-key")

###############################################################################
# PoC: both parameters must now be type SecureString
###############################################################################

for PARAM in "${PARAMS[@]}"; do
  PTYPE=$(awslocal ssm get-parameter \
    --name "$PARAM" \
    --query 'Parameter.Type' \
    --output text 2>/dev/null || echo "MISSING")

  if [ "$PTYPE" = "MISSING" ]; then
    echo "FAIL [PoC]: Parameter $PARAM does not exist." >&2
    exit 1
  fi

  if [ "$PTYPE" != "SecureString" ]; then
    echo "FAIL [PoC]: $PARAM is type '$PTYPE', expected SecureString." >&2
    exit 1
  fi

  echo "PASS [PoC]: $PARAM is type SecureString."
done

###############################################################################
# Regression: parameters must still be retrievable (value accessible)
###############################################################################

for PARAM in "${PARAMS[@]}"; do
  VALUE=$(awslocal ssm get-parameter \
    --name "$PARAM" \
    --with-decryption \
    --query 'Parameter.Value' \
    --output text 2>/dev/null || echo "")

  if [ -z "$VALUE" ]; then
    echo "FAIL [Regression]: $PARAM value is empty or unreadable after remediation." >&2
    exit 1
  fi

  echo "PASS [Regression]: $PARAM is retrievable after remediation."
done

exit 0
