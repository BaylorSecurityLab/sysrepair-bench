#!/bin/bash
# Scenario 82: AWS S3 Public Bucket Policy (misconfig)
set -u

BUCKET="sensitive-data"

###############################################################################
# PoC: bucket policy must not contain "Principal": "*"
###############################################################################

POLICY=$(awslocal s3api get-bucket-policy \
  --bucket "$BUCKET" \
  --query 'Policy' \
  --output text 2>/dev/null || echo "NO_POLICY")

if [ "$POLICY" = "NO_POLICY" ] || [ -z "$POLICY" ]; then
  echo "PASS [PoC]: No bucket policy found (public access removed)."
else
  # Check for wildcard principal in any statement
  if echo "$POLICY" | python3 -c "
import sys, json, urllib.parse
raw = sys.stdin.read().strip()
try:
    doc = json.loads(urllib.parse.unquote(raw))
except Exception:
    doc = json.loads(raw)
for s in doc.get('Statement', []):
    if s.get('Effect') == 'Allow':
        principal = s.get('Principal', '')
        if principal == '*' or (isinstance(principal, dict) and '*' in str(principal)):
            sys.exit(1)
sys.exit(0)
" 2>/dev/null; then
    echo "PASS [PoC]: Bucket policy does not contain 'Principal: *'."
  else
    echo "FAIL [PoC]: Bucket policy still contains 'Principal: *' (public access)." >&2
    exit 1
  fi
fi

###############################################################################
# PoC 2: Block Public Access must be enabled
###############################################################################

BPA=$(awslocal s3api get-public-access-block \
  --bucket "$BUCKET" \
  --query 'PublicAccessBlockConfiguration' \
  --output json 2>/dev/null || echo "{}")

BLOCK_OK=$(echo "$BPA" | python3 -c "
import sys, json
cfg = json.load(sys.stdin)
if cfg.get('BlockPublicPolicy') and cfg.get('RestrictPublicBuckets'):
    print('true')
else:
    print('false')
" 2>/dev/null || echo "false")

if [ "$BLOCK_OK" = "true" ]; then
  echo "PASS [PoC]: S3 Block Public Access is enabled."
else
  echo "FAIL [PoC]: S3 Block Public Access (BlockPublicPolicy/RestrictPublicBuckets) not fully enabled." >&2
  exit 1
fi

###############################################################################
# Regression: bucket and object must still exist
###############################################################################

STATUS=$(awslocal s3api head-object \
  --bucket "$BUCKET" \
  --key "customers.csv" \
  --query 'ContentLength' \
  --output text 2>/dev/null || echo "")

if [ -n "$STATUS" ]; then
  echo "PASS [Regression]: customers.csv still exists in bucket $BUCKET."
  exit 0
fi

echo "FAIL [Regression]: customers.csv not found in bucket $BUCKET after remediation." >&2
exit 1
