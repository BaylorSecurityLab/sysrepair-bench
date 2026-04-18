#!/bin/bash
set -u

# --- PoC: check for Terrapin-vulnerable ciphers/MACs in sshd config ---

# Check effective sshd configuration
SSHD_CFG=$(/usr/sbin/sshd -T 2>/dev/null || true)

# Check for chacha20-poly1305 in ciphers
CIPHERS=$(echo "$SSHD_CFG" | grep -i '^ciphers ' | head -1)
if echo "$CIPHERS" | grep -qi 'chacha20-poly1305'; then
    echo "FAIL [PoC]: chacha20-poly1305 is still enabled in sshd ciphers." >&2
    exit 1
fi

# Check for EtM MACs
MACS=$(echo "$SSHD_CFG" | grep -i '^macs ' | head -1)
if echo "$MACS" | grep -qi 'etm@openssh\.com'; then
    echo "FAIL [PoC]: Encrypt-then-MAC (EtM) MACs still enabled in sshd." >&2
    exit 1
fi

# Also check for CBC ciphers (vulnerable with EtM)
if echo "$CIPHERS" | grep -qi '\-cbc'; then
    echo "FAIL [PoC]: CBC ciphers still enabled (vulnerable with EtM)." >&2
    exit 1
fi

echo "PASS [PoC]: no Terrapin-vulnerable ciphers or MACs in sshd config."

# --- Regression: sshd must still accept connections on port 22 ---
for i in 1 2 3 4 5; do
    if ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
          localhost true 2>/dev/null; then
        echo "PASS [Regression]: sshd accepts connections on port 22."
        exit 0
    fi
    # Also accept "Permission denied" — that means sshd IS listening and responding
    if ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
          localhost true 2>&1 | grep -qi 'permission denied'; then
        echo "PASS [Regression]: sshd responds on port 22 (auth required)."
        exit 0
    fi
    sleep 2
done
echo "FAIL [Regression]: sshd not responding on port 22." >&2
exit 1
