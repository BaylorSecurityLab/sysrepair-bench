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

# PoC (behavioral): attempt to negotiate chacha20-poly1305 cipher via openssl/ssh
# If the cipher is disabled, the connection will fail to negotiate it.
if command -v ssh >/dev/null 2>&1; then
    CIPHER_TEST=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
        -c chacha20-poly1305@openssh.com localhost true 2>&1 || true)
    if echo "$CIPHER_TEST" | grep -qi 'no matching cipher\|unable to negotiate'; then
        echo "PASS [PoC]: sshd rejects chacha20-poly1305 cipher negotiation."
    elif echo "$CIPHER_TEST" | grep -qi 'permission denied'; then
        echo "FAIL [PoC]: sshd accepted chacha20-poly1305 cipher (auth reached)." >&2
        exit 1
    fi
fi

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
