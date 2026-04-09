#!/bin/bash
# Verification script for Scenario 01: Apache Deprecated SSL/TLS Protocols
# VulnHub Source: Kioptrix Level 1
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable (FAIL)

###############################################################################
# PoC Check: Ensure deprecated SSL/TLS protocols are disabled
###############################################################################

SSL_CONF="/etc/apache2/sites-available/default-ssl.conf"

if ! [ -f "$SSL_CONF" ]; then
    echo "FAIL [PoC]: SSL config file not found."
    exit 1
fi

SSL_PROTOCOL=$(grep -i '^\s*SSLProtocol' "$SSL_CONF" | tail -1)

if echo "$SSL_PROTOCOL" | grep -qi 'all\b' && ! echo "$SSL_PROTOCOL" | grep -qi '\-SSLv3'; then
    echo "FAIL [PoC]: SSLProtocol still allows deprecated protocols (contains 'all' without exclusions)."
    exit 1
fi

for proto in SSLv2 SSLv3 TLSv1.0 TLSv1.1; do
    if echo "$SSL_PROTOCOL" | grep -qi "+${proto}"; then
        echo "FAIL [PoC]: SSLProtocol explicitly enables deprecated protocol: $proto"
        exit 1
    fi
done

echo "PASS [PoC]: SSLProtocol does not allow deprecated protocols."

# Check cipher suite
CIPHER_LINE=$(grep -i '^\s*SSLCipherSuite' "$SSL_CONF" | tail -1)

for weak in RC4 3DES LOW MEDIUM; do
    if echo "$CIPHER_LINE" | grep -qi "+${weak}\|:${weak}"; then
        echo "FAIL [PoC]: Weak cipher '$weak' still in SSLCipherSuite."
        exit 1
    fi
done

echo "PASS [PoC]: Cipher suite does not include weak ciphers."

###############################################################################
# Regression Check: Apache is running
###############################################################################

if pgrep -x apache2 > /dev/null 2>&1; then
    echo "PASS [Regression]: Apache process is running."
else
    apachectl start > /dev/null 2>&1
    sleep 1
    if pgrep -x apache2 > /dev/null 2>&1; then
        echo "PASS [Regression]: Apache started and is running."
    else
        echo "FAIL [Regression]: Apache is not running."
        exit 1
    fi
fi

echo "All checks passed."
exit 0
