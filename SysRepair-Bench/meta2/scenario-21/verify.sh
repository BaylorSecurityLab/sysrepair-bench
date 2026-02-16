#!/bin/bash
# Verify remediation of OpenSSL CCS Injection CVE-2014-0224 (scenario-21)

PASS=0
FAIL=1

##############################################
# PoC Check: OpenSSL must be upgraded or SSL disabled
##############################################

# Check OpenSSL version
OPENSSL_VER=$(openssl version 2>/dev/null | awk '{print $2}')

if [ -n "$OPENSSL_VER" ]; then
    # Extract version components: expecting format like 0.9.8g, 0.9.8za, 1.0.0m, etc.
    # Vulnerable: < 0.9.8za, 1.0.0 < 1.0.0m, 1.0.1 < 1.0.1h

    # Simple check: if version starts with 0.9.8 and letter suffix < 'za'
    if echo "$OPENSSL_VER" | grep -q "^0\.9\.8"; then
        SUFFIX=$(echo "$OPENSSL_VER" | sed 's/0\.9\.8//')
        # za is the minimum safe version; single-letter suffixes (a-z) are all vulnerable
        if [ ${#SUFFIX} -le 1 ]; then
            # Check if SSL is disabled on PostgreSQL as alternative fix
            PG_CONF=$(find /etc/postgresql -name postgresql.conf 2>/dev/null | head -1)
            if [ -n "$PG_CONF" ]; then
                SSL_SETTING=$(grep "^ssl" "$PG_CONF" 2>/dev/null | grep -v "ssl_" | tail -1)
                if echo "$SSL_SETTING" | grep -qi "on"; then
                    echo "FAIL: OpenSSL $OPENSSL_VER is vulnerable and PostgreSQL SSL is still enabled"
                    exit $FAIL
                else
                    echo "PASS: OpenSSL is old but PostgreSQL SSL is disabled"
                fi
            fi
        else
            echo "PASS: OpenSSL version $OPENSSL_VER appears patched"
        fi
    else
        echo "PASS: OpenSSL version $OPENSSL_VER is not in the vulnerable 0.9.8 range"
    fi
else
    echo "WARNING: Could not determine OpenSSL version"
fi

##############################################
# Regression Check: PostgreSQL must still work
##############################################

# Check that PostgreSQL is running
if ! netstat -tlnp 2>/dev/null | grep -q ':5432 '; then
    echo "FAIL: PostgreSQL is not listening on port 5432"
    exit $FAIL
fi

# Test a basic connection
PGRESULT=$(su - postgres -c "psql -d testdb -t -c 'SELECT name FROM test_data LIMIT 1;'" 2>/dev/null | tr -d '[:space:]')
if [ "$PGRESULT" != "test_entry" ]; then
    # Try without switching user
    PGRESULT2=$(psql -h 127.0.0.1 -U testuser -d testdb -t -c "SELECT name FROM test_data LIMIT 1;" 2>/dev/null | tr -d '[:space:]')
    if [ "$PGRESULT2" != "test_entry" ]; then
        echo "FAIL: PostgreSQL is not responding to queries properly"
        exit $FAIL
    fi
fi

echo "PASS: PostgreSQL is functional"
exit $PASS
