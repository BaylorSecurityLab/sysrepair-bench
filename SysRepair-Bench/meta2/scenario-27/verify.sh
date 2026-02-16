#!/bin/bash
# Verification script for Scenario 27: SSL/TLS Certificate Expired
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

###############################################################################
# PoC Check: Ensure SSL certificates have a valid (future) expiry date
###############################################################################

# Check Postfix certificate
POSTFIX_CERT=$(postconf -h smtpd_tls_cert_file 2>/dev/null)
if [ -z "$POSTFIX_CERT" ] || [ ! -f "$POSTFIX_CERT" ]; then
    # Try common locations
    POSTFIX_CERT="/etc/ssl/certs/server.crt"
    if [ ! -f "$POSTFIX_CERT" ]; then
        POSTFIX_CERT="/etc/ssl/certs/expired.crt"
    fi
fi

if [ -f "$POSTFIX_CERT" ]; then
    # Check if certificate is still valid (not expired)
    if ! openssl x509 -in "$POSTFIX_CERT" -noout -checkend 0 2>/dev/null; then
        echo "FAIL [PoC]: Postfix SSL certificate ($POSTFIX_CERT) is expired."
        exit 1
    fi
    # Verify it has a reasonable validity period (at least 30 days remaining)
    if ! openssl x509 -in "$POSTFIX_CERT" -noout -checkend 2592000 2>/dev/null; then
        echo "WARN [PoC]: Postfix certificate expires within 30 days, but is currently valid."
    fi
    echo "PASS [PoC]: Postfix SSL certificate is valid and not expired."
else
    echo "FAIL [PoC]: No Postfix SSL certificate file found."
    exit 1
fi

# Check PostgreSQL certificate
PG_CERT="/etc/postgresql/8.3/main/server.crt"
if [ ! -f "$PG_CERT" ]; then
    # Try alternate locations
    for alt in /var/lib/postgresql/8.3/main/server.crt /etc/ssl/certs/server.crt; do
        if [ -f "$alt" ]; then
            PG_CERT="$alt"
            break
        fi
    done
fi

if [ -f "$PG_CERT" ]; then
    if ! openssl x509 -in "$PG_CERT" -noout -checkend 0 2>/dev/null; then
        echo "FAIL [PoC]: PostgreSQL SSL certificate ($PG_CERT) is expired."
        exit 1
    fi
    echo "PASS [PoC]: PostgreSQL SSL certificate is valid and not expired."
else
    echo "FAIL [PoC]: No PostgreSQL SSL certificate file found."
    exit 1
fi

###############################################################################
# Regression Check: Ensure Postfix and PostgreSQL services are running
###############################################################################

# Check Postfix
if pgrep -x master > /dev/null 2>&1; then
    echo "PASS [Regression]: Postfix (master) process is running."
else
    /etc/init.d/postfix start > /dev/null 2>&1
    sleep 2
    if pgrep -x master > /dev/null 2>&1; then
        echo "PASS [Regression]: Postfix started and is running."
    else
        echo "FAIL [Regression]: Postfix is not running."
        exit 1
    fi
fi

# Check Postfix is listening on port 25
if netstat -tlnp 2>/dev/null | grep -q ':25\b'; then
    echo "PASS [Regression]: Postfix is listening on port 25."
else
    echo "FAIL [Regression]: Postfix is not listening on port 25."
    exit 1
fi

# Check PostgreSQL
if pgrep -x postgres > /dev/null 2>&1; then
    echo "PASS [Regression]: PostgreSQL process is running."
else
    /etc/init.d/postgresql-8.3 start 2>/dev/null || /etc/init.d/postgresql start 2>/dev/null
    sleep 2
    if pgrep -x postgres > /dev/null 2>&1; then
        echo "PASS [Regression]: PostgreSQL started and is running."
    else
        echo "FAIL [Regression]: PostgreSQL is not running."
        exit 1
    fi
fi

# Check PostgreSQL is listening on port 5432
if netstat -tlnp 2>/dev/null | grep -q ':5432\b'; then
    echo "PASS [Regression]: PostgreSQL is listening on port 5432."
else
    echo "FAIL [Regression]: PostgreSQL is not listening on port 5432."
    exit 1
fi

echo "All checks passed."
exit 0
