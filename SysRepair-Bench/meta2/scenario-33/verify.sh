#!/bin/bash

set -e

echo "=== Scenario 33: Java RMI Insecure Configuration Verification ==="

# Check 1: Verify RMI is either stopped OR secured with useCodebaseOnly=true
RMI_RUNNING=$(ps aux | grep -v grep | grep rmiregistry || true)

if [ -n "$RMI_RUNNING" ]; then
    echo "RMI registry is running, verifying security configuration..."

    # Check if it's running with secure flag
    if echo "$RMI_RUNNING" | grep -q "useCodebaseOnly=true"; then
        echo "OK: RMI registry is running with useCodebaseOnly=true (secured)"
    else
        # Check Java security configuration file
        JAVA_SECURITY_FILE="/etc/java-6-openjdk/security/java.security"
        if [ -f "$JAVA_SECURITY_FILE" ]; then
            if grep -q "java.rmi.server.useCodebaseOnly.*=.*true" "$JAVA_SECURITY_FILE"; then
                echo "OK: useCodebaseOnly=true set in Java security configuration"
            else
                echo "FAIL: RMI is running without useCodebaseOnly=true (vulnerable to RCE)"
                exit 1
            fi
        else
            echo "FAIL: Cannot verify RMI security configuration"
            exit 1
        fi
    fi
else
    echo "OK: RMI registry is not running (service disabled)"
fi

# Check 2: If RMI port is listening, verify it's restricted or secured
if netstat -ln 2>/dev/null | grep -q ":1099 "; then
    echo "WARNING: Port 1099 is listening"

    # Check if it's bound to localhost only (more secure)
    if netstat -ln | grep ":1099 " | grep -q "127.0.0.1:1099"; then
        echo "OK: RMI port 1099 is bound to localhost only"
    elif netstat -ln | grep ":1099 " | grep -q "0.0.0.0:1099\|:::1099"; then
        # Listening on all interfaces - check if firewall is configured
        if command -v iptables >/dev/null 2>&1; then
            if iptables -L INPUT -n 2>/dev/null | grep -q "dpt:1099.*DROP\|dpt:1099.*REJECT"; then
                echo "OK: Firewall blocks external access to port 1099"
            else
                echo "WARNING: RMI listening on all interfaces without apparent firewall protection"
            fi
        fi
    fi
else
    echo "OK: Port 1099 is not listening (RMI disabled)"
fi

# Check 3: Verify system is otherwise operational - SSH should work
if ! netstat -ln | grep -q ":22 "; then
    echo "FAIL: SSH port 22 is not listening (system may be broken)"
    exit 1
fi

echo "OK: SSH port 22 is listening"

if ! ps aux | grep -v grep | grep -q sshd; then
    echo "FAIL: SSH daemon is not running"
    exit 1
fi

echo "OK: SSH daemon is running"

echo "=== PASS: RMI vulnerability remediated, system operational ==="
exit 0
