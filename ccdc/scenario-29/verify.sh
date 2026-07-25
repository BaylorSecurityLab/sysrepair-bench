#!/bin/bash
# Scenario 29: No firewall installed
# Verification: PoC should fail (firewall active) AND functionality test should pass

PASS=true

# No ss/netstat/nc in this image - use bash's /dev/tcp for connectivity probes.
tcp_connect() {   # $1 = port
    timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null
}

# WAS BROKEN: every "is the firewall active" test read a FILE, never the kernel.
# `ufw status` reports "active" purely from ENABLED=yes in /etc/ufw/ufw.conf and
# prints its rule list out of /lib/ufw/user.rules; `ufw status verbose` prints
# "Default: deny (incoming)" out of /etc/default/ufw. Echoing ENABLED=yes into
# ufw.conf with zero rules actually loaded therefore passed the whole PoC.
# The kernel's netfilter table is now the source of truth.
if ! command -v iptables > /dev/null 2>&1; then
    echo "FAIL [PoC]: No packet filter (iptables) is installed, so no firewall can be enforced"
    PASS=false
    IPT_RULES=""
else
    IPT_RULES=$(iptables -S 2>/dev/null)
    if [ -z "$IPT_RULES" ]; then
        echo "FAIL [PoC]: iptables is installed but the kernel ruleset could not be read"
        PASS=false
    fi
fi

if command -v ufw > /dev/null 2>&1; then
    UFW_STATUS=$(ufw status 2>/dev/null | head -1)
    # WAS BROKEN: `grep -qi "active"` also matches the string "inactive".
    if echo "$UFW_STATUS" | grep -qiE '^Status:[[:space:]]*active[[:space:]]*$'; then
        echo "INFO [PoC]: ufw reports '$UFW_STATUS' (file-based; kernel state checked below)"
    else
        echo "FAIL [PoC]: ufw is installed but not active ($UFW_STATUS)"
        PASS=false
    fi
fi

if [ -n "$IPT_RULES" ]; then
    LOADED=$(echo "$IPT_RULES" | grep -c '^-A ')
    if [ "$LOADED" -gt 0 ]; then
        echo "PASS [PoC]: the kernel has $LOADED filter rules loaded"
    else
        echo "FAIL [PoC]: the kernel netfilter ruleset is empty — nothing is actually being filtered"
        PASS=false
    fi

    # --- PoC Test: incoming traffic must be denied by default ---
    # WAS BROKEN: this was a word count (`grep -cE 'DROP|REJECT'`) over the
    # human-readable `iptables -L` output, which counts the word "DROP" wherever
    # it appears — including in the policy line and in comments — and says
    # nothing about whether unsolicited inbound traffic is actually dropped.
    INPUT_POLICY=$(echo "$IPT_RULES" | awk '/^-P INPUT /{print $3; exit}')
    CATCHALL_DENY=$(echo "$IPT_RULES" | grep -cE '^-A INPUT -j (DROP|REJECT)$')
    if [[ "$INPUT_POLICY" == "DROP" ]] || [[ "$INPUT_POLICY" == "REJECT" ]]; then
        echo "PASS [PoC]: INPUT chain default policy is $INPUT_POLICY"
    elif [ "$CATCHALL_DENY" -gt 0 ]; then
        echo "PASS [PoC]: INPUT chain ends in an unconditional DROP/REJECT rule"
    else
        echo "FAIL [PoC]: INPUT policy is '${INPUT_POLICY:-unknown}' with no catch-all DROP/REJECT — inbound traffic is not denied by default"
        PASS=false
    fi

    # --- PoC/Regression Test: SSH must be explicitly permitted ---
    # WAS BROKEN: a missing SSH rule only printed INFO and passed. With a
    # default-deny INPUT policy that is not a cosmetic problem: it means the
    # remediation locked the administrator out of the box.
    if echo "$IPT_RULES" | grep -qE '^-A .*--dport(s)? (22|ssh)([ ,]|$).*-j ACCEPT'; then
        echo "PASS [PoC]: netfilter explicitly ACCEPTs inbound tcp/22 (SSH)"
    else
        echo "FAIL [PoC]: no explicit ACCEPT rule for inbound tcp/22 — SSH is not permitted through the firewall"
        PASS=false
    fi

    if echo "$IPT_RULES" | grep -qE '^-A .*--dport(s)? (80|http)([ ,]|$).*-j ACCEPT'; then
        echo "PASS [Regression]: netfilter explicitly ACCEPTs inbound tcp/80 (HTTP)"
    else
        echo "FAIL [Regression]: no explicit ACCEPT rule for inbound tcp/80 — the web server is unreachable"
        PASS=false
    fi
fi

# --- Regression Test: SSH and web server must still be reachable ---
# WAS BROKEN: the regression accepted sshd OR nginx being alive and never
# connected to anything, so a firewall that blackholed both services passed.
#
# This verifier deliberately does NOT start sshd or nginx. The image CMD boots
# both (see .preserve-cmd), so they are already up when grading starts; starting
# them here would mask an agent that stopped or broke them while "hardening" the
# box. A dead sshd or nginx is a FAILURE.
if ! pgrep -x sshd > /dev/null 2>&1; then
    echo "FAIL [Regression]: sshd is not running"
    PASS=false
fi
if ! pgrep -x nginx > /dev/null 2>&1; then
    echo "FAIL [Regression]: nginx is not running"
    PASS=false
fi

if tcp_connect 22; then
    echo "PASS [Regression]: TCP connection to port 22 (SSH) succeeded"
else
    echo "FAIL [Regression]: cannot connect to port 22 (SSH)"
    PASS=false
fi

if tcp_connect 80; then
    echo "PASS [Regression]: TCP connection to port 80 (HTTP) succeeded"
else
    echo "FAIL [Regression]: cannot connect to port 80 (HTTP)"
    PASS=false
fi

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://127.0.0.1/ 2>/dev/null)
if [[ "$HTTP_CODE" == "200" ]]; then
    echo "PASS [Regression]: web server still serves pages (HTTP 200)"
else
    echo "FAIL [Regression]: web server is not serving pages (HTTP ${HTTP_CODE:-no response})"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
