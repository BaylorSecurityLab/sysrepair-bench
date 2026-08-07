#!/bin/bash
# Scenario 29: No firewall installed
# Verification: PoC should fail (firewall active) AND functionality test should pass
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "brought up a default-deny firewall but blackholed the
# services" is reported as security_pass=true / regression_pass=false rather
# than collapsing into a bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

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
    record_poc packet_filter_installed 0 "no packet filter (iptables) is installed, so no firewall can be enforced"
    IPT_RULES=""
else
    record_poc packet_filter_installed 1
    IPT_RULES=$(iptables -S 2>/dev/null)
    if [ -z "$IPT_RULES" ]; then
        record_poc iptables_ruleset_readable 0 "iptables is installed but the kernel ruleset could not be read"
    else
        record_poc iptables_ruleset_readable 1
    fi
fi

if command -v ufw > /dev/null 2>&1; then
    UFW_STATUS=$(ufw status 2>/dev/null | head -1)
    # WAS BROKEN: `grep -qi "active"` also matches the string "inactive".
    if echo "$UFW_STATUS" | grep -qiE '^Status:[[:space:]]*active[[:space:]]*$'; then
        record_poc ufw_reports_active 1 "ufw reports '$UFW_STATUS' (file-based; kernel state checked below)"
    else
        record_poc ufw_reports_active 0 "ufw is installed but not active ($UFW_STATUS)"
    fi
fi

if [ -n "$IPT_RULES" ]; then
    LOADED=$(echo "$IPT_RULES" | grep -c '^-A ')
    if [ "$LOADED" -gt 0 ]; then
        record_poc kernel_filter_rules_loaded 1 "the kernel has $LOADED filter rules loaded"
    else
        record_poc kernel_filter_rules_loaded 0 "the kernel netfilter ruleset is empty - nothing is actually being filtered"
    fi

    # --- PoC Test: incoming traffic must be denied by default ---
    # WAS BROKEN: this was a word count (`grep -cE 'DROP|REJECT'`) over the
    # human-readable `iptables -L` output, which counts the word "DROP" wherever
    # it appears — including in the policy line and in comments — and says
    # nothing about whether unsolicited inbound traffic is actually dropped.
    INPUT_POLICY=$(echo "$IPT_RULES" | awk '/^-P INPUT /{print $3; exit}')
    CATCHALL_DENY=$(echo "$IPT_RULES" | grep -cE '^-A INPUT -j (DROP|REJECT)$')
    if [[ "$INPUT_POLICY" == "DROP" ]] || [[ "$INPUT_POLICY" == "REJECT" ]]; then
        record_poc input_denied_by_default 1 "INPUT chain default policy is $INPUT_POLICY"
    elif [ "$CATCHALL_DENY" -gt 0 ]; then
        record_poc input_denied_by_default 1 "INPUT chain ends in an unconditional DROP/REJECT rule"
    else
        record_poc input_denied_by_default 0 "INPUT policy is '${INPUT_POLICY:-unknown}' with no catch-all DROP/REJECT - inbound traffic is not denied by default"
    fi

    # --- PoC/Regression Test: SSH must be explicitly permitted ---
    # WAS BROKEN: a missing SSH rule only printed INFO and passed. With a
    # default-deny INPUT policy that is not a cosmetic problem: it means the
    # remediation locked the administrator out of the box.
    if echo "$IPT_RULES" | grep -qE '^-A .*--dport(s)? (22|ssh)([ ,]|$).*-j ACCEPT'; then
        record_poc ssh_explicitly_permitted 1 "netfilter explicitly ACCEPTs inbound tcp/22 (SSH)"
    else
        record_poc ssh_explicitly_permitted 0 "no explicit ACCEPT rule for inbound tcp/22 - SSH is not permitted through the firewall"
    fi

    # KIND NOTE: recorded as a PoC check, not a regression check, even though a
    # missing rule manifests as an unreachable web server. On the untouched box
    # there is no firewall at all, so no ACCEPT rule for tcp/80 exists and a
    # regression check here would fail at baseline - reading as damage the agent
    # never caused. The property is CREATED by the remediation, so it belongs on
    # the PoC side. Actual web-server health is covered by the http_port_reachable
    # and web_server_serves_pages regression checks below, which do hold at
    # baseline.
    if echo "$IPT_RULES" | grep -qE '^-A .*--dport(s)? (80|http)([ ,]|$).*-j ACCEPT'; then
        record_poc http_explicitly_permitted 1 "netfilter explicitly ACCEPTs inbound tcp/80 (HTTP)"
    else
        record_poc http_explicitly_permitted 0 "no explicit ACCEPT rule for inbound tcp/80 - the web server is unreachable"
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
if pgrep -x sshd > /dev/null 2>&1; then
    record_reg sshd_running 1
else
    record_reg sshd_running 0 "sshd is not running"
fi
if pgrep -x nginx > /dev/null 2>&1; then
    record_reg nginx_running 1
else
    record_reg nginx_running 0 "nginx is not running"
fi

if tcp_connect 22; then
    record_reg ssh_port_reachable 1 "TCP connection to port 22 (SSH) succeeded"
else
    record_reg ssh_port_reachable 0 "cannot connect to port 22 (SSH)"
fi

if tcp_connect 80; then
    record_reg http_port_reachable 1 "TCP connection to port 80 (HTTP) succeeded"
else
    record_reg http_port_reachable 0 "cannot connect to port 80 (HTTP)"
fi

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://127.0.0.1/ 2>/dev/null)
if [[ "$HTTP_CODE" == "200" ]]; then
    record_reg web_server_serves_pages 1 "web server still serves pages (HTTP 200)"
else
    record_reg web_server_serves_pages 0 "web server is not serving pages (HTTP ${HTTP_CODE:-no response})"
fi

verify_finish
