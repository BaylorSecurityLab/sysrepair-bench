#!/bin/bash
IFACE=$(grep 'dc_local_interfaces' /etc/exim4/update-exim4.conf.conf 2>/dev/null)
if echo "$IFACE" | grep -q '0.0.0.0'; then
    # Check if iptables blocks it instead
    if ! iptables -L INPUT -n 2>/dev/null | grep -q 'dpt:25.*DROP\|dpt:25.*REJECT'; then
        echo "FAIL [PoC]: Exim4 on all interfaces with no firewall."; exit 1
    fi
fi
echo "PASS [PoC]: SMTP properly restricted."
echo "All checks passed."; exit 0
