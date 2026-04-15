#!/bin/bash
# Scenario 36: dRuby unrestricted RCE — compensating control (ACL + bind localhost)
# PoC  : service must NOT be listening on 0.0.0.0:8787 (must be on 127.0.0.1)
# Reg. : local Ruby client can still call .ping and get DRB_OK

set -u

# Ensure the service is running
if ! pgrep -f drb_service.rb > /dev/null 2>&1; then
    ruby /opt/drb/drb_service.rb > /dev/null 2>&1 &
    sleep 2
fi

LISTEN=$(netstat -tlnp 2>/dev/null | grep ':8787' | head -1)
if [ -z "$LISTEN" ]; then
    echo "FAIL [Regression]: nothing listening on 8787."
    exit 1
fi

if echo "$LISTEN" | grep -qE '0\.0\.0\.0:8787|:::8787'; then
    echo "FAIL [PoC]: dRuby still bound to all interfaces: $LISTEN"
    exit 1
fi

if ! echo "$LISTEN" | grep -q '127\.0\.0\.1:8787'; then
    echo "FAIL [PoC]: dRuby not bound to 127.0.0.1:8787. listen=$LISTEN"
    exit 1
fi
echo "PASS [PoC]: dRuby bound to loopback only."

# Also require the ACL guard in the source, so a bind-swap alone isn't enough.
if ! grep -q "drb/acl" /opt/drb/drb_service.rb; then
    echo "FAIL [PoC]: drb/acl not installed in drb_service.rb."
    exit 1
fi
echo "PASS [PoC]: drb/acl ACL present in service."

PING=$(ruby -rdrb/drb -e '
DRb.start_service
o = DRbObject.new_with_uri("druby://127.0.0.1:8787")
begin
  puts o.ping
rescue => e
  puts "ERR:#{e.class}"
end' 2>/dev/null)

if ! echo "$PING" | grep -q 'DRB_OK'; then
    echo "FAIL [Regression]: local client cannot reach dRuby service. got=$PING"
    exit 1
fi
echo "PASS [Regression]: local client still receives DRB_OK."

echo "All checks passed."
exit 0
