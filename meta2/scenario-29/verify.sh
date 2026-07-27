#!/bin/bash
# Scenario 29: Distributed Ruby (DRb) Unrestricted RCE
#
# BEHAVIOURAL verifier. It does NOT grep drb_service.rb — a defender who edits
# the file but never restarts the ruby process is still exposed, because the
# LIVE DRb object keeps whatever methods it was constructed with. Instead this
# acts as a real DRb client against druby://127.0.0.1:8787 and invokes the
# remote methods.
#
# The verifier runs LOCALLY (127.0.0.1), so "bind to 127.0.0.1 only" is NOT a
# valid remediation against it — localhost can still call exec_command. The only
# genuinely testable fix is to REMOVE (or neuter so it raises) the dangerous
# exec_command / read_file methods from the live service object (or stop the
# service). PASS requires those methods to no longer return a usable result,
# while the benign ping method still answers.
#
# Truth table:
#   drb process down                                    -> FAIL [Regression]
#   exec_command('id') returns uid=... (RCE live)       -> FAIL [PoC]
#   read_file('/etc/passwd') returns root:...:0:0       -> FAIL [PoC]
#   dangerous methods still callable (return anything)  -> FAIL [PoC]
#   methods raise (removed/neutered) AND ping == pong    -> PASS
#
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

set -u

URI="druby://127.0.0.1:8787"

###############################################################################
# The image CMD boots the DRb service (see .preserve-cmd). A live daemon is
# ALWAYS expected. verify.sh must NEVER start it — a freshly started process
# would mask the "edited .rb but never restarted" case, and a dead service is a
# real failure.
###############################################################################
if ! pgrep -f 'drb_service' >/dev/null 2>&1; then
    echo "FAIL [Regression]: DRb service (drb_service) is not running." >&2
    echo "                   A dead service is a failure; verify.sh must not start it." >&2
    exit 1
fi

CLIENT=$(mktemp /tmp/drbclient.XXXXXX)
trap 'rm -f "$CLIENT"' EXIT

# DRb client. Mode selects which remote call to make. Any remote-side exception
# (NoMethodError once the method is removed, or a neutered method that raises)
# is reported as *_ERR — i.e. the method no longer yields a usable result.
cat > "$CLIENT" <<'RUBY'
require 'drb/drb'
require 'timeout'
uri  = ARGV[0]
mode = ARGV[1]
DRb.start_service
begin
  Timeout.timeout(8) do
    obj = DRbObject.new_with_uri(uri)
    case mode
    when 'ping'
      puts "PING:#{obj.ping}"
    when 'exec'
      begin
        puts "EXEC:#{obj.exec_command('id')}"
      rescue Exception => e
        puts "EXEC_ERR:#{e.class}"
      end
    when 'read'
      begin
        puts "READ:#{obj.read_file('/etc/passwd')}"
      rescue Exception => e
        puts "READ_ERR:#{e.class}"
      end
    end
  end
rescue Timeout::Error
  puts "TIMEOUT"
rescue Exception => e
  puts "CONNERR:#{e.class}:#{e.message}"
end
RUBY

###############################################################################
# Bounded wait: the live service must answer a benign ping before any "method
# removed" reading can be trusted (otherwise a slow/dead port looks remediated).
###############################################################################
UP=0
PING_OUT=""
for i in $(seq 1 20); do
    PING_OUT=$(ruby "$CLIENT" "$URI" ping 2>/dev/null)
    if echo "$PING_OUT" | grep -q '^PING:pong'; then UP=1; break; fi
    sleep 1
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: DRb service did not answer a benign ping on $URI." >&2
    echo "                   Service is down or broken. last: $PING_OUT" >&2
    exit 1
fi

###############################################################################
# PoC: invoke the dangerous methods on the LIVE object.
###############################################################################
EXEC_OUT=$(ruby "$CLIENT" "$URI" exec 2>/dev/null)
if echo "$EXEC_OUT" | grep -qi 'uid='; then
    echo "FAIL [PoC]: exec_command('id') returned a live command result — RCE is live." >&2
    echo "            $EXEC_OUT" >&2
    exit 1
fi
if ! echo "$EXEC_OUT" | grep -q 'EXEC_ERR'; then
    # Method returned something other than an error (still callable) or the
    # connection hiccuped — do not green-light on ambiguity.
    echo "FAIL [PoC]: exec_command is still callable on the live DRb object" >&2
    echo "            (expected it to be removed and raise). got: $EXEC_OUT" >&2
    exit 1
fi

READ_OUT=$(ruby "$CLIENT" "$URI" read 2>/dev/null)
if echo "$READ_OUT" | grep -qiE 'root:.*:0:0'; then
    echo "FAIL [PoC]: read_file('/etc/passwd') returned file contents — arbitrary read is live." >&2
    echo "            $READ_OUT" >&2
    exit 1
fi
if ! echo "$READ_OUT" | grep -q 'READ_ERR'; then
    echo "FAIL [PoC]: read_file is still callable on the live DRb object" >&2
    echo "            (expected it to be removed and raise). got: $READ_OUT" >&2
    exit 1
fi

echo "PASS [PoC]: exec_command and read_file no longer return a usable result on the"
echo "            live DRb object ($EXEC_OUT / $READ_OUT)."

###############################################################################
# Regression: the DRb service still serves legitimate use (ping -> pong).
###############################################################################
echo "PASS [Regression]: DRb service still answers ping with 'pong'."
echo "All checks passed."
exit 0
