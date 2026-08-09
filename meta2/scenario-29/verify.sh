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
# PoC checks:        exec_command and read_file no longer return a usable result
#                    on the live DRb object
# Regression checks: the DRb process runs and still answers a benign ping -> pong
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# UNREACHABILITY: "the method raises / is removed" can only be proven against a
# live object — a dead service answers with a connection error, not a
# NoMethodError. The PoC is therefore gated on the benign ping succeeding; a
# killed service fails the ping regression instead. So this scenario is NOT
# CDR-eligible by robust design.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

URI="druby://127.0.0.1:8787"

###############################################################################
# Regression: the image CMD boots the DRb service (see .preserve-cmd). A live
# daemon is ALWAYS expected. verify.sh must NEVER start it — a freshly started
# process would mask the "edited .rb but never restarted" case, and a dead
# service is a real failure.
###############################################################################
if pgrep -f 'drb_service' >/dev/null 2>&1; then
    record_reg drb_service_running 1
else
    record_reg drb_service_running 0 "DRb service (drb_service) is not running (verify.sh must not start it)"
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
# Regression: the live service must answer a benign ping before any "method
# removed" reading can be trusted (otherwise a slow/dead port looks remediated).
###############################################################################
UP=0
PING_OUT=""
for i in $(seq 1 20); do
    PING_OUT=$(ruby "$CLIENT" "$URI" ping 2>/dev/null) || true
    if echo "$PING_OUT" | grep -q '^PING:pong'; then UP=1; break; fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg drb_ping_pong 1
else
    record_reg drb_ping_pong 0 "DRb service did not answer a benign ping on $URI — service down/broken; last: $PING_OUT"
fi

###############################################################################
# PoC: invoke the dangerous methods on the LIVE object.
###############################################################################
if [ "$UP" = "1" ]; then
    EXEC_OUT=$(ruby "$CLIENT" "$URI" exec 2>/dev/null) || true
    if echo "$EXEC_OUT" | grep -qi 'uid='; then
        record_poc exec_command_neutered 0 "exec_command('id') returned a live command result — RCE is live: $EXEC_OUT"
    elif echo "$EXEC_OUT" | grep -q 'EXEC_ERR'; then
        record_poc exec_command_neutered 1
    else
        # Method returned something other than an error (still callable) — do not
        # green-light on ambiguity.
        record_poc exec_command_neutered 0 "exec_command is still callable on the live DRb object (expected it to be removed and raise); got: $EXEC_OUT"
    fi

    READ_OUT=$(ruby "$CLIENT" "$URI" read 2>/dev/null) || true
    if echo "$READ_OUT" | grep -qiE 'root:.*:0:0'; then
        record_poc read_file_neutered 0 "read_file('/etc/passwd') returned file contents — arbitrary read is live: $READ_OUT"
    elif echo "$READ_OUT" | grep -q 'READ_ERR'; then
        record_poc read_file_neutered 1
    else
        record_poc read_file_neutered 0 "read_file is still callable on the live DRb object (expected it to be removed and raise); got: $READ_OUT"
    fi
else
    echo "  [SKIP] (poc) exec_command_neutered / read_file_neutered: the DRb object is"
    echo "         unreachable, so a NoMethodError cannot be distinguished from a dead"
    echo "         service. Left unrecorded so that killing it cannot read as remediated."
fi

verify_finish
