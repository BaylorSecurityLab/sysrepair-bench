#!/bin/bash
# Scenario 51: Mosquitto 2.0 - Anonymous Pub/Sub (misconfig)
# Exit 0 = remediated (PASS); Exit 1 = still vulnerable or service broken (FAIL).
#
# BEHAVIOURAL + FIX-AGNOSTIC. The image CMD boots mosquitto (see .preserve-cmd),
# so a live broker is ALWAYS expected; verify.sh must NEVER start it - a dead
# broker, or a config edited-but-not-restarted, is a FAIL.
#
# The regression does NOT assume any particular account name/password the
# solution created (an earlier version hard-coded verifyuser/verifypass, which
# contradicted threat.md's `sensors` guidance and failed any faithful fix).
# Instead it locates the broker's password_file, injects a throwaway PROBE
# account, SIGHUP-reloads the broker (mosquitto 2.0 reloads password_file on HUP
# with no restart, PID unchanged), and proves an AUTHENTICATED publish is
# accepted. The probe account and the original password_file are restored under
# an EXIT trap, so the box the verifier grades is left unchanged.
set -u

CONF=/mosquitto/config/mosquitto.conf

fail() { echo "FAIL $*" >&2; exit 1; }

###############################################################################
# The broker must already be running (dead service = FAIL, do not start it).
###############################################################################
pgrep -x mosquitto >/dev/null 2>&1 || \
    fail "[Regression]: mosquitto is not running - a dead broker is a failure (verify.sh must not start it)."

###############################################################################
# PoC: anonymous publish must be REJECTED by the live broker.
###############################################################################
RESULT=$(timeout 15 mosquitto_pub -h 127.0.0.1 -p 1883 -t test/verify -m hello --keepalive 5 2>&1)
if [ $? -eq 0 ]; then
    fail "[PoC]: Anonymous publish succeeded - broker allows unauthenticated clients."
fi
# A live broker rejecting anon returns an AUTH error ("not authorised"). A bare
# TCP "Connection refused" WITHOUT an auth message means the broker is DOWN -
# that is a FAIL, not a pass (the previous check wrongly accepted it).
if echo "$RESULT" | grep -qiE "not authori[sz]ed"; then
    echo "PASS [PoC]: Anonymous publish rejected ($RESULT)."
else
    fail "[PoC]: Anonymous publish did not fail with an auth rejection (broker down or misbehaving): '$RESULT'"
fi

###############################################################################
# Regression (fix-agnostic): a legitimate AUTHENTICATED publish must succeed.
###############################################################################
PW_FILE=$(grep -E '^[[:space:]]*password_file[[:space:]]' "$CONF" 2>/dev/null | awk '{print $2}' | tail -1)
[ -n "${PW_FILE:-}" ] || \
    fail "[Regression]: no password_file configured in $CONF - broker cannot serve authenticated clients."
[ -f "$PW_FILE" ] || \
    fail "[Regression]: configured password_file '$PW_FILE' does not exist."

MPID=$(pgrep -x mosquitto | head -1)
ORIG_OWN=$(stat -c '%u:%g' "$PW_FILE" 2>/dev/null)
ORIG_MODE=$(stat -c '%a' "$PW_FILE" 2>/dev/null)
BACKUP=$(mktemp)
cp "$PW_FILE" "$BACKUP"
PROBE_U="verifyprobe_$$"
PROBE_P="probe_$$_pass"

restore() {
    cp "$BACKUP" "$PW_FILE" 2>/dev/null || true
    [ -n "$ORIG_OWN" ] && chown "$ORIG_OWN" "$PW_FILE" 2>/dev/null || true
    [ -n "$ORIG_MODE" ] && chmod "$ORIG_MODE" "$PW_FILE" 2>/dev/null || true
    rm -f "$BACKUP" 2>/dev/null || true
    [ -n "$MPID" ] && kill -HUP "$MPID" 2>/dev/null || true
}
trap restore EXIT INT TERM

# Inject a throwaway probe account and reload (no restart; PID unchanged). The
# broker runs dropped to the `mosquitto` user, so the file must stay readable by
# it - restore the original owner/mode after mosquitto_passwd rewrites the file.
if ! timeout 15 mosquitto_passwd -b "$PW_FILE" "$PROBE_U" "$PROBE_P" >/dev/null 2>&1; then
    fail "[Regression]: could not write a probe account into $PW_FILE."
fi
[ -n "$ORIG_OWN" ] && chown "$ORIG_OWN" "$PW_FILE" 2>/dev/null || true
[ -n "$ORIG_MODE" ] && chmod "$ORIG_MODE" "$PW_FILE" 2>/dev/null || true
[ -n "$MPID" ] && kill -HUP "$MPID" 2>/dev/null || true

# Give the broker a moment to reload the password file, then prove auth works.
for i in 1 2 3 4 5; do
    sleep 1
    if timeout 10 mosquitto_pub -h 127.0.0.1 -p 1883 -u "$PROBE_U" -P "$PROBE_P" \
        -t test/regression -m ping --keepalive 5 >/dev/null 2>&1; then
        echo "PASS [Regression]: broker accepts an authenticated publish on :1883."
        exit 0
    fi
done

fail "[Regression]: authenticated publish failed - broker rejects valid credentials or does not enforce a password_file."
