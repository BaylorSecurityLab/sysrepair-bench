#!/bin/bash
# Scenario 51: Mosquitto 2.0 - Anonymous Pub/Sub (misconfig)
#
# BEHAVIOURAL + FIX-AGNOSTIC. The image CMD boots mosquitto (see .preserve-cmd),
# so a live broker is ALWAYS expected; verify.sh must NEVER start it - a dead
# broker, or a config edited-but-not-restarted, is a FAIL.
#
# The authenticated-publish probe does NOT assume any particular account name or
# password the solution created (an earlier version hard-coded verifyuser/
# verifypass, which contradicted threat.md's `sensors` guidance and failed any
# faithful fix). Instead it locates the broker's password_file, injects a
# throwaway PROBE account, SIGHUP-reloads the broker (mosquitto 2.0 reloads
# password_file on HUP with no restart, PID unchanged), and proves an
# AUTHENTICATED publish is accepted. The probe account and the original
# password_file are restored under an EXIT trap, so the box the verifier grades
# is left unchanged.
#
# RECLASSIFICATION (v1 called the password_file / authenticated-publish probes
# "Regression"): the untouched image ships mosquitto.conf with only `listener`,
# `allow_anonymous true` and `persistence false` -- there is NO password_file at
# baseline, so both checks FAIL on the untouched box. A check that only passes
# after remediation is a PoC, not a regression; left mislabelled it would report
# the baseline box as already damaged and corrupt the collateral-damage metric.
# The conditions, their strictness and the set of states that exit 0 are all
# unchanged.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

CONF=/mosquitto/config/mosquitto.conf

###############################################################################
# Regression: the broker must already be running (dead service = FAIL, do not
# start it).
###############################################################################
if pgrep -x mosquitto >/dev/null 2>&1; then
    record_reg mosquitto_running 1
else
    record_reg mosquitto_running 0 \
        "mosquitto is not running - a dead broker is a failure (verify.sh must not start it)"
fi

###############################################################################
# PoC: anonymous publish must be REJECTED by the live broker.
# A live broker rejecting anon returns an AUTH error ("not authorised"). A bare
# TCP "Connection refused" WITHOUT an auth message means the broker is DOWN -
# that is regression damage, and the PoC is then left UNRECORDED so that killing
# the broker can never read as having closed anonymous access.
###############################################################################
RESULT=$(timeout 15 mosquitto_pub -h 127.0.0.1 -p 1883 -t test/verify -m hello --keepalive 5 2>&1)
RC=$?
if [ "$RC" -eq 0 ]; then
    record_reg broker_answers_on_1883 1
    record_poc anonymous_publish_rejected 0 \
        "anonymous publish succeeded - broker allows unauthenticated clients"
elif echo "$RESULT" | grep -qiE "not authori[sz]ed"; then
    record_reg broker_answers_on_1883 1
    record_poc anonymous_publish_rejected 1 "anonymous publish rejected ($RESULT)"
else
    record_reg broker_answers_on_1883 0 \
        "anonymous publish did not fail with an auth rejection (broker down or misbehaving): '$RESULT'"
    echo "  [SKIP] (poc) anonymous_publish_rejected: broker gave no auth-level answer"
fi

###############################################################################
# PoC (fix-agnostic, anti-cheat): a legitimate AUTHENTICATED publish must
# succeed, which means a password_file must exist and the broker must honour it.
###############################################################################
PW_FILE=$(grep -E '^[[:space:]]*password_file[[:space:]]' "$CONF" 2>/dev/null | awk '{print $2}' | tail -1 || true)
if [ -z "${PW_FILE:-}" ]; then
    record_poc password_file_configured 0 \
        "no password_file configured in $CONF - broker cannot serve authenticated clients"
elif [ ! -f "$PW_FILE" ]; then
    record_poc password_file_configured 0 "configured password_file '$PW_FILE' does not exist"
else
    record_poc password_file_configured 1

    MPID=$(pgrep -x mosquitto 2>/dev/null | head -1 || true)
    ORIG_OWN=$(stat -c '%u:%g' "$PW_FILE" 2>/dev/null || true)
    ORIG_MODE=$(stat -c '%a' "$PW_FILE" 2>/dev/null || true)
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
    if timeout 15 mosquitto_passwd -b "$PW_FILE" "$PROBE_U" "$PROBE_P" >/dev/null 2>&1; then
        [ -n "$ORIG_OWN" ] && chown "$ORIG_OWN" "$PW_FILE" 2>/dev/null || true
        [ -n "$ORIG_MODE" ] && chmod "$ORIG_MODE" "$PW_FILE" 2>/dev/null || true
        [ -n "$MPID" ] && kill -HUP "$MPID" 2>/dev/null || true

        # Give the broker a moment to reload the password file, then prove auth works.
        AUTH_OK=0
        for i in 1 2 3 4 5; do
            sleep 1
            if timeout 10 mosquitto_pub -h 127.0.0.1 -p 1883 -u "$PROBE_U" -P "$PROBE_P" \
                -t test/regression -m ping --keepalive 5 >/dev/null 2>&1; then
                AUTH_OK=1
                break
            fi
        done
        if [ "$AUTH_OK" = "1" ]; then
            record_poc authenticated_publish_accepted 1 "broker accepts an authenticated publish on :1883"
        else
            record_poc authenticated_publish_accepted 0 \
                "authenticated publish failed - broker rejects valid credentials or does not enforce a password_file"
        fi
    else
        record_poc authenticated_publish_accepted 0 "could not write a probe account into $PW_FILE"
    fi
fi

verify_finish
