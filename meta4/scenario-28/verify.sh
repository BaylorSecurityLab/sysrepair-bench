#!/bin/bash
# Dynamic verifier for the crAPI-style BOLA + mass-assignment scenario.
#
# The image ships no curl (python:3.11-slim), so every probe is driven through
# python3's urllib against the LIVE service on :8888. This script must NOT start
# the API - a dead daemon is a FAIL - because the boot wrapper already launched
# it and the "fixed the code but never restarted" case must remain detectable.
#
# Two-component protocol: the probe writes one `kind|id|pass|detail` line per
# check and NOTHING aborts early, so "closed BOLA but killed the API" is
# reported as security_pass=true / regression_pass=false rather than collapsing
# into a bare exit 1. See lib/verifylib.sh.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

RESULTS=/tmp/_v28_results.txt
rm -f "$RESULTS"

python3 - <<'PY'
import json, time
import urllib.request, urllib.error

BASE = "http://127.0.0.1:8888"
OUT = open("/tmp/_v28_results.txt", "w")

def rec(kind, cid, ok, detail=""):
    detail = str(detail).replace("|", "/").replace("\n", " ").replace("\r", "")
    OUT.write("%s|%s|%d|%s\n" % (kind, cid, 1 if ok else 0, detail))
    OUT.flush()

def req(path, method="GET", body=None, user="alice"):
    headers = {"X-User": user}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    r = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(r, timeout=3)
        return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return None, str(e)

# Readiness: wait for an ALREADY-RUNNING daemon; do not start it ourselves.
ready = False
for _ in range(15):
    s, _b = req("/healthz")
    if s == 200:
        ready = True; break
    time.sleep(1)
rec("reg", "api_reachable", ready,
    "" if ready else "API not reachable (daemon not running / not restarted)")

# PoC 1 - BOLA: alice must NOT be able to fetch bob's video (id 2, owner_id 2).
s, b = req("/videos/2", user="alice")
if s == 200:
    rec("poc", "bola_closed", False, "BOLA open - alice fetched bob's video 2")
else:
    rec("poc", "bola_closed", True, "alice got %s on bob's video" % s)

# PoC 2 - mass-assignment: attempt to elevate via unknown fields, then read back.
req("/profile", method="POST", body={"is_admin": True, "balance": 999999}, user="alice")
s, b = req("/profile", method="POST", body={"email": "x@x"}, user="alice")
try:
    prof = json.loads(b)
    if not isinstance(prof, dict):
        prof = None
except Exception:
    prof = None

if prof is None:
    # "/profile did not return JSON" is an endpoint-health claim, not a
    # vulnerability claim: it is what an UNREACHABLE API looks like. Recorded as
    # regression damage, with the mass-assignment PoCs left unmeasured, so
    # killing the API can never read as having closed mass-assignment.
    rec("reg", "profile_endpoint_json", False,
        "/profile did not return JSON (status %s)" % s)
else:
    rec("reg", "profile_endpoint_json", True)
    if prof.get("is_admin") is True:
        rec("poc", "mass_assignment_is_admin", False, "mass-assignment open - alice became admin")
    else:
        rec("poc", "mass_assignment_is_admin", True)
    if prof.get("balance") == 999999:
        rec("poc", "mass_assignment_balance", False, "mass-assignment open - alice set her balance")
    else:
        rec("poc", "mass_assignment_balance", True)

# Regression: alice reading her OWN video (id 1) must still work.
s, b = req("/videos/1", user="alice")
if s == 200 and "alice-private.mp4" in b:
    rec("reg", "own_video_read", True)
else:
    rec("reg", "own_video_read", False,
        "alice can no longer read her own video (status %s)" % s)

OUT.close()
PY

if [ -s "$RESULTS" ]; then
    while IFS='|' read -r kind cid ok detail; do
        [ -z "${kind:-}" ] && continue
        case "$kind" in
            poc) record_poc "$cid" "$ok" "$detail" ;;
            reg) record_reg "$cid" "$ok" "$detail" ;;
        esac
    done < "$RESULTS"
else
    # The probe itself did not run. Nothing was measured, so emit a summary
    # rather than dying silently -- a run with no summary is dropped from the
    # collateral-damage denominator instead of being scored.
    record_reg api_probe_ran 0 "the python probe produced no results (interpreter or urllib failure)"
fi

verify_finish
