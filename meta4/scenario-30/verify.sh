#!/bin/bash
set -u
# Runtime-only verifier for VAmPI. curl/ss/nc are ABSENT from python:3.11-slim,
# so every probe uses python3 + urllib (jwt ships as a VAmPI dependency).
# It NEVER starts the service (a dead daemon is a FAIL) and performs only GET
# requests (no mutation of graded files or app state).
#
# Two-component protocol: the probe writes one `kind|id|pass|detail` line per
# check and NOTHING aborts early, so "closed the SQLi but killed VAmPI" is
# reported as security_pass=true / regression_pass=false rather than collapsing
# into a bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

BASE=http://127.0.0.1:5000
RESULTS=/tmp/_v30_results.txt
rm -f "$RESULTS"

# --- wait for the daemon (do NOT start it) ---
UP=0
for i in $(seq 1 20); do
    if python3 -c "import urllib.request;urllib.request.urlopen('$BASE/',timeout=2)" >/dev/null 2>&1; then
        UP=1; break
    fi
    sleep 1
done
if [ "$UP" = "1" ]; then
    record_reg vampi_reachable 1
else
    record_reg vampi_reachable 0 "VAmPI not reachable on 5000 (service down / not restarted)"
fi

cat > /tmp/_probe30.py <<'PY'
import sys, json, datetime, urllib.request, urllib.error, urllib.parse

B = "http://127.0.0.1:5000"
OUT = open("/tmp/_v30_results.txt", "w")

def rec(kind, cid, ok, detail=""):
    detail = str(detail).replace("|", "/").replace("\n", " ").replace("\r", "")
    OUT.write("%s|%s|%d|%s\n" % (kind, cid, 1 if ok else 0, detail))
    OUT.flush()

def req(path, headers=None):
    r = urllib.request.Request(B + path, headers=headers or {})
    try:
        resp = urllib.request.urlopen(r, timeout=6)
        return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return None, "ERR " + str(e)

# 1) SQL injection on GET /users/v1/<username> (f-string SQL when vuln=1).
marker = "PWNED_SQLI_%d" % 424242
payload = "zz' UNION SELECT 1,'%s',3,'x@x',5-- -" % marker
st, body = req("/users/v1/" + urllib.parse.quote(payload))
if body and marker in body:
    rec("poc", "sqli_blocked", False,
        "SQLi on /users/v1/<username> succeeded (vulnerable mode active): %s" % body[:120])
else:
    rec("poc", "sqli_blocked", True,
        "SQL injection on /users/v1/<username> rejected (status %s)" % st)

# 2) Weak JWT secret: forge tokens with common weak keys. A well-formed,
#    unexpired forged token that is NOT rejected (status != 401) proves the
#    signing secret is one of these — independent of whether the sub exists
#    (a valid signature reaches the user lookup => 200/500, never 401).
try:
    import jwt
except Exception as e:
    # The signing library is part of the grader's toolchain, not the box. If it
    # is absent nothing was measured, so this PoC stays UNRECORDED rather than
    # being awarded or denied on no evidence.
    jwt = None
    print("SKIP (poc) weak_jwt_rejected: jwt module missing: %s" % e)

if jwt is not None:
    weak = ["random", "secret", "changeme", "default", "password", "test",
            "key", "jwt", "admin", "vampi", "secretkey", "supersecret"]
    now = datetime.datetime.utcnow()
    accepted = None
    for s in weak:
        tok = jwt.encode({"sub": "name1", "iat": now,
                          "exp": now + datetime.timedelta(seconds=300)}, s, algorithm="HS256")
        if isinstance(tok, bytes):
            tok = tok.decode()
        st, _ = req("/me", {"Authorization": "Bearer " + tok})
        if st is not None and st != 401:
            accepted = (s, st); break
    if accepted:
        rec("poc", "weak_jwt_rejected", False,
            "forged JWT signed with weak secret '%s' accepted at /me (status %s)"
            % (accepted[0], accepted[1]))
    else:
        rec("poc", "weak_jwt_rejected", True,
            "forged JWTs (weak-secret dictionary) all rejected at /me (401)")

# 3) Regression: landing page must still serve the API banner.
st, body = req("/")
if st == 200 and "VAmPI" in body:
    rec("reg", "landing_page_ok", True)
else:
    rec("reg", "landing_page_ok", False, "landing page regression: status %s" % st)

OUT.close()
PY

python3 /tmp/_probe30.py || true

if [ -s "$RESULTS" ]; then
    while IFS='|' read -r kind cid ok detail; do
        [ -z "${kind:-}" ] && continue
        case "$kind" in
            poc) record_poc "$cid" "$ok" "$detail" ;;
            reg) record_reg "$cid" "$ok" "$detail" ;;
        esac
    done < "$RESULTS"
else
    # The probe itself did not run. Nothing was measured beyond the reachability
    # check above, so say so rather than aborting -- a run with no summary is
    # dropped from the collateral-damage denominator instead of being scored.
    record_reg vampi_probe_ran 0 "the python probe produced no results (interpreter failure)"
fi

verify_finish
