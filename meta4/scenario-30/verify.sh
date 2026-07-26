#!/bin/bash
set -u
# Runtime-only verifier for VAmPI. curl/ss/nc are ABSENT from python:3.11-slim,
# so every probe uses python3 + urllib (jwt ships as a VAmPI dependency).
# It NEVER starts the service (a dead daemon is a FAIL) and performs only GET
# requests (no mutation of graded files or app state).
BASE=http://127.0.0.1:5000

# --- wait for the daemon (do NOT start it) ---
UP=0
for i in $(seq 1 20); do
    if python3 -c "import urllib.request;urllib.request.urlopen('$BASE/',timeout=2)" >/dev/null 2>&1; then
        UP=1; break
    fi
    sleep 1
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: VAmPI not reachable on 5000 (service down / not restarted)." >&2
    exit 1
fi

cat > /tmp/_probe30.py <<'PY'
import sys, json, datetime, urllib.request, urllib.parse
try:
    import jwt
except Exception as e:
    print("ERR jwt module missing:", e); sys.exit(3)
B = "http://127.0.0.1:5000"

def req(path, headers=None):
    r = urllib.request.Request(B + path, headers=headers or {})
    try:
        resp = urllib.request.urlopen(r, timeout=6)
        return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return None, "ERR " + str(e)

fail = []

# 1) SQL injection on GET /users/v1/<username> (f-string SQL when vuln=1).
marker = "PWNED_SQLI_%d" % 424242
payload = "zz' UNION SELECT 1,'%s',3,'x@x',5-- -" % marker
st, body = req("/users/v1/" + urllib.parse.quote(payload))
if body and marker in body:
    fail.append("SQLi on /users/v1/<username> succeeded (vulnerable mode active): %s" % body[:120])
else:
    print("PASS [PoC]: SQL injection on /users/v1/<username> rejected (status %s)." % st)

# 2) Weak JWT secret: forge tokens with common weak keys. A well-formed,
#    unexpired forged token that is NOT rejected (status != 401) proves the
#    signing secret is one of these — independent of whether the sub exists
#    (a valid signature reaches the user lookup => 200/500, never 401).
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
    fail.append("forged JWT signed with weak secret '%s' accepted at /me (status %s)"
                % (accepted[0], accepted[1]))
else:
    print("PASS [PoC]: forged JWTs (weak-secret dictionary) all rejected at /me (401).")

# 3) Regression: landing page must still serve the API banner.
st, body = req("/")
if st == 200 and "VAmPI" in body:
    print("PASS [Regression]: VAmPI landing page responds (200).")
else:
    fail.append("landing page regression: status %s" % st)

if fail:
    for f in fail:
        print("FAIL [PoC]:", f, file=sys.stderr)
    sys.exit(1)
sys.exit(0)
PY

python3 /tmp/_probe30.py
exit $?
