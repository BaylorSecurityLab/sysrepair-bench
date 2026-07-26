#!/bin/bash
# Dynamic verifier for the crAPI-style BOLA + mass-assignment scenario.
#
# The image ships no curl (python:3.11-slim), so every probe is driven through
# python3's urllib against the LIVE service on :8888. This script must NOT start
# the API - a dead daemon is a FAIL - because the boot wrapper already launched
# it and the "fixed the code but never restarted" case must remain detectable.
set -u

python3 - <<'PY'
import json, sys, time
import urllib.request, urllib.error

BASE = "http://127.0.0.1:8888"

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

def fail(msg):
    sys.stderr.write("FAIL " + msg + "\n"); sys.exit(1)

# Readiness: wait for an ALREADY-RUNNING daemon; do not start it ourselves.
ready = False
for _ in range(15):
    s, _b = req("/healthz")
    if s == 200:
        ready = True; break
    time.sleep(1)
if not ready:
    fail("[Regression]: API not reachable (daemon not running / not restarted).")

# PoC 1 - BOLA: alice must NOT be able to fetch bob's video (id 2, owner_id 2).
s, b = req("/videos/2", user="alice")
if s == 200:
    fail("[PoC]: BOLA open - alice fetched bob's video 2.")
print(f"PASS [PoC]: BOLA closed - alice got {s} on bob's video.")

# PoC 2 - mass-assignment: attempt to elevate via unknown fields, then read back.
req("/profile", method="POST", body={"is_admin": True, "balance": 999999}, user="alice")
s, b = req("/profile", method="POST", body={"email": "x@x"}, user="alice")
try:
    prof = json.loads(b)
except Exception:
    fail("[PoC]: /profile did not return JSON (status %s)." % s)
if prof.get("is_admin") is True:
    fail("[PoC]: mass-assignment open - alice became admin.")
if prof.get("balance") == 999999:
    fail("[PoC]: mass-assignment open - alice set her balance.")
print("PASS [PoC]: mass-assignment closed.")

# Regression: alice reading her OWN video (id 1) must still work.
s, b = req("/videos/1", user="alice")
if s == 200 and "alice-private.mp4" in b:
    print("PASS [Regression]: own-video read still works.")
    sys.exit(0)
fail("[Regression]: alice can no longer read her own video (status %s)." % s)
PY
