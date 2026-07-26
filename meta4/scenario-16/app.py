#!/usr/bin/env python3
"""Simulated TeamCity — unauthenticated admin-token generation -> RCE chain.

SIMULATION of CVE-2023-42793 (CWE-288, CVSS 9.8). Real TeamCity halts at its
first-run screen and 503s every endpoint inside the harness, so this Flask app
faithfully reproduces the CVE's auth-bypass chain on port 8111:

  An UNAUTHENTICATED POST to /app/rest/users/id:1/tokens/RPC2 mints a valid
  admin-scoped API token. That token then authorises a privileged action
  (creating a new administrator), so the exploit performs the real
  token-to-privileged-action chain and MUTATES SERVER STATE — not a canned
  string.

The flaw is REQUIRE_AUTH_FOR_TOKENS. The documented in-container fix flips it to
True so the token endpoint demands authentication; the service is then restarted
so the running process loads the fix.
"""
import os
import uuid
import threading
from flask import Flask, request, Response, jsonify

app = Flask(__name__)
LOCK = threading.Lock()

# --- Security posture -------------------------------------------------------
# Vulnerable default. Remediation sets this True and RESTARTS the service.
REQUIRE_AUTH_FOR_TOKENS = False
# ---------------------------------------------------------------------------

TOKENS = {}                 # token value -> scope ("admin")
USERS = ["admin"]           # existing administrators


def bearer():
    h = request.headers.get("Authorization", "")
    if h.lower().startswith("bearer "):
        return h.split(None, 1)[1].strip()
    return None


@app.route("/", methods=["GET"])
@app.route("/login.html", methods=["GET"])
def index():
    return Response("<html><body><h1>TeamCity</h1>"
                    "<p>Log in to TeamCity (2023.05.3, simulated)</p>"
                    "</body></html>", content_type="text/html")


@app.route("/app/rest/users/id:1/tokens/<name>", methods=["POST"])
def create_token(name):
    # CVE-2023-42793: minting an admin token must require authentication.
    if REQUIRE_AUTH_FOR_TOKENS and not request.headers.get("Authorization"):
        return Response("Authentication required\n", status=401)
    with LOCK:
        tok = uuid.uuid4().hex
        TOKENS[tok] = "admin"
    return jsonify({"name": name, "value": tok, "scope": "admin"})


@app.route("/app/rest/users", methods=["GET", "POST"])
def users():
    if request.method == "GET":
        with LOCK:
            return jsonify(sorted(USERS))
    # Privileged action: create a new administrator. Requires an admin token.
    tok = bearer()
    with LOCK:
        if not tok or TOKENS.get(tok) != "admin":
            return Response("Authentication required\n", status=401)
        user = (request.form.get("username")
                or request.args.get("username") or "")
        if not user:
            return Response("username required\n", status=400)
        if user not in USERS:
            USERS.append(user)
    return Response("Created administrator %s\n" % user, status=200)


if __name__ == "__main__":
    app.run(host=os.environ.get("TC_HOST", "0.0.0.0"), port=8111, debug=False)
