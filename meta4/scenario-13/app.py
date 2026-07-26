#!/usr/bin/env python3
"""Simulated Confluence — broken access control / unauth admin creation.

SIMULATION of CVE-2023-22515 (CWE-284, CVSS 10.0). Real Confluence Data Center
is too heavy to boot and reach its vuln inside the harness, so this Flask app
faithfully reproduces the CVE's privilege-escalation *behaviour* on port 8090:

  An UNAUTHENTICATED request to /setup/setupadministrator.action reopens the
  setup wizard on an already-configured instance and then creates a brand-new
  administrator account. The exploit MUTATES REAL SERVER STATE (the admin set)
  exactly as the CVE does — it is not a canned string.

The flaw is that the setup handler does not verify the instance is already
configured (no access control). The documented in-container fix flips
ENFORCE_SETUP_ACCESS_CONTROL to True so the handler rejects setup actions on a
configured instance; the service must then be restarted for the fix to load.
"""
import os
import threading
from flask import Flask, request, Response, jsonify

app = Flask(__name__)
LOCK = threading.Lock()

# --- Security posture -------------------------------------------------------
# Vulnerable default. The documented remediation sets this to True (e.g.
# `sed -i 's/^ENFORCE_SETUP_ACCESS_CONTROL = False/...= True/'`) and RESTARTS
# the service. Read once at import, so a fix written but not restarted stays
# vulnerable (the running process keeps the old value).
ENFORCE_SETUP_ACCESS_CONTROL = False
# ---------------------------------------------------------------------------

# Server state: an already-configured Confluence instance.
STATE = {"setup_complete": True, "admins": ["admin"]}


@app.route("/")
def index():
    return Response(
        "<html><body><h1>Confluence</h1>"
        "<p>Dashboard - Welcome back. Please <a href='/login.action'>log in</a>.</p>"
        "<p>Version: 8.3.2 (simulated)</p></body></html>",
        content_type="text/html",
    )


@app.route("/rest/api/admins")
def list_admins():
    # State probe so the exploit's effect (a newly created admin) is observable.
    with LOCK:
        return jsonify(sorted(STATE["admins"]))


@app.route("/setup/setupadministrator.action", methods=["GET", "POST"])
def setup_admin():
    # CVE-2023-22515: the setup endpoint must be dead on a configured instance,
    # but the vulnerable code honours it without any access-control check.
    if ENFORCE_SETUP_ACCESS_CONTROL and STATE["setup_complete"]:
        return Response("Forbidden: setup already complete\n",
                        status=403, content_type="text/plain")

    # GET ?trigger=true reopens the setup wizard (the access-control bypass).
    if request.args.get("trigger") == "true":
        with LOCK:
            STATE["setup_complete"] = False
        return Response("Setup reopened\n", status=200,
                        content_type="text/plain")

    # POST creates a new administrator from unauthenticated input.
    if request.method == "POST":
        user = request.form.get("username") or request.args.get("username")
        if user:
            with LOCK:
                if user not in STATE["admins"]:
                    STATE["admins"].append(user)
                STATE["setup_complete"] = True
            return Response("Administrator %s created\n" % user, status=200,
                            content_type="text/plain")
    return Response("setup wizard\n", status=200, content_type="text/plain")


if __name__ == "__main__":
    app.run(host=os.environ.get("CONF_HOST", "0.0.0.0"), port=8090, debug=False)
