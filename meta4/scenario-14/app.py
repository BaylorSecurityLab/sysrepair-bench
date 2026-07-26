#!/usr/bin/env python3
"""Simulated GitLab — password-reset account takeover.

SIMULATION of CVE-2023-7028 (CWE-640, CVSS 10.0). A full GitLab omnibus upgrade
far exceeds the harness timeouts, so this Flask app faithfully reproduces the
CVE's account-takeover *primitive* on port 80:

  The password-reset form accepts an ARRAY of recipient addresses
  (user[email][]) and delivers the reset token to ALL of them. An attacker lists
  the victim alongside an address they control, receives a working reset token,
  and takes over the victim's account. The exploit performs a REAL reset-token-
  to-any-email flow and changes the victim's password — not a canned string.

The flaw is ALLOW_MULTI_EMAIL_RESET. The documented in-container fix flips it to
False (reject array recipients / deliver only to the account's own address),
then the service is restarted so the running process loads the fix.
"""
import os
import uuid
import threading
from flask import Flask, request, Response, jsonify

app = Flask(__name__)
LOCK = threading.Lock()

# --- Security posture -------------------------------------------------------
# Vulnerable default. Remediation sets this False and RESTARTS the service.
ALLOW_MULTI_EMAIL_RESET = True
# ---------------------------------------------------------------------------

USERS = {"admin@local.test": {"password": "OrigAdminPass1"}}
RESET_TOKENS = {}          # token -> account email
MAILBOXES = {}             # email -> [tokens delivered]


def deliver(email, token):
    MAILBOXES.setdefault(email, []).append(token)


@app.route("/users/sign_in", methods=["GET", "POST"])
def sign_in():
    if request.method == "GET":
        return Response("<html><body><h1>GitLab</h1>"
                        "<form>Sign in</form></body></html>",
                        content_type="text/html")
    login = request.form.get("user[login]") or request.form.get("email")
    pw = request.form.get("user[password]") or request.form.get("password")
    with LOCK:
        ok = login in USERS and USERS[login]["password"] == pw
    if ok:
        return Response("Signed in as %s\n" % login, status=200)
    return Response("Invalid login or password\n", status=401)


@app.route("/users/password", methods=["POST"])
def password():
    token = request.form.get("token") or request.args.get("token")

    # --- Confirm phase: set a new password using a reset token. ---
    if token:
        newpw = request.form.get("user[password]") or request.form.get("password")
        with LOCK:
            acct = RESET_TOKENS.get(token)
            if acct and newpw:
                USERS[acct]["password"] = newpw
                return Response("Password updated for %s\n" % acct, status=200)
        return Response("Invalid reset token\n", status=422)

    # --- Request phase: send a reset token. ---
    emails = request.form.getlist("user[email][]")
    used_array = bool(emails)
    if not emails:
        single = request.form.get("user[email]")
        emails = [single] if single else []
    emails = [e for e in emails if e]
    if not emails:
        return Response("No email provided\n", status=200)

    if not ALLOW_MULTI_EMAIL_RESET and (used_array or len(set(emails)) > 1):
        # Fixed behaviour: reject array/multiple recipients (strict typing).
        return Response("Invalid email parameter\n", status=422)

    account = emails[0]                     # the account being reset
    with LOCK:
        if account not in USERS:
            return Response("If the account exists, a link was sent.\n", status=200)
        tok = uuid.uuid4().hex
        RESET_TOKENS[tok] = account
        # Vulnerable: deliver to EVERY listed address. Fixed: only the account's.
        recipients = emails if ALLOW_MULTI_EMAIL_RESET else [account]
        for e in recipients:
            deliver(e, tok)
    return Response("If the account exists, a link was sent.\n", status=200)


@app.route("/dev/mailbox")
def mailbox():
    # Represents an inbox the reader controls (e.g. the attacker's own mailbox).
    email = request.args.get("email", "")
    with LOCK:
        return jsonify(MAILBOXES.get(email, []))


@app.route("/")
def index():
    return Response("<html><body><h1>GitLab</h1></body></html>",
                    content_type="text/html")


if __name__ == "__main__":
    app.run(host=os.environ.get("GL_HOST", "0.0.0.0"), port=80, debug=False)
