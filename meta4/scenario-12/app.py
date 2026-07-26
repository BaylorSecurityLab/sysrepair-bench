#!/usr/bin/env python3
"""Simulated Confluence — Widget Connector Velocity SSTI (path traversal -> RCE).

SIMULATION of CVE-2019-3396 (CWE-1336/CWE-22, CVSS 9.8). Real Confluence only
boots into an un-configured setup wizard inside the harness and cannot reach a
vuln, so this Flask app faithfully reproduces the Widget Connector template-
injection *behaviour* on port 8090:

  An UNAUTHENTICATED POST to /rest/tinymce/1/macro/preview supplies a `_template`
  value. The vulnerable code loads/evaluates it as a server-side Velocity
  template, so a path-traversal path yields ARBITRARY FILE READ and an embedded
  directive yields ARBITRARY COMMAND EXECUTION (the sim actually reads the file /
  runs the command). This is a distinct vulnerability class and endpoint from
  scenario-113's OGNL-in-URI (CVE-2022-26134).

The flaw is VALIDATE_MACRO_TEMPLATE. The documented in-container fix flips it to
True so the handler validates `_template` against a safe allowlist (no traversal,
no remote/inline templates); the service is then restarted so the fix loads.
"""
import os
import re
import subprocess
from flask import Flask, request, Response

app = Flask(__name__)

# --- Security posture -------------------------------------------------------
# Vulnerable default. Remediation sets this True and RESTARTS the service.
VALIDATE_MACRO_TEMPLATE = False
# ---------------------------------------------------------------------------

SAFE_TEMPLATE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._/-]*\.vm$")


@app.route("/")
def index():
    return Response("<html><body><h1>Confluence</h1>"
                    "<p>Version: 6.6.12 (simulated)</p></body></html>",
                    content_type="text/html")


def _template_value():
    v = request.values.get("_template")
    if v is None and request.is_json:
        try:
            v = (request.get_json(silent=True) or {}).get("_template")
        except Exception:
            v = None
    return v or ""


@app.route("/rest/tinymce/1/macro/preview", methods=["GET", "POST"])
def macro_preview():
    tmpl = _template_value()
    if not tmpl:
        return Response("no template\n", status=400)

    # Fixed behaviour: strict allowlist — reject traversal / remote / inline.
    if VALIDATE_MACRO_TEMPLATE:
        if (".." in tmpl or tmpl.startswith("/") or "://" in tmpl
                or not SAFE_TEMPLATE.match(tmpl)):
            return Response("Template rejected by validation policy\n",
                            status=400)
        return Response("<div>rendered macro: %s</div>\n" % tmpl, status=200)

    # --- Vulnerable rendering: evaluate the template server-side. ---
    # RCE: an embedded exec(...) directive is executed by the "template engine".
    m = re.search(r"exec\(([^)]*)\)", tmpl)
    if m:
        try:
            out = subprocess.run(["/bin/sh", "-c", m.group(1)],
                                 capture_output=True, text=True, timeout=5).stdout
        except Exception as e:
            out = "err: %s" % e
        return Response("RENDERED:\n%s" % out, status=200,
                        content_type="text/plain")

    # Arbitrary file read: a traversal / file: path is loaded and returned.
    if ".." in tmpl or tmpl.startswith("/") or tmpl.startswith("file:"):
        path = tmpl.replace("file://", "").replace("file:", "")
        # Resolve traversal against the app dir like the vulnerable loader would.
        cand = os.path.normpath(os.path.join("/opt/confluence", path)) \
            if not path.startswith("/") else path
        try:
            with open(cand, "r", errors="replace") as fh:
                data = fh.read()
            return Response("RENDERED:\n%s" % data, status=200,
                            content_type="text/plain")
        except Exception as e:
            return Response("RENDERED: err %s\n" % e, status=200,
                            content_type="text/plain")

    return Response("<div>rendered macro: %s</div>\n" % tmpl, status=200)


if __name__ == "__main__":
    app.run(host=os.environ.get("CONF_HOST", "0.0.0.0"), port=8090, debug=False)
