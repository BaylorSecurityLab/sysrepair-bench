#!/usr/bin/env python3
"""Simulated Confluence app — vulnerable to OGNL injection via URI (CVE-2022-26134)."""
import os
from flask import Flask, request, Response

app = Flask(__name__)

@app.route("/")
def index():
    return Response(
        "<html><body><h1>Confluence Setup</h1>"
        "<p>Confluence Data Center - Setup Wizard</p>"
        "<p>Version: 7.18.0 (simulated)</p>"
        "</body></html>",
        content_type="text/html",
    )

@app.route("/<path:path>", methods=["GET", "POST"])
def catch_all(path):
    # Simulate OGNL injection: if ${...} appears in the path, execute it
    if "${" in path or "%24%7B" in path.lower():
        # In a real Confluence, this would execute the OGNL expression.
        # Here we simulate the vulnerable behaviour by echoing it back.
        return Response(
            f"OGNL_EXECUTED: {path}\nuid=0(root) gid=0(root) groups=0(root)\n",
            content_type="text/plain",
            status=200,
        )
    return Response(
        "<html><body><h1>Confluence</h1><p>Page not found</p></body></html>",
        content_type="text/html",
        status=404,
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090, debug=False)
