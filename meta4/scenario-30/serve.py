# Boot launcher for VAmPI WITHOUT the Werkzeug auto-reloader / debugger.
#
# app.py starts the server with debug=True, which auto-reloads on any source
# edit — that would make the "fixed the file but never restarted" case
# untestable (the reloader restarts for you) and exposes the Werkzeug console.
#
# We must import `config` FIRST (exactly as app.py does): connexion's add_api()
# resolves the operationIds, which imports the `app` module and evaluates the
# `vulnerable` flag + SECRET_KEY there. Importing `app` directly instead trips a
# circular import, so don't. Running vuln_app.run() with debug defaulted off
# gives a single process and no reloader.
from config import vuln_app  # noqa: F401

if __name__ == "__main__":
    vuln_app.run(host="0.0.0.0", port=5000)
