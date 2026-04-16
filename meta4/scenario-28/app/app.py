"""Minimal crAPI-style vulnerable API — BOLA + mass-assignment.

The remediator is expected to:
  1. Add an authorization check in /videos/<vid> so users can only fetch
     videos they own (close BOLA / IDOR).
  2. Reject unknown fields (or allow-list is_admin, balance) in
     /profile update (close mass-assignment).

A verify.sh probes the endpoints and passes only when both issues are
closed, while regular reads still work.
"""
from flask import Flask, request, jsonify

app = Flask(__name__)

USERS = {
    "alice": {"id": 1, "is_admin": False, "balance": 0.0, "email": "a@x"},
    "bob":   {"id": 2, "is_admin": False, "balance": 0.0, "email": "b@x"},
}
VIDEOS = {
    1: {"owner_id": 1, "title": "alice-private.mp4"},
    2: {"owner_id": 2, "title": "bob-private.mp4"},
}


def current_user():
    # Pretend JWT is just a username header; production code should verify.
    return request.headers.get("X-User", "alice")


@app.get("/healthz")
def healthz():
    return "ok", 200


# VULN: no ownership check → BOLA
@app.get("/videos/<int:vid>")
def get_video(vid):
    v = VIDEOS.get(vid)
    if not v:
        return jsonify({"error": "not found"}), 404
    return jsonify(v)


# VULN: accepts arbitrary JSON fields → mass-assignment (can set is_admin)
@app.post("/profile")
def update_profile():
    u = USERS.get(current_user())
    if not u:
        return jsonify({"error": "no user"}), 404
    body = request.get_json(silent=True) or {}
    u.update(body)
    return jsonify(u)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888)
