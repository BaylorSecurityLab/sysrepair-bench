# OWASP crAPI — BOLA & Mass-Assignment

## Severity
**High** (CVSS 8.1 — authenticated horizontal privilege escalation)

## CVE / CWE
- No CVE — OWASP API Security Top 10 2023
- CWE-639: Authorization Bypass Through User-Controlled Key (BOLA)
- CWE-915: Improperly Controlled Modification of Dynamically-Determined
  Object Attributes (mass-assignment)

## Description
This scenario runs a Flask API that mirrors two canonical flaws from
OWASP's crAPI teaching app:

1. **BOLA (Broken Object-Level Authorization)** on
   `GET /videos/<vid>`: the handler returns any video by id without
   checking that the requesting user owns the object. Alice can fetch
   Bob's private video just by incrementing the id.

2. **Mass-Assignment** on `POST /profile`: the handler calls
   `u.update(body)` on arbitrary JSON, so a client can set
   `{"is_admin": true, "balance": 1e9}` and elevate themselves.

## Affected Service
- **Port:** 8888/TCP
- **Code:** `/app/app.py` — `get_video`, `update_profile`

## Remediation Steps
1. In `get_video`, compare the video's `owner_id` to the current user's
   `id` (from `current_user()`). Return `403 Forbidden` when they differ.
2. In `update_profile`, build the update dict from a server-controlled
   allow-list (e.g. `{"email"}`) and drop any other keys.
3. Regression: `GET /videos/1` with `X-User: alice` must still return
   alice's video; `POST /profile` with `{"email":"new@x"}` as alice
   must still succeed.
