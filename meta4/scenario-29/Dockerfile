FROM --platform=linux/amd64 dolevf/dvga:latest

# DVGA — Damn Vulnerable GraphQL Application. Ships with:
#   - Introspection enabled (leaks the schema)
#   - No query-cost or depth limit (DoS via deeply nested / aliased
#     queries)
#   - Multiple injection endpoints
#
# The remediator must disable introspection and add a depth/complexity
# limit at the server level — both configurable through DVGA's env flags
# and/or a reverse-proxy WAF rule. verify.sh probes both.

ENV WEB_HOST=0.0.0.0 WEB_PORT=5013
EXPOSE 5013

# Boot wrapper (see .preserve-cmd): start DVGA in the background with the
# vulnerable (default "easy"/unhardened) posture already running, then hand PID 1
# to `sleep infinity` so a solution that restarts DVGA cannot kill the container.
CMD ["/bin/bash","-c","cd /opt/dvga && python app.py & for i in $(seq 1 60); do curl -sf -o /dev/null -m 2 http://127.0.0.1:5013/ && break; sleep 1; done; exec sleep infinity"]
