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
