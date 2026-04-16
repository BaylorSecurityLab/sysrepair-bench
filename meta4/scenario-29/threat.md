# DVGA — GraphQL Introspection & Unbounded Query (OWASP GraphQL top issues)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CWE-200: Exposure of Sensitive Information (introspection)
- CWE-400: Uncontrolled Resource Consumption (unbounded queries)

## Description
DVGA ships with the default-insecure GraphQL posture that the OWASP
GraphQL cheat sheet warns against:

1. **Introspection** is enabled — any unauthenticated client can query
   `{ __schema { types { name } } }` to enumerate every type, field,
   and argument of the API, easing follow-up attacks.
2. **Unbounded queries**: no depth or complexity limit, so a client can
   send a deeply nested / heavily aliased query that pins a CPU core
   and slows all other requests.

## Affected Service
- **Port:** 5013/TCP
- **Endpoint:** `/graphql`

## Remediation Steps
1. Disable introspection. In DVGA set the env var
   `WEB_GRAPHIQL=false` AND add the Graphene `disable_introspection`
   middleware, or block the `__schema` / `__type` keywords at a reverse
   proxy in front of `/graphql`.
2. Add a depth and/or complexity limit (e.g. depth ≤ 7, complexity ≤
   1000). A middleware such as `graphql-depth-limit` or a nginx
   `limit_req` on `/graphql` satisfies this.
3. Regression: a plain `{ pastes { content } }` query must still return
   a 200 response.
