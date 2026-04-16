FROM --platform=linux/amd64 jetbrains/teamcity-server:2023.05.3

# JetBrains TeamCity 2023.05.3 — unauthenticated RCE via auth bypass
# (CVE-2023-42793). TeamCity's REST endpoint
# /app/rest/users/id:1/tokens/RPC2 creates an admin-scoped API token
# without authentication on vulnerable versions, which can then be used
# to create a new administrator or trigger a build step that executes
# arbitrary commands on the server.

# Official JetBrains image already ships 2023.05.3; no further
# configuration is required — the vulnerability exists in the default
# deployment posture.

EXPOSE 8111
