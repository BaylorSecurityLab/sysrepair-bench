FROM --platform=linux/amd64 atlassian/confluence-server:8.3.2

# Confluence 8.3.2 — broken access control: unauthenticated setup-state
# reset (CVE-2023-22515). An attacker sends requests to
# /setup/setupadministrator.action with trigger=true, tripping
# Confluence back into the initial setup wizard. The attacker then
# creates a new administrator account, bypassing all authentication.
# Exploited as a 0day by a Chinese nation-state actor in 2023.

EXPOSE 8090
