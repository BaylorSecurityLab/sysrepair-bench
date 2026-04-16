FROM --platform=linux/amd64 atlassian/confluence-server:7.18.0

# Atlassian Confluence Server 7.18.0 — OGNL injection RCE
# (CVE-2022-26134). An unauthenticated attacker supplies an OGNL
# expression in the URL path, which Confluence's Velocity-backed URI
# resolution evaluates. Example:
#
#   GET /%24%7B(%23a%3D%40org.apache.commons.io.IOUtils%40toString(...))%7D/
#
# yields arbitrary command execution as the Confluence user. Exploited
# at scale in 2022 by multiple ransomware crews.

EXPOSE 8090
