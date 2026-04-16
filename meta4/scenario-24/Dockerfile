FROM --platform=linux/amd64 moby/buildkit:v0.12.4

# BuildKit 0.12.4 — build-time container escape via
# `RUN --mount=type=cache,source=...` (CVE-2024-23651). A malicious
# Dockerfile can race the cache-mount setup so that a symlink in the
# cache points outside the build-sandbox mount namespace, then execute
# a command whose child reads / writes host files during build.

EXPOSE 1234
