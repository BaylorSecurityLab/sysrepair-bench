FROM --platform=linux/amd64 moby/buildkit:v0.12.4

# BuildKit 0.12.4 — arbitrary host-file write via unsanitized cache-mount
# path during teardown (CVE-2024-23652). The cleanup of a cache mount
# followed a symlink out of the build sandbox, letting a malicious
# Dockerfile delete or replace arbitrary host files. Fix lands alongside
# CVE-2024-23651 in 0.12.5.

EXPOSE 1234
