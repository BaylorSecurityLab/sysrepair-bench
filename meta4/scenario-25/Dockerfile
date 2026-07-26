FROM --platform=linux/amd64 moby/buildkit:v0.12.4

# BuildKit 0.12.4 — arbitrary host-file write via unsanitized cache-mount
# path during teardown (CVE-2024-23652). The cleanup of a cache mount
# followed a symlink out of the build sandbox, letting a malicious
# Dockerfile delete or replace arbitrary host files. Fix lands alongside
# CVE-2024-23651 in 0.12.5.

# bash: the SysRepair harness runs verify.sh with `bash`, but the stock
# moby/buildkit image (Alpine) ships only busybox `sh`. curl: for the solution's
# network fallback. Install both so the scenario is runnable and solvable.
RUN apk add --no-cache bash curl

# Vendor the FIXED BuildKit 0.12.5 binaries (sha256-pinned) into /opt/fix so the
# remediation is hermetic (no network needed at solve time).
RUN set -eux; \
    curl -fsSL -o /tmp/bk.tgz https://github.com/moby/buildkit/releases/download/v0.12.5/buildkit-v0.12.5.linux-amd64.tar.gz; \
    echo "fcd9149b876fba0404365cb021937e2435cad443d2a31b2bc5360298f900dfd7  /tmp/bk.tgz" | sha256sum -c -; \
    mkdir -p /opt/fix; \
    tar -xzf /tmp/bk.tgz -C /opt/fix bin/buildkitd bin/buildctl; \
    mv /opt/fix/bin/buildkitd /opt/fix/buildkitd; \
    mv /opt/fix/bin/buildctl  /opt/fix/buildctl; \
    rmdir /opt/fix/bin; \
    rm -f /tmp/bk.tgz; \
    chmod +x /opt/fix/buildkitd /opt/fix/buildctl

EXPOSE 1234

# The base image's ENTRYPOINT is ["buildkitd"]; clear it so the CMD wrapper runs
# verbatim. The wrapper boots the VULNERABLE buildkitd (v0.12.4, already on PATH)
# backgrounded on the default socket, so the daemon is ALREADY RUNNING at
# handoff. This makes the "replaced the binary but never restarted the daemon"
# mistake detectable: verify.sh queries the LIVE daemon version, not just the
# binary on disk. PID 1 stays `sleep infinity` (via exec) so restarting
# buildkitd never kills the container.
ENTRYPOINT []
CMD ["/bin/sh", "-c", "buildkitd --addr unix:///run/buildkit/buildkitd.sock >/tmp/buildkitd.log 2>&1 & for i in $(seq 1 40); do [ -S /run/buildkit/buildkitd.sock ] && break; sleep 0.5; done; exec sleep infinity"]
