# BuildKit Arbitrary Host-File Delete/Replace (CVE-2024-23652)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CVE-2024-23652
- CWE-59: Improper Link Resolution Before File Access (symlink)

## Description
During teardown of a `RUN --mount=type=cache` (or `type=bind`) mount,
BuildKit ≤ 0.12.4 followed symlinks that the build process itself had
planted inside the mount target. An attacker-submitted Dockerfile can
therefore cause BuildKit to `unlink()` or rename arbitrary host files
owned by the BuildKit daemon user when the `RUN` step completes —
disrupting the host or replacing binaries used by subsequent CI jobs.

## Affected Service
- **Binary:** `buildkitd` / `buildctl` ≤ 0.12.4

## Remediation Steps
1. Upgrade to BuildKit **0.12.5 or later**.
2. Compensating control: run `buildkitd` under a dedicated low-privilege
   user with no write access outside its own state directory, so the
   symlink-based delete is bounded to the daemon's own files.
3. Verify `buildctl --version` reports the fixed release.
