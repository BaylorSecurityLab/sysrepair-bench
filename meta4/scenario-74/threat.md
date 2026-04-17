# Docker Image Secrets in ENV/Layers — Cleartext Storage (misconfig)

## Severity
**High** (CVSS 8.8)

## CVE / CWE
- CWE-312: Cleartext Storage of Sensitive Information

## Description
Secrets (passwords, API keys, tokens) embedded in Docker `ENV` instructions are
stored in cleartext in two places that persist beyond the running container:

1. **Image metadata:** Every `ENV` instruction is recorded in the image
   manifest. Anyone who can pull the image can run `docker inspect <image>` and
   read all environment variables, including secrets — no container execution
   required.
2. **Layer history:** `docker history --no-trunc <image>` exposes every
   Dockerfile instruction, including `ENV DB_PASSWORD=SuperSecret123`.

Additionally, the running container exposes secrets via:
- `docker inspect <container>` → `Config.Env` array
- `/proc/1/environ` inside the container (readable by any process in the
  container's PID namespace)

Unlike secrets in RUN commands (which can sometimes be scrubbed by squashing
layers), `ENV` values cannot be removed from an image without rebuilding it
from scratch without those instructions.

## Affected Service
- **Image:** Any Docker image with `ENV` instructions containing secrets
- **Exposed values:** `DB_PASSWORD=SuperSecret123`, `API_KEY=sk-live-abc123`

## Vulnerable Configuration
- `ENV DB_PASSWORD=SuperSecret123` in Dockerfile
- `ENV API_KEY=sk-live-abc123` in Dockerfile
- Secrets present in `env` output inside the container and in `/proc/1/environ`

## Remediation Steps
1. Remove all `ENV` secret instructions from the Dockerfile. Rebuild the image.
2. Inject secrets at **runtime** using one of:
   - `docker run -e DB_PASSWORD="$(secret_provider get db_password)"` — avoids
     baking into the image but still exposes via `docker inspect`.
   - **Docker Secrets** (Swarm mode): mount at `/run/secrets/<name>` and read
     as a file — never appears in env or image metadata.
   - **Kubernetes Secrets** mounted as volumes — same file-based pattern.
   - A secrets manager sidecar (Vault Agent, AWS Secrets Manager CSI driver).
3. If the image has already been pushed with baked secrets, rotate all exposed
   credentials immediately, then rebuild and repush without secrets.
4. Add a pre-commit hook or CI step using `trufflehog` or `detect-secrets` to
   prevent secrets from entering Dockerfiles.
