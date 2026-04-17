# Docker ARG Secret in Layers (misconfig)

## Severity
**Medium** (CVSS 6.5)

## CVE / CWE
- CWE-312: Cleartext Storage of Sensitive Information

## Description
Docker `ARG` instructions pass build-time variables into `RUN` commands. Unlike
`ENV`, the value does not appear in the final image's environment — but it is
permanently embedded in the image layer created by the `RUN` instruction that
consumed it. Anyone with access to the image can recover the secret with:

```
docker history --no-trunc <image>
```

The layer diff shows the full shell command including the argument value, e.g.:

```
/bin/sh -c echo "token=ghp_abc123def456" > /etc/app/config.ini
```

Even if a subsequent `RUN` step overwrites or deletes the file, the original
layer (and thus the secret) remains in the image and is recoverable by
exporting the image tarball and inspecting individual layer tarballs.

## Affected Service
- **Service:** Ubuntu 22.04 application container
- **Vulnerable configuration:** `ARG SECRET_TOKEN=ghp_abc123def456` passed to `RUN echo`

## Vulnerable Configuration
- `ARG SECRET_TOKEN` with a default value baked into the Dockerfile
- `RUN echo "token=${SECRET_TOKEN}"` writes the secret to a file in a layer
- Secret recoverable via `docker history`, image export, or layer inspection

## Remediation Steps
1. Remove the `ARG SECRET_TOKEN` and any `RUN` commands that write it to disk.
2. Mount secrets at build time using `RUN --mount=type=secret` (BuildKit):
   ```dockerfile
   RUN --mount=type=secret,id=secret_token \
       TOKEN=$(cat /run/secrets/secret_token) && \
       echo "token=${TOKEN}" > /etc/app/config.ini
   ```
   The secret is available only during the build step and never stored in any layer.
3. At runtime, inject the token via a Docker secret or mounted volume and read
   it from `/run/secrets/` rather than baking it into the image.
4. Rotate any tokens that were previously baked into published images.
