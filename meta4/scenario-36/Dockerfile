FROM --platform=linux/amd64 minio/minio:latest

# MinIO public bucket — anonymous read access (misconfig).
# A bucket is created with public anonymous download policy,
# allowing anyone to read its contents without authentication.

ENV MINIO_ROOT_USER=minioadmin
ENV MINIO_ROOT_PASSWORD=minioadmin

# Create startup script that initializes MinIO with a public bucket
# We use a wrapper that starts MinIO in background, configures it, then
# brings it to foreground.
USER root
RUN microdnf install -y curl || apk add --no-cache curl 2>/dev/null || true

RUN cat > /opt/start.sh <<'BASH'
#!/bin/sh
# Start MinIO server in background
minio server /data --console-address ":9001" &
MINIO_PID=$!

# Wait for MinIO to be ready
for i in $(seq 1 30); do
    curl -sf http://127.0.0.1:9000/minio/health/live >/dev/null 2>&1 && break
    sleep 1
done

# Configure mc alias
mc alias set local http://127.0.0.1:9000 minioadmin minioadmin 2>/dev/null

# Create bucket and upload a secret file
mc mb local/testbucket 2>/dev/null || true
echo "SECRET_DATA: aws_access_key_id=AKIAIOSFODNN7EXAMPLE" | \
    mc pipe local/testbucket/secret.txt 2>/dev/null

# Set anonymous download policy (vulnerable!)
mc anonymous set download local/testbucket 2>/dev/null

# Bring MinIO to foreground
wait $MINIO_PID
BASH
RUN chmod +x /opt/start.sh

COPY verify.sh /verify.sh
RUN chmod +x /verify.sh

EXPOSE 9000 9001
ENTRYPOINT ["/opt/start.sh"]
