FROM --platform=linux/amd64 redis:7-alpine

# ArgoCD bundled Redis — no authentication (misconfig).
# Redis ships with no requirepass, allowing any network client to
# read/write ArgoCD session tokens and application state.

# Use a custom start script that seeds data after Redis starts
RUN cat > /start.sh <<'BASH'
#!/bin/sh
redis-server --save 60 1 --loglevel warning &
REDIS_PID=$!

# Wait for Redis to be ready
for i in $(seq 1 20); do
    redis-cli PING >/dev/null 2>&1 && break
    sleep 0.5
done

# Seed ArgoCD data
redis-cli SET "argocd:session:token:admin" \
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhcmdvY2QiLCJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.faketoken" \
    >/dev/null 2>&1
redis-cli SET "argocd:app:guestbook" \
    '{"name":"guestbook","namespace":"default","status":"Healthy"}' \
    >/dev/null 2>&1

wait $REDIS_PID
BASH
RUN chmod +x /start.sh


EXPOSE 6379
CMD ["/start.sh"]
