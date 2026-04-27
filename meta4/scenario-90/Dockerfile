FROM --platform=linux/amd64 debian:bookworm-slim

# A credential committed to git history is never truly deleted.
# Even after a "fix" commit removes the file, `git log -p` reveals the
# original plaintext value to anyone with repository access.

RUN apt-get update && \
    apt-get install -y --no-install-recommends git bash ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN git config --global user.email "dev@example.com" && \
    git config --global user.name "Dev" && \
    git config --global init.defaultBranch main

RUN mkdir -p /opt/app && cd /opt/app && \
    git init && \
    # First commit: accidentally include the password
    echo "DB_PASSWORD=leaked_secret_42" > config.env && \
    echo "APP_PORT=8080" >> config.env && \
    git add config.env && \
    git commit -m "Add application config" && \
    # Second commit: "fix" by removing the password line
    echo "APP_PORT=8080" > config.env && \
    git add config.env && \
    git commit -m "Remove password from config (security fix)"


WORKDIR /opt/app

CMD ["bash", "-c", "echo 'App config:'; cat config.env; exec sleep infinity"]
