# Bridge container for scenario-14-freebsd13.
# The FreeBSD target runs in a Vagrant VM; this container holds the SSH key
# and acts as the Inspect sandbox — the agent SSHes from here to the VM.
# build/vagrant_key is extracted by the pipeline in task.py before `docker build`.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*
COPY build/vagrant_key /root/.ssh/vagrant_key
RUN chmod 700 /root/.ssh && chmod 600 /root/.ssh/vagrant_key
# Disable host-key prompts — the VM is ephemeral and we control it
RUN printf 'Host *\n    StrictHostKeyChecking no\n    UserKnownHostsFile /dev/null\n    LogLevel QUIET\n' \
    > /root/.ssh/config && chmod 600 /root/.ssh/config
