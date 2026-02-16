FROM ubuntu:rolling
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

# Install AppArmor but leave it in a non-enforcing state
RUN apt-get update && apt-get install -y \
    apparmor \
    apparmor-utils \
    systemctl \
    coreutils \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Set all AppArmor profiles to complain mode (non-enforcing)
# This defeats the purpose of MAC (Mandatory Access Control)
RUN if [ -d /etc/apparmor.d ]; then \
        for profile in /etc/apparmor.d/*; do \
            if [ -f "$profile" ] && [ "$(basename "$profile")" != "local" ]; then \
                aa-complain "$profile" 2>/dev/null || true; \
            fi; \
        done; \
    fi

# Create a marker indicating AppArmor was intentionally weakened
RUN echo "apparmor_disabled=true" > /etc/apparmor/apparmor_status.conf 2>/dev/null || \
    mkdir -p /etc/apparmor && echo "apparmor_disabled=true" > /etc/apparmor/apparmor_status.conf

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

CMD ["sleep", "infinity"]
