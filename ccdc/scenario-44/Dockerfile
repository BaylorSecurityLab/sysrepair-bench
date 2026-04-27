FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    sudo \
    passwd \
    && rm -rf /var/lib/apt/lists/*

# Create the authorized admin user and add to sudo group
RUN useradd -m -s /bin/bash admin && \
    echo "admin:Str0ngP@ss!" | chpasswd && \
    usermod -aG sudo admin

# Vulnerability: Create an unauthorized user "intern" and add to sudo group.
# The intern user should not have sudo privileges per organizational policy.
RUN useradd -m -s /bin/bash intern && \
    echo "intern:intern123" | chpasswd && \
    usermod -aG sudo intern

# Create the authorized sudoers list
RUN echo "admin" > /opt/authorized_sudoers

# Create a regular test user (not in sudo)
RUN useradd -m -s /bin/bash testuser


CMD ["sleep", "infinity"]
