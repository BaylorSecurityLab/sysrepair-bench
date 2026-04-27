FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y screen && apt-get clean && rm -rf /var/lib/apt/lists/*
# Set SUID bit on screen (VULNERABLE)
RUN chmod u+s /usr/bin/screen
CMD ["/bin/bash"]
