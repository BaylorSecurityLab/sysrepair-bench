FROM --platform=linux/amd64 ubuntu:22.04

# ImageMagick with a missing/permissive policy.xml allows dangerous coders
# (MVG, MSL, URL) — an attacker can trigger RCE via specially crafted images.
# CVE-2023-34152 / CWE-94 / CVSS 8.8

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        imagemagick \
        libmagickcore-6.q16-6 \
        && \
    rm -rf /var/lib/apt/lists/*

# Represent the vulnerable state: remove the shipped policy.xml so that
# all coders are permitted (same effect as a fully permissive policy).
RUN rm -f /etc/ImageMagick-6/policy.xml

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

CMD ["bash"]
