FROM --platform=linux/amd64 ubuntu:22.04

# netfilter nf_tables UAF — CVE-2024-1086.
# Affected: kernel 5.14 through 6.6 (with fixes backported to various
# stable branches in January–February 2024). This is a kernel LPE; the
# container exercises the userspace component only.

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        iptables nftables ca-certificates && \
    rm -rf /var/lib/apt/lists/*


CMD ["/bin/bash", "-c", "tail -f /dev/null"]
