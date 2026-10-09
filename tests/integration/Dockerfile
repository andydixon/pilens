# Test environment mirroring the Raspberry Pi OS (Debian trixie) userland.
# Used only for automated tests; the appliance itself does not use Docker.
FROM debian:trixie
ENV DEBIAN_FRONTEND=noninteractive
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections && \
    apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      tshark dnsmasq-base nftables iproute2 iputils-ping curl bind9-dnsutils \
      python3 busybox procps ca-certificates >/dev/null && rm -rf /var/lib/apt/lists/*
