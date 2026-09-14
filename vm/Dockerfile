# Stands in for the dev VM in this demo (doc's own §21.2/§25.3 integration
# tests run against "a throwaway container" -- this is that container, just
# also used interactively). A real deployment provisions an actual VM via
# IaC (doc §26.3 Phase 0); see the README for exactly what's simulated here
# and why (principally: bubblewrap needs --privileged only because this
# container is itself nested inside the outer sandbox's Docker -- on a real,
# non-containerized VM kernel, unprivileged user namespaces just work).
FROM debian:bookworm-slim

# This base image ships without ca-certificates, and the build network here
# only reaches deb.debian.org over HTTPS (not plain HTTP), which is a
# chicken-and-egg problem for apt. Bootstrap ca-certificates with
# verification off for this ONE install, then everything after verifies
# normally. If you're building this on a normal network, an ordinary
# `apt-get update && apt-get install` would work without any of this.
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/*.sources \
 && apt-get update -qq -o Acquire::https::Verify-Peer=false \
 && apt-get install -y -qq -o Acquire::https::Verify-Peer=false --no-install-recommends \
      ca-certificates bubblewrap openssh-server git python3 python3-venv iptables \
 && rm -rf /var/lib/apt/lists/*

# devd's own account: unprivileged, no login shell, not in sudo/docker/disk/adm (§3.2).
RUN useradd -m -s /usr/sbin/nologin -U devd

# The tunnel account: forwarding-only, locked down further by
# vm/sshd_config.d/devd-tunnel.conf (§9.4).
RUN useradd -m -s /usr/sbin/nologin -U devd-tunnel

RUN mkdir -p /run/devd /var/lib/devd/runs /etc/devd /etc/ssh/principals \
 && chown devd:devd /run/devd /var/lib/devd/runs

COPY vm/sshd_config.d/ /etc/ssh/sshd_config.d/

# devd's own source, including its operations -- root-owned, read-only to
# devd (§12.3: "devd cannot write its own operation files or config").
COPY devd /opt/devd_src/devd
COPY common /opt/devd_src/common
RUN chown -R root:root /opt/devd_src && chmod -R a-w /opt/devd_src

RUN python3 -m venv /opt/devd_venv \
 && /opt/devd_venv/bin/pip install --no-cache-dir --quiet \
      fastapi "uvicorn[standard]" pyjwt cryptography pyyaml structlog

COPY vm/entrypoint.sh /entrypoint.sh
COPY vm/harden.sh /harden.sh
COPY vm/seed_demo_data.sh /seed_demo_data.sh
RUN chmod +x /entrypoint.sh /harden.sh /seed_demo_data.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
