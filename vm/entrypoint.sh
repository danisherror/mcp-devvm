#!/bin/bash
set -euo pipefail

echo "[entrypoint] generating sshd host keys if missing..."
ssh-keygen -A >/dev/null

if [ -f /etc/devd/ca.pub ]; then
  echo "[entrypoint] trusting tunnel CA..."
  cp /etc/devd/ca.pub /etc/ssh/ca.pub
  mkdir -p /etc/ssh/principals
  echo "devd-tunnel" > /etc/ssh/principals/devd-tunnel
  cat > /etc/ssh/sshd_config.d/ca-trust.conf <<EOF
TrustedUserCAKeys /etc/ssh/ca.pub
AuthorizedPrincipalsFile /etc/ssh/principals/%u
EOF
else
  echo "[entrypoint] WARNING: no CA public key mounted at /etc/devd/ca.pub -- the tunnel account will not accept any certificate" >&2
fi

if [ -z "$(ls /etc/devd/approvers/*.pub 2>/dev/null)" ]; then
  echo "[entrypoint] NOTE: no approver keys in /etc/devd/approvers yet -- operations that need approval will be refused until one is added (python -m scripts.approver_keys init)" >&2
fi

if [ ! -f /etc/devd/token_signing_key.pub ]; then
  echo "[entrypoint] WARNING: no token verification key mounted at /etc/devd/token_signing_key.pub -- devd will refuse every request" >&2
fi

chown -R devd:devd /run/devd /var/lib/devd
mkdir -p /srv/workspace /srv/logs /srv/services
chown -R devd:devd /srv/workspace /srv/logs /srv/services

echo "[entrypoint] seeding demo data..."
su devd -s /bin/bash -c /seed_demo_data.sh

echo "[entrypoint] hardening..."
/harden.sh

echo "[entrypoint] starting sshd..."
mkdir -p /run/sshd
/usr/sbin/sshd -D -e 2>>/var/log/sshd.log &

echo "[entrypoint] starting devd..."
# `su` does not reliably forward an exported environment to the target user,
# so the vars devd needs are passed explicitly via `env` inside the su'd command.
exec su devd -s /bin/bash -c "exec env \
  PYTHONPATH=/opt/devd_src \
  DEVD_OPERATIONS_DIR=/opt/devd_src/devd/operations \
  DEVD_SOCKET=/run/devd/devd.sock \
  DEVD_TOKEN_PUBKEY=/etc/devd/token_signing_key.pub \
  DEVD_APPROVERS_DIR=/etc/devd/approvers \
  DEVD_TARGET_ID=${DEVD_TARGET_ID:-dev-vm-01} \
  /opt/devd_venv/bin/python -m uvicorn devd.app:app --uds /run/devd/devd.sock --log-level info"
