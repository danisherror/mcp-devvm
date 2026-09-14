#!/bin/bash
# Idempotent VM hardening (doc §17), run at container start and safe to
# re-run any time. Some checks are best-effort inside a nested-container demo
# (see README's "what's simulated" section) -- each says so where it applies.
set -euo pipefail

echo "[harden] locking implicitly-executed paths for devd..."
for p in /home/devd/.bashrc /home/devd/.profile /home/devd/.ssh /home/devd/.bash_profile; do
  if [ -e "$p" ]; then
    chattr +i "$p" 2>/dev/null || chmod a-w "$p" 2>/dev/null || true
  fi
done

echo "[harden] verifying devd is unprivileged..."
if id -nG devd | tr ' ' '\n' | grep -qxE 'sudo|docker|disk|adm|root'; then
  echo "[harden] FAIL: devd is in a privileged group" >&2
  exit 1
fi
if [ -f /etc/sudoers.d/devd ]; then
  echo "[harden] FAIL: a sudoers entry exists for devd" >&2
  exit 1
fi
if [ "$(id -u devd)" = "0" ]; then
  echo "[harden] FAIL: devd resolves to uid 0" >&2
  exit 1
fi

echo "[harden] devd's own operation files are read-only to it..."
# root always passes a plain [ -w ] test regardless of permission bits, so
# check as the devd account actually would see it.
if su devd -s /bin/sh -c '[ -w /opt/devd_src/devd/operations ]' 2>/dev/null; then
  echo "[harden] FAIL: devd's operations directory is writable by devd" >&2
  exit 1
fi

echo "[harden] blocking the cloud instance-metadata address..."
if command -v iptables >/dev/null 2>&1; then
  iptables -C OUTPUT -d 169.254.0.0/16 -j DROP 2>/dev/null \
    || iptables -A OUTPUT -d 169.254.0.0/16 -j DROP 2>/dev/null \
    || echo "[harden] iptables present but rule could not be applied -- skipped"
else
  echo "[harden] iptables unavailable in this demo container -- skipped (see README)"
fi

echo "[harden] OK"
