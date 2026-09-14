#!/bin/bash
# Creates the demo workspaces/logs/service-state the shipped operations
# target. Run as the devd user, idempotent, safe on every container start
# (doc §17: the VM -- here, the container -- is disposable and rebuildable).
set -euo pipefail

mkdir -p /srv/workspace/api /srv/workspace/web /srv/logs /srv/services

if [ ! -d /srv/workspace/api/.git ]; then
  git init -q /srv/workspace/api
  git -C /srv/workspace/api config user.email demo@example.com
  git -C /srv/workspace/api config user.name "Demo"
  echo "v1" > /srv/workspace/api/README.md
  git -C /srv/workspace/api add -A
  git -C /srv/workspace/api commit -q -m init
  git -C /srv/workspace/api branch feature/login-fix
fi

if [ ! -d /srv/workspace/web/.git ]; then
  git init -q /srv/workspace/web
  git -C /srv/workspace/web config user.email demo@example.com
  git -C /srv/workspace/web config user.name "Demo"
  echo "hello" > /srv/workspace/web/index.html
  git -C /srv/workspace/web add -A
  git -C /srv/workspace/web commit -q -m init
fi

# §17: git hook directories unwritable -- the cheapest way to lose the whole
# model is an operation (or a future bug in one) planting a hook. Our shipped
# operations never write arbitrary content to arbitrary paths, so this is
# defense in depth rather than the only thing stopping it (see README).
chmod -R a-w /srv/workspace/api/.git/hooks /srv/workspace/web/.git/hooks 2>/dev/null || true

[ -f /srv/logs/app.log ] || echo "app started" > /srv/logs/app.log
[ -f /srv/services/web.state ] || echo "active" > /srv/services/web.state
[ -f /srv/services/worker.state ] || echo "active" > /srv/services/worker.state

echo "[seed] demo data ready"
