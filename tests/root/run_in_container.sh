#!/bin/sh
# Run tests/root as root in a throwaway Ubuntu container:
#
#     sh tests/root/run_in_container.sh
#
# Covers what can't be tested without root: scripts/install_decide.sh and
# `approver-keys enroll`. Installs the committed HEAD, so commit first.
set -eu
REPO=$(cd "$(dirname "$0")/../.." && pwd -P)
IMAGE=${MCP_ROOT_TEST_IMAGE:-ubuntu:24.04}

exec docker run --rm -v "$REPO:/src:ro" -e MCP_ROOT_TESTS=1 "$IMAGE" sh -euc '
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends git python3 python3-venv sudo ca-certificates >/dev/null
  for u in alice bob carol; do useradd -m "$u"; done
  # Approvers other than the checkout owner need to reach the repo (decide
  # reads data/ from it), so let them into alice home directory.
  chmod 755 /home/alice
  git clone -q /src /home/alice/repo
  chown -R alice:alice /home/alice/repo
  python3 -m venv /opt/testenv
  /opt/testenv/bin/pip install -q pytest pexpect
  cd /home/alice/repo
  /opt/testenv/bin/python -m pytest tests/root -q -p no:cacheprovider
'
