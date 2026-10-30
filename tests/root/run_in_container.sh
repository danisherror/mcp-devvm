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
  apt-get install -y -qq --no-install-recommends git python3 python3-venv sudo ca-certificates curl >/dev/null
  for u in alice bob carol; do useradd -m "$u"; done
  # Approvers other than the checkout owner need to reach the repo (decide
  # reads data/ from it), so let them into alice home directory.
  chmod 755 /home/alice
  git clone -q /src /home/alice/repo
  chown -R alice:alice /home/alice/repo
  retry() { for i in 1 2 3 4 5; do "$@" && return 0; echo "retrying: $*" >&2; sleep 3; done; return 1; }
  python3 -m venv /opt/testenv
  retry /opt/testenv/bin/pip install -q pytest pexpect
  cd /home/alice/repo
  # Fetch the hash-pinned wheels up front, with retries, and point the
  # installer pip at them, so a flaky network (Docker Desktop drops some
  # HTTPS connections) cannot fail the run. pip still checks every hash.
  retry /opt/testenv/bin/pip download -q --only-binary=:all: --no-deps --require-hashes \
    -r scripts/requirements/decide.txt -d /opt/wheels
  export PIP_FIND_LINKS=/opt/wheels PIP_NO_INDEX=1
  /opt/testenv/bin/python -m pytest tests/root -q -p no:cacheprovider
'
