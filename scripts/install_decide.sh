#!/bin/sh
# Install a root-owned copy of the approval CLI that the agent can't modify.
#
#     sudo scripts/install_decide.sh [GIT_REF]        (default ref: HEAD)
#
# Why: `decide approve` is where you type your approver passphrase. The repo
# copy of decide.py and everything it imports can be edited by an agent
# running as your OS user, and a modified copy could capture the passphrase.
# This script copies the code from a git commit you have reviewed into
# /opt/mcp-devvm-approve, owned by root, with its own root-owned virtualenv,
# and puts two launchers there:
#
#     /opt/mcp-devvm-approve/bin/decide         replaces python -m server.approvals.decide
#     /opt/mcp-devvm-approve/bin/approver-keys  replaces python -m scripts.approver_keys
#
# It also creates /etc/mcp-devvm/approvers, the root-owned directory of
# approver public keys that devd trusts (filled by `approver-keys enroll`).
#
# The launchers run Python in isolated mode (-I), so the repo, PYTHONPATH
# and your user site-packages are never on the import path. They still read
# data/ (the approval DB and your encrypted key) from the repo.
#
# Only root-owned programs run as root here (the Python below, /bin/*); git
# runs as you. Re-run after reviewing new commits to update; remove with
#     sudo rm -rf /opt/mcp-devvm-approve /opt/mcp-devvm-approve-python

set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 022

PREFIX=${MCP_DECIDE_PREFIX:-/opt/mcp-devvm-approve}
# A root-owned Python 3.10+ to build the venv from: MCP_DECIDE_PYTHON if set,
# else /usr/bin/python3 if new enough, else a pinned standalone build (see
# below). MCP_DECIDE_PYTHON=standalone forces the standalone build.
PYTHON_CHOICE=${MCP_DECIDE_PYTHON:-}
PYTHON_HOME_ROOT=${MCP_DECIDE_PYTHON_HOME:-/opt/mcp-devvm-approve-python}
REF=${1:-HEAD}
REPO=$(cd "$(dirname "$0")/.." && pwd -P)
KEYS_DIR=/etc/mcp-devvm/approvers

# Dependencies come from scripts/requirements/decide.txt in the commit being
# installed: every package (including sub-dependencies) pinned by version and
# sha256, so pip refuses anything PyPI serves that doesn't match. Wheel-only,
# so pip never runs a package's build script as root.
REQUIREMENTS=scripts/requirements/decide.txt

die() { echo "install_decide: $*" >&2; exit 1; }

# MCP_DECIDE_TEST=1 lets the test suite install into a temp dir without root.
# The result is NOT protected; never use it for real.
if [ "$(id -u)" -ne 0 ] && [ "${MCP_DECIDE_TEST:-}" != 1 ]; then
  die "run with sudo: sudo $0 $*"
fi
RUN_AS=${SUDO_USER:-$(id -un)}

# Every directory from / down to the interpreter must be root-owned and not
# writable by group/other, or the agent could swap the interpreter.
check_root_owned() {
  p=$1
  while :; do
    [ -e "$p" ] || die "$p does not exist"
    # GNU stat (-c) first: GNU also accepts -f, but it means "file system
    # status" there and prints the wrong thing. BSD/macOS stat rejects -c.
    owner=$(stat -c %u "$p" 2>/dev/null || stat -f %u "$p")
    mode=$(stat -c %a "$p" 2>/dev/null || stat -f %Lp "$p")
    [ "$owner" = 0 ] || die "$p is not owned by root -- the agent could replace it"
    # A symlink's own mode is always 777 and means nothing; its target is
    # checked separately.
    if [ ! -L "$p" ]; then
      case $mode in
        *[2367]? | *[2367]) die "$p is group- or world-writable" ;;
      esac
    fi
    [ "$p" = / ] && break
    p=$(dirname "$p")
  done
}

# /usr/bin/python3 is often a symlink: check the link and the file it
# resolves to, each with every directory above it -- before running it.
check_interpreter() {
  [ "${MCP_DECIDE_TEST:-}" = 1 ] && return 0
  check_root_owned "$1"
  check_root_owned "$(realpath "$1")"
}
new_enough() {
  [ -x "$1" ] && "$1" -I -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null
}
sha256_of() {
  if [ -x /usr/bin/sha256sum ]; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# python-fido2 needs Python 3.10+, and macOS's /usr/bin/python3 is 3.9.
# Every other Python on a Mac (Homebrew, python.org, uv) is writable by your
# user, so the agent could swap it. Instead, download a pinned build from
# astral-sh/python-build-standalone, check its sha256, and unpack it as root
# into $PYTHON_HOME_ROOT. Kept across reinstalls; bump the pins below to
# update it (hashes from the release's SHA256SUMS).
PBS_RELEASE=20261009
PBS_VERSION=3.12.15
standalone_python() {
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64)  triple=aarch64-apple-darwin; sha=83dcb04777c798bd95f3687acf9ae84b09860272ee6bdfb05be8bcf9447f75b8 ;;
    Darwin-x86_64) triple=x86_64-apple-darwin;  sha=4c84ef5abe4bc145646175fce9b881936d60126b9a3f9a24c6308e2d035ca5c6 ;;
    Linux-aarch64 | Linux-arm64)
                   triple=aarch64-unknown-linux-gnu; sha=b342ccfb577fda349d0237c98b24848234ca767c10f034628a5ff9fc858d662f ;;
    Linux-x86_64)  triple=x86_64-unknown-linux-gnu;  sha=5864001bf969db329fadc2b654c4878c6027d170c6bd77e28f88666260bcaf63 ;;
    *) die "no pinned Python build for $(uname -s) $(uname -m); set MCP_DECIDE_PYTHON to a root-owned Python 3.10+" ;;
  esac
  dest="$PYTHON_HOME_ROOT/cpython-$PBS_VERSION+$PBS_RELEASE"
  if [ ! -d "$dest" ]; then
    [ -x /usr/bin/curl ] || die "need /usr/bin/curl to download Python $PBS_VERSION"
    echo "Downloading Python $PBS_VERSION (python-build-standalone $PBS_RELEASE, $triple)"
    tmp=$(mktemp -d)
    url="https://github.com/astral-sh/python-build-standalone/releases/download/$PBS_RELEASE/cpython-$PBS_VERSION%2B$PBS_RELEASE-$triple-install_only.tar.gz"
    /usr/bin/curl -fsSL --proto =https --tlsv1.2 --retry 5 -o "$tmp/python.tar.gz" "$url" || { rm -rf "$tmp"; die "download failed: $url"; }
    got=$(sha256_of "$tmp/python.tar.gz")
    [ "$got" = "$sha" ] || { rm -rf "$tmp"; die "Python download has sha256 $got, expected $sha -- refusing it"; }
    mkdir "$tmp/x"
    tar -xzf "$tmp/python.tar.gz" -C "$tmp/x"
    mkdir -p "$PYTHON_HOME_ROOT"
    rm -rf "$dest.new"
    mv "$tmp/x/python" "$dest.new"
    rm -rf "$tmp"
    if [ "$(id -u)" -eq 0 ]; then chown -R 0:0 "$PYTHON_HOME_ROOT" "$dest.new"; fi
    chmod 755 "$PYTHON_HOME_ROOT"
    chmod -R go-w "$dest.new"
    mv "$dest.new" "$dest"
  fi
  PYTHON="$dest/bin/python3"
}

case $PYTHON_CHOICE in
  standalone) standalone_python ;;
  "")
    if check_interpreter /usr/bin/python3 && new_enough /usr/bin/python3; then
      PYTHON=/usr/bin/python3
    else
      standalone_python
    fi ;;
  *) PYTHON=$PYTHON_CHOICE ;;
esac
check_interpreter "$PYTHON"
new_enough "$PYTHON" || die "$PYTHON is older than 3.10 (python-fido2 needs 3.10+)"
echo "Using $PYTHON ($("$PYTHON" -I -c 'import sys; print(sys.version.split()[0])'))"

# Read the source as the invoking user, so no repo config or hook runs as root.
as_user() {
  if [ "$(id -u)" -eq 0 ] && [ "$RUN_AS" != root ]; then sudo -u "$RUN_AS" "$@"; else "$@"; fi
}
COMMIT=$(as_user /usr/bin/git -C "$REPO" rev-parse --verify "$REF^{commit}") \
  || die "unknown git ref: $REF"
SUBJECT=$(as_user /usr/bin/git -C "$REPO" log -1 --format=%s "$COMMIT")

echo "Installing the approval CLI from commit $COMMIT"
echo "  \"$SUBJECT\""
echo "Only install a commit whose common/, server/ and scripts/ you have reviewed:"
echo "  git log -p -- common server scripts"
if [ "${MCP_DECIDE_TEST:-}" != 1 ]; then
  printf "Install it? [y/N] "
  read -r answer < /dev/tty
  [ "$answer" = y ] || [ "$answer" = Y ] || die "aborted"
fi

STAGE="$PREFIX.new"
rm -rf "$STAGE"
mkdir -p "$STAGE/src" "$STAGE/bin"
as_user /usr/bin/git -C "$REPO" archive --format=tar "$COMMIT" common server scripts \
  | tar -x -C "$STAGE/src" -f -

"$PYTHON" -I -m venv "$STAGE/venv"
[ -f "$STAGE/src/$REQUIREMENTS" ] || die "commit $COMMIT has no $REQUIREMENTS"
"$STAGE/venv/bin/python" -I -m pip install --quiet --disable-pip-version-check \
  --no-cache-dir --timeout 60 --retries 5 --only-binary=:all: --no-deps --require-hashes \
  -r "$STAGE/src/$REQUIREMENTS"

cat > "$STAGE/launch.py" <<EOF
import runpy
import sys

sys.path.insert(0, "$PREFIX/src")
module = {"decide": "server.approvals.decide", "approver-keys": "scripts.approver_keys"}[sys.argv.pop(1)]
runpy.run_module(module, run_name="__main__", alter_sys=True)
EOF

for tool in decide approver-keys; do
  cat > "$STAGE/bin/$tool" <<EOF
#!/bin/sh
# Installed by scripts/install_decide.sh from commit $COMMIT.
cd "$REPO" || exit 1
exec "$PREFIX/venv/bin/python" -I -B "$PREFIX/launch.py" $tool "\$@"
EOF
  chmod 755 "$STAGE/bin/$tool"
done
echo "$COMMIT" > "$STAGE/COMMIT"

if [ "$(id -u)" -eq 0 ]; then chown -R 0:0 "$STAGE"; fi
chmod -R go-w "$STAGE"
rm -rf "$PREFIX"
mv "$STAGE" "$PREFIX"

# The approver public keys devd trusts (scripts/approver_keys.py enroll).
# Root-owned so an agent running as you can't add a key of its own. Kept
# across reinstalls.
if [ "${MCP_DECIDE_TEST:-}" != 1 ]; then
  mkdir -p "$KEYS_DIR"
  chown 0:0 "$KEYS_DIR"
  chmod 755 "$KEYS_DIR"
  check_root_owned "$(cd "$KEYS_DIR" && pwd -P)"
fi

echo
echo "Installed to $PREFIX. Use these instead of the repo copies:"
echo "  $PREFIX/bin/decide list | show <id> | approve <id> | deny <id>"
echo "  $PREFIX/bin/approver-keys init | list      (security key plugged in for init)"
echo "  sudo $PREFIX/bin/approver-keys enroll     (makes devd trust your key)"
echo "Type the full path rather than relying on PATH or an alias, which the agent can change."
