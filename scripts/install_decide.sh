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
# Only root-owned programs run as root here (/usr/bin/python3, /bin/*); git
# runs as you. Re-run after reviewing new commits to update; remove with
#     sudo rm -rf /opt/mcp-devvm-approve

set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 022

PREFIX=${MCP_DECIDE_PREFIX:-/opt/mcp-devvm-approve}
PYTHON=${MCP_DECIDE_PYTHON:-/usr/bin/python3}
REF=${1:-HEAD}
REPO=$(cd "$(dirname "$0")/.." && pwd -P)
KEYS_DIR=/etc/mcp-devvm/approvers

# Pinned and wheel-only, so pip never runs a package's build script as root.
DEPS="cryptography==50.0.1 aiosqlite==0.22.1 pyyaml==6.0.3"

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
    owner=$(stat -f %u "$p" 2>/dev/null || stat -c %u "$p")
    mode=$(stat -f %Lp "$p" 2>/dev/null || stat -c %a "$p")
    [ "$owner" = 0 ] || die "$p is not owned by root -- the agent could replace it"
    case $mode in
      *[2367]? | *[2367]) die "$p is group- or world-writable" ;;
    esac
    [ "$p" = / ] && break
    p=$(dirname "$p")
  done
}

[ "${MCP_DECIDE_TEST:-}" = 1 ] || check_root_owned "$PYTHON"
"$PYTHON" -I -c 'import sys; sys.exit(sys.version_info < (3, 9))' \
  || die "$PYTHON is older than 3.9"

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
"$STAGE/venv/bin/python" -I -m pip install --quiet --disable-pip-version-check \
  --no-cache-dir --only-binary=:all: $DEPS

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
echo "  $PREFIX/bin/approver-keys init | list"
echo "  sudo $PREFIX/bin/approver-keys enroll     (makes devd trust your key)"
echo "Type the full path rather than relying on PATH or an alias, which the agent can change."
