#!/usr/bin/env python3
"""Builds and starts the demo dev-VM container, provisions the CA and token
signing keys, and pins the container's real sshd host key into
config/targets.yaml. Safe to re-run -- it recreates the container fresh
each time (the VM is meant to be disposable, doc §17).

    python scripts/setup_dev_vm.py                    normal
    python scripts/setup_dev_vm.py --test-approvers   for the integration tests

devd trusts the approver public keys in /etc/mcp-devvm/approvers/, which
must be root-owned (scripts/install_decide.sh creates it). --test-approvers
mounts data/approvers/test-public/ instead, which your user can write, so
the integration tests can add throwaway keys. That also lets an agent add
its own key, so never use it with an agent connected."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.ca import init_ca  # noqa: E402
from scripts.keys import ensure_token_signing_keypair  # noqa: E402
from scripts.approver_keys import TRUSTED_PUBLIC_DIR, untrusted_dir_reason  # noqa: E402

DATA = ROOT / "data"
IMAGE = "mcp-devvm-vm"
CONTAINER = "mcp-devvm-dev-vm"
SSH_PORT = 2222


def sh(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    print("+", " ".join(cmd))
    return subprocess.run(cmd, check=True, **kw)


def _observed_source_address() -> str | None:
    for _ in range(10):
        log = subprocess.run(
            ["docker", "exec", CONTAINER, "cat", "/var/log/sshd.log"], capture_output=True, text=True,
        ).stdout
        found = re.findall(r"Connection from (\S+) port \d+", log)
        if found:
            return found[-1]
        time.sleep(0.5)
    return None


TEST_APPROVERS_DIR = DATA / "approvers" / "test-public"


def _approvers_dir(test_approvers: bool) -> Path:
    """The directory of approver public keys devd will trust. Mounted as a
    directory and read live, so keys enrolled later work without
    recreating the container."""
    if test_approvers:
        TEST_APPROVERS_DIR.mkdir(parents=True, exist_ok=True)
        print(f"WARNING: --test-approvers: devd will trust keys in {TEST_APPROVERS_DIR}, which your user (and any "
              "agent running as you) can write. For integration tests only.", file=sys.stderr)
        return TEST_APPROVERS_DIR
    reason = untrusted_dir_reason(TRUSTED_PUBLIC_DIR)
    if reason:
        print(f"ERROR: {TRUSTED_PUBLIC_DIR} can't be trusted: {reason}.\n"
              "Create it with: sudo scripts/install_decide.sh", file=sys.stderr)
        sys.exit(1)
    # Docker Desktop on macOS needs the real path (/etc is a symlink).
    return TRUSTED_PUBLIC_DIR.resolve()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-approvers", action="store_true",
                        help="trust a user-writable approver dir, for the integration tests only")
    args = parser.parse_args()
    approvers_dir = _approvers_dir(args.test_approvers)

    (DATA / "ca").mkdir(parents=True, exist_ok=True)
    (DATA / "keys").mkdir(parents=True, exist_ok=True)
    (DATA / "sockets").mkdir(parents=True, exist_ok=True)

    init_ca(DATA / "ca")
    ensure_token_signing_keypair(DATA / "keys" / "token_signing_key.pem", DATA / "keys" / "token_signing_key.pub")

    sh(["docker", "build", "-t", IMAGE, "-f", str(ROOT / "vm" / "Dockerfile"), str(ROOT)])

    subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)

    sh([
        "docker", "run", "-d", "--name", CONTAINER,
        # Needed only because this "VM" is itself a container nested inside
        # the outer sandbox's Docker -- bubblewrap's unprivileged user
        # namespaces need capabilities Docker doesn't grant by default in
        # that nested case. On a real (non-containerized) dev VM kernel this
        # flag is not needed at all. See README "what's simulated here."
        "--privileged",
        "-p", f"{SSH_PORT}:22",
        "-v", f"{DATA / 'ca' / 'ca_key.pub'}:/etc/devd/ca.pub:ro",
        "-v", f"{DATA / 'keys' / 'token_signing_key.pub'}:/etc/devd/token_signing_key.pub:ro",
        "-v", f"{approvers_dir}:/etc/devd/approvers:ro",
        IMAGE,
    ])

    print("waiting for sshd to come up...")
    host_key = None
    for _ in range(30):
        result = subprocess.run(
            ["ssh-keyscan", "-p", str(SSH_PORT), "-t", "ed25519", "127.0.0.1"],
            capture_output=True, text=True,
        )
        if result.stdout.strip():
            line = result.stdout.strip().splitlines()[-1]
            _, key_type, key_data = line.split(maxsplit=2)
            host_key = f"{key_type} {key_data}"
            break
        time.sleep(1)

    if host_key is None:
        print("ERROR: sshd never came up in the container", file=sys.stderr)
        sys.exit(1)

    targets_path = ROOT / "config" / "targets.yaml"
    text = targets_path.read_text()
    text = re.sub(r'host_key: ".*"', f'host_key: "{host_key}"', text)
    targets_path.write_text(text)

    # The container is reached through Docker's published-port NAT, so sshd
    # doesn't see 127.0.0.1. The tunnel certificate's source-address
    # restriction (doc §9.4) has to match what sshd actually observes, or
    # every connection is refused ("not from a permitted source address").
    # That address differs by platform (the bridge gateway on Linux,
    # 192.168.65.x on Docker Desktop), so read it from sshd's own log of
    # the ssh-keyscan connection above instead of guessing. A real
    # (non-NATed) deployment pins the MCP server's actual egress IP.
    gw = _observed_source_address() or subprocess.run(
        ["docker", "inspect", CONTAINER, "--format", "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    (DATA / "tunnel_source_address.txt").write_text(gw or "127.0.0.1")

    print(f"\ndev VM is up: container={CONTAINER} ssh_port={SSH_PORT}")
    print(f"host key pinned in {targets_path}")
    print(f"tunnel source-address pinned to {gw or '127.0.0.1'}")
    print(f"approver keys trusted from {approvers_dir}")
    if not args.test_approvers and not any(approvers_dir.glob("*.pub")):
        print("\nNo enrolled approver key yet. Create and enroll yours (you'll pick a passphrase):")
        print("  /opt/mcp-devvm-approve/bin/approver-keys init")
        print("  sudo /opt/mcp-devvm-approve/bin/approver-keys enroll")
    print("\nNext: python -m server.main")


if __name__ == "__main__":
    main()
