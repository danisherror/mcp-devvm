"""Approver signing keys (see common/approval_sig.py for why they exist).

    python -m scripts.approver_keys init [--name NAME]
    python -m scripts.approver_keys list

Each approver gets an Ed25519 keypair:
  data/approvers/private/<name>.key   private half, encrypted with a passphrase
  data/approvers/public/<name>.pub    public half, mounted read-only into the VM

The passphrase is the part the agent can't get: it is never written to disk
and is typed by the human into `decide approve`. Use a real passphrase, not
an empty one; an agent can read the encrypted key file, so its strength is
what stands between the agent and a forged approval.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common.approval_sig import APPROVER_NAME_RE

APPROVERS_DIR = Path("data/approvers")
MIN_PASSPHRASE_LEN = 12


def private_key_path(name: str, base: Path = APPROVERS_DIR) -> Path:
    return base / "private" / f"{name}.key"


def public_key_path(name: str, base: Path = APPROVERS_DIR) -> Path:
    return base / "public" / f"{name}.pub"


def create_approver_key(name: str, passphrase: str, base: Path = APPROVERS_DIR) -> tuple[Path, Path]:
    if not APPROVER_NAME_RE.match(name):
        raise ValueError(f"approver name must match {APPROVER_NAME_RE.pattern}")
    if not passphrase:
        raise ValueError("passphrase must not be empty")
    priv_path, pub_path = private_key_path(name, base), public_key_path(name, base)
    if priv_path.exists() or pub_path.exists():
        raise FileExistsError(f"approver key '{name}' already exists")
    priv_path.parent.mkdir(parents=True, exist_ok=True)
    pub_path.parent.mkdir(parents=True, exist_ok=True)
    priv_path.parent.chmod(0o700)

    key = Ed25519PrivateKey.generate()
    priv_path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    ))
    priv_path.chmod(0o600)
    pub_path.write_bytes(key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return priv_path, pub_path


def load_private_key(name: str, passphrase: str, base: Path = APPROVERS_DIR) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(private_key_path(name, base).read_bytes(), password=passphrase.encode("utf-8"))
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("approver key is not Ed25519")
    return key


def list_approvers(base: Path = APPROVERS_DIR) -> list[str]:
    priv_dir = base / "private"
    return sorted(p.stem for p in priv_dir.glob("*.key")) if priv_dir.is_dir() else []


def _default_name() -> str:
    return getpass.getuser().lower()


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m scripts.approver_keys")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_init = sub.add_parser("init", help="create a new approver key")
    p_init.add_argument("--name", default=None, help="approver name (default: your OS username)")
    sub.add_parser("list", help="list approver keys on this machine")
    args = parser.parse_args()

    if args.cmd == "list":
        names = list_approvers()
        print("\n".join(names) if names else "no approver keys -- run: python -m scripts.approver_keys init")
        return

    name = args.name or _default_name()
    passphrase = getpass.getpass(f"New passphrase for approver '{name}' (min {MIN_PASSPHRASE_LEN} chars): ")
    if len(passphrase) < MIN_PASSPHRASE_LEN:
        print(f"passphrase too short (need at least {MIN_PASSPHRASE_LEN} characters)", file=sys.stderr)
        raise SystemExit(1)
    if getpass.getpass("Repeat passphrase: ") != passphrase:
        print("passphrases did not match", file=sys.stderr)
        raise SystemExit(1)
    try:
        priv, pub = create_approver_key(name, passphrase)
    except (ValueError, FileExistsError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"created approver '{name}'\n  private (encrypted): {priv}\n  public:              {pub}")
    print("The VM reads data/approvers/public/ live -- no restart needed if it's already running.")


if __name__ == "__main__":
    main()
